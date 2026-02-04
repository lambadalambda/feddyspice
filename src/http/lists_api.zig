const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const list_accounts = @import("../list_accounts.zig");
const lists = @import("../lists.zig");
const masto = @import("mastodon.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const util_ids = @import("../util/ids.zig");

const ListPayload = struct {
    id: []const u8,
    title: []const u8,
    replies_policy: []const u8,
};

fn makeListPayload(allocator: std.mem.Allocator, l: lists.List) ListPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{l.id}) catch "0";
    return .{ .id = id_str, .title = l.title, .replies_policy = l.replies_policy };
}

pub fn listsIndex(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const rows = lists.listByUser(&app_state.conn, allocator, info.?.user_id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads: std.ArrayListUnmanaged(ListPayload) = .empty;
    defer payloads.deinit(allocator);

    for (rows) |l| {
        payloads.append(allocator, makeListPayload(allocator, l)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, payloads.items);
}

pub fn listsCreate(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const title_raw = parsed.get("title") orelse return .{ .status = .unprocessable_entity, .body = "invalid title\n" };
    const title = std.mem.trim(u8, title_raw, " \t\r\n");
    if (title.len == 0) return .{ .status = .unprocessable_entity, .body = "invalid title\n" };

    const replies_policy = parsed.get("replies_policy") orelse "list";

    const l = lists.create(&app_state.conn, allocator, info.?.user_id, title, replies_policy) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return common.jsonOk(allocator, makeListPayload(allocator, l));
}

pub fn listGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const l = lists.lookupByIdForUser(&app_state.conn, allocator, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (l == null) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, makeListPayload(allocator, l.?));
}

pub fn listUpdate(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const title_raw = parsed.get("title");
    const title_trimmed = if (title_raw) |t| std.mem.trim(u8, t, " \t\r\n") else null;
    if (title_trimmed != null and title_trimmed.?.len == 0) return .{ .status = .unprocessable_entity, .body = "invalid title\n" };

    const replies_policy = parsed.get("replies_policy");

    const l = lists.update(&app_state.conn, allocator, id, info.?.user_id, title_trimmed, replies_policy) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (l == null) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, makeListPayload(allocator, l.?));
}

pub fn listDelete(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = lists.delete(&app_state.conn, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    const payload: struct {} = .{};
    return common.jsonOk(allocator, payload);
}

pub fn listAccountsIndex(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    const suffix = "/accounts";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len .. path.len - suffix.len];
    const list_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const l = lists.lookupByIdForUser(&app_state.conn, allocator, list_id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (l == null) return .{ .status = .not_found, .body = "not found\n" };

    const actor_ids = list_accounts.listRemoteActorIds(&app_state.conn, allocator, list_id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var out: std.ArrayListUnmanaged(masto.AccountPayload) = .empty;
    defer out.deinit(allocator);

    for (actor_ids) |actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        const api_id = util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor_id);
        out.append(allocator, masto.makeRemoteAccountPayload(app_state, allocator, api_id, actor.?)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, out.items);
}

fn parseAccountIds(parsed: *const form.Form) ?[]const u8 {
    return parsed.get("account_ids[]") orelse parsed.get("account_ids");
}

pub fn listAccountsAdd(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    const suffix = "/accounts";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len .. path.len - suffix.len];
    const list_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const l = lists.lookupByIdForUser(&app_state.conn, allocator, list_id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (l == null) return .{ .status = .not_found, .body = "not found\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const raw = parseAccountIds(&parsed) orelse "";
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |id_str| {
        if (id_str.len == 0) continue;
        const account_id = std.fmt.parseInt(i64, id_str, 10) catch continue;
        if (account_id < util_ids.remote_actor_id_base) continue;

        const rowid = account_id - util_ids.remote_actor_id_base;
        if (rowid <= 0) continue;

        const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch null;
        if (actor == null) continue;

        list_accounts.add(&app_state.conn, list_id, actor.?.id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const payload: struct {} = .{};
    return common.jsonOk(allocator, payload);
}

pub fn listAccountsRemove(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/lists/";
    const suffix = "/accounts";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len .. path.len - suffix.len];
    const list_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const l = lists.lookupByIdForUser(&app_state.conn, allocator, list_id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (l == null) return .{ .status = .not_found, .body = "not found\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const raw = parseAccountIds(&parsed) orelse "";
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |id_str| {
        if (id_str.len == 0) continue;
        const account_id = std.fmt.parseInt(i64, id_str, 10) catch continue;
        if (account_id < util_ids.remote_actor_id_base) continue;

        const rowid = account_id - util_ids.remote_actor_id_base;
        if (rowid <= 0) continue;

        const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch null;
        if (actor == null) continue;

        list_accounts.remove(&app_state.conn, list_id, actor.?.id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const payload: struct {} = .{};
    return common.jsonOk(allocator, payload);
}

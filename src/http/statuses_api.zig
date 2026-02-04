const std = @import("std");

const app = @import("../app.zig");
const background = @import("../background.zig");
const common = @import("common.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const media = @import("../media.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const statuses = @import("../statuses.zig");
const users = @import("../users.zig");

const StatusPayload = masto.StatusPayload;

pub fn createStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const max_media_attachments: i64 = 4;

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const text_opt = parsed.get("status");
    const text = text_opt orelse "";
    const visibility = parsed.get("visibility") orelse "public";
    const media_ids_raw = parsed.get("media_ids[]") orelse parsed.get("media_ids");

    const has_media = blk: {
        const raw = media_ids_raw orelse break :blk false;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |id_str| {
            if (id_str.len == 0) continue;
            break :blk true;
        }
        break :blk false;
    };

    const has_text = std.mem.trim(u8, text, " \t\r\n").len > 0;
    if (text_opt == null and !has_media) return .{ .status = .bad_request, .body = "missing status\n" };
    if (!has_text and !has_media) return .{ .status = .unprocessable_entity, .body = "invalid status\n" };

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const st = statuses.create(&app_state.conn, allocator, info.?.user_id, text, visibility) catch |err| switch (err) {
        error.InvalidText => return .{ .status = .unprocessable_entity, .body = "invalid status\n" },
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    if (media_ids_raw) |raw| {
        var pos: i64 = 0;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |id_str| {
            if (id_str.len == 0) continue;
            if (pos >= max_media_attachments) {
                return .{ .status = .unprocessable_entity, .body = "too many media\n" };
            }
            const media_id = std.fmt.parseInt(i64, id_str, 10) catch
                return .{ .status = .unprocessable_entity, .body = "invalid media\n" };

            const meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (meta == null or meta.?.user_id != info.?.user_id) {
                return .{ .status = .unprocessable_entity, .body = "invalid media\n" };
            }

            const attached = media.attachToStatus(&app_state.conn, st.id, media_id, pos) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (!attached) return .{ .status = .unprocessable_entity, .body = "invalid media\n" };
            pos += 1;
        }
    }

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    background.deliverStatusToFollowers(app_state, allocator, info.?.user_id, st.id);

    const resp = statusResponse(app_state, allocator, user.?, st);
    app_state.streaming.publishUpdate(info.?.user_id, resp.body);
    return resp;
}

pub fn getStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        return remoteStatusResponse(app_state, allocator, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    return statusResponse(app_state, allocator, user.?, st.?);
}

pub fn statusContext(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    const suffix = "/context";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    } else {
        const st = statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    }

    return common.jsonOk(allocator, .{
        .ancestors = [_]StatusPayload{},
        .descendants = [_]StatusPayload{},
    });
}

pub fn statusActionNoop(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    req: http_types.Request,
    path: []const u8,
    suffix: []const u8,
) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        return remoteStatusResponse(app_state, allocator, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    return statusResponse(app_state, allocator, user.?, st.?);
}

pub fn deleteStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };
    if (id < 0) return .{ .status = .not_found, .body = "not found\n" };

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const ok = statuses.markDeleted(&app_state.conn, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    media.deleteForStatus(&app_state.conn, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    background.deliverDeleteToFollowers(app_state, allocator, info.?.user_id, id);

    const resp = statusResponse(app_state, allocator, user.?, st.?);
    app_state.streaming.publishDelete(info.?.user_id, id_str);
    return resp;
}

fn statusResponse(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) http_types.Response {
    const payload = masto.makeStatusPayload(app_state, allocator, user, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn remoteStatusResponse(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) http_types.Response {
    const payload = masto.makeRemoteStatusPayload(app_state, allocator, actor, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const conversations = @import("../conversations.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const statuses = @import("../statuses.zig");
const users = @import("../users.zig");
const util_ids = @import("../util/ids.zig");

const AccountPayload = masto.AccountPayload;
const StatusPayload = masto.StatusPayload;

const ConversationPayload = struct {
    id: []const u8,
    unread: bool,
    accounts: []const AccountPayload,
    last_status: ?StatusPayload = null,
};

fn conversationPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    local_user: users.User,
    row: conversations.Conversation,
) ?ConversationPayload {
    const remote_actor = remote_actors.lookupById(&app_state.conn, allocator, row.remote_actor_id) catch
        return null;
    if (remote_actor == null) return null;

    const api_id = util_ids.remoteAccountApiIdAlloc(app_state, allocator, remote_actor.?.id);
    const remote_account = masto.makeRemoteAccountPayload(app_state, allocator, api_id, remote_actor.?);

    const accounts_slice = allocator.alloc(AccountPayload, 1) catch return null;
    accounts_slice[0] = remote_account;

    const last_status: ?StatusPayload = blk: {
        const id = row.last_status_id;
        if (id < 0) {
            const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch break :blk null;
            if (st == null) break :blk null;
            break :blk masto.makeRemoteStatusPayload(app_state, allocator, remote_actor.?, st.?);
        }

        const st = statuses.lookup(&app_state.conn, allocator, id) catch break :blk null;
        if (st == null) break :blk null;
        break :blk masto.makeStatusPayload(app_state, allocator, local_user, st.?);
    };

    return .{
        .id = std.fmt.allocPrint(allocator, "{d}", .{row.id}) catch "0",
        .unread = row.unread,
        .accounts = accounts_slice,
        .last_status = last_status,
    };
}

pub fn conversationsGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const local_user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (local_user == null) return common.unauthorized(allocator);

    const q = common.queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };
    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 40;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 40;
        break :blk @min(parsed, 200);
    };

    const rows = conversations.listVisible(&app_state.conn, allocator, info.?.user_id, limit) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var out: std.ArrayListUnmanaged(ConversationPayload) = .empty;
    defer out.deinit(allocator);

    for (rows) |r| {
        if (conversationPayload(app_state, allocator, local_user.?, r)) |p| {
            out.append(allocator, p) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    return common.jsonOk(allocator, out.items);
}

pub fn conversationsRead(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/conversations/";
    const suffix = "/read";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = conversations.markRead(&app_state.conn, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    const row = conversations.lookupById(&app_state.conn, allocator, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (row == null) return .{ .status = .not_found, .body = "not found\n" };

    const local_user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (local_user == null) return common.unauthorized(allocator);

    const payload = conversationPayload(app_state, allocator, local_user.?, row.?) orelse
        return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, payload);
}

pub fn conversationsDelete(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/conversations/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len..];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = conversations.hide(&app_state.conn, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, .{});
}

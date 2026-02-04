const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const notifications = @import("../notifications.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const util_ids = @import("../util/ids.zig");

const AccountPayload = masto.AccountPayload;

const NotificationPayload = struct {
    id: []const u8,
    type: []const u8,
    created_at: []const u8,
    account: AccountPayload,
    status: ?masto.StatusPayload = null,
};

fn makeNotificationPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    n: notifications.Notification,
) ?NotificationPayload {
    const actor = remote_actors.lookupById(&app_state.conn, allocator, n.actor_id) catch return null;
    if (actor == null) return null;

    const api_id = util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
    const acct = masto.makeRemoteAccountPayload(app_state, allocator, api_id, actor.?);

    const id_str = std.fmt.allocPrint(allocator, "{d}", .{n.id}) catch "0";

    return .{
        .id = id_str,
        .type = n.kind,
        .created_at = n.created_at,
        .account = acct,
        .status = null,
    };
}

pub fn notificationsGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const q = common.queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };

    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 20;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 20;
        break :blk @min(parsed, 200);
    };

    const max_id: ?i64 = blk: {
        const s = params.get("max_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const rows = notifications.list(&app_state.conn, allocator, info.?.user_id, limit, max_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var out: std.ArrayListUnmanaged(NotificationPayload) = .empty;
    defer out.deinit(allocator);

    for (rows) |n| {
        if (makeNotificationPayload(app_state, allocator, n)) |p| {
            out.append(allocator, p) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    return common.jsonOk(allocator, out.items);
}

pub fn notificationsUnreadCount(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const cnt = notifications.count(&app_state.conn, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return common.jsonOk(allocator, .{ .count = cnt });
}

pub fn notificationsShow(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/notifications/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const n = notifications.lookupById(&app_state.conn, allocator, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (n == null) return .{ .status = .not_found, .body = "not found\n" };

    const payload = makeNotificationPayload(app_state, allocator, n.?) orelse
        return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, payload);
}

pub fn notificationsClear(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    notifications.clear(&app_state.conn, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return common.jsonOk(allocator, .{});
}

pub fn notificationsDismiss(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/notifications/";
    const suffix = "/dismiss";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = notifications.dismiss(&app_state.conn, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, .{});
}

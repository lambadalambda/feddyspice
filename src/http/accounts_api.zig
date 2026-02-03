const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const media = @import("../media.zig");
const oauth = @import("../oauth.zig");
const urls = @import("urls.zig");
const users = @import("../users.zig");
const util_html = @import("../util/html.zig");

pub fn verifyCredentials(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    return accountByUser(app_state, allocator, user.?);
}

pub fn updateCredentials(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    var display_name = user.?.display_name;
    var note = user.?.note;
    var avatar_media_id = user.?.avatar_media_id;
    var header_media_id = user.?.header_media_id;

    var avatar_file: ?form.MultipartFilePart = null;
    var header_file: ?form.MultipartFilePart = null;

    var clear_avatar = false;
    var clear_header = false;

    if (common.isMultipart(req.content_type)) {
        var parsed = form.parseMultipartWithFiles(allocator, req.content_type.?, req.body) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };
        defer parsed.deinit(allocator);

        if (parsed.form.get("display_name")) |v| {
            display_name = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
        if (parsed.form.get("note")) |v| {
            note = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        if (parsed.form.get("avatar")) |v| clear_avatar = v.len == 0;
        if (parsed.form.get("header")) |v| clear_header = v.len == 0;

        for (parsed.files) |f| {
            if (std.mem.eql(u8, f.name, "avatar")) avatar_file = f;
            if (std.mem.eql(u8, f.name, "header")) header_file = f;
        }
    } else {
        var parsed = common.parseBodyParams(allocator, req) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };
        defer parsed.deinit(allocator);

        if (parsed.get("display_name")) |v| {
            display_name = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
        if (parsed.get("note")) |v| {
            note = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        if (parsed.get("avatar")) |v| clear_avatar = v.len == 0;
        if (parsed.get("header")) |v| clear_header = v.len == 0;
    }

    if (clear_avatar) avatar_media_id = null;
    if (clear_header) header_media_id = null;

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const now_ms: i64 = std.time.milliTimestamp();

    if (avatar_file) |f| {
        var meta = media.create(
            &app_state.conn,
            allocator,
            info.?.user_id,
            f.content_type orelse "application/octet-stream",
            f.data,
            null,
            now_ms,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        defer meta.deinit(allocator);
        avatar_media_id = meta.id;
    }

    if (header_file) |f| {
        var meta = media.create(
            &app_state.conn,
            allocator,
            info.?.user_id,
            f.content_type orelse "application/octet-stream",
            f.data,
            null,
            now_ms,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        defer meta.deinit(allocator);
        header_media_id = meta.id;
    }

    const updated = users.updateProfile(
        &app_state.conn,
        info.?.user_id,
        display_name,
        note,
        avatar_media_id,
        header_media_id,
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!updated) return common.unauthorized(allocator);

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    const one_day_ms: i64 = 24 * 60 * 60 * 1000;
    _ = media.pruneOrphansOlderThan(&app_state.conn, now_ms - one_day_ms) catch 0;

    const updated_user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (updated_user == null) return common.unauthorized(allocator);

    return accountByUser(app_state, allocator, updated_user.?);
}

pub fn lookup(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    const acct_param = common.parseQueryParam(allocator, q, "acct") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    if (acct_param == null) return .{ .status = .bad_request, .body = "missing acct\n" };

    var username = acct_param.?;
    if (std.mem.indexOfScalar(u8, username, '@')) |at| {
        const domain = username[at + 1 ..];
        if (domain.len == 0) return .{ .status = .not_found, .body = "not found\n" };
        if (!std.mem.eql(u8, domain, app_state.cfg.domain)) return .{ .status = .not_found, .body = "not found\n" };
        username = username[0..at];
    }
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    return accountByUser(app_state, allocator, user.?);
}

pub fn accountByUser(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) http_types.Response {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const user_url = urls.userUrlAlloc(app_state, allocator, user.username) catch "";
    const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, user);
    const header_url = urls.userHeaderUrlAlloc(app_state, allocator, user);
    const note_html = util_html.textToHtmlAlloc(allocator, user.note) catch user.note;

    const payload: masto.AccountPayload = .{
        .id = id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = user.display_name,
        .note = note_html,
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

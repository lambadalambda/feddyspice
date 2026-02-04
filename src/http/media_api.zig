const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const media = @import("../media.zig");
const oauth = @import("../oauth.zig");

pub fn createMedia(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    if (!common.isMultipart(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid form\n" };
    }

    var parsed = form.parseMultipartWithFile(allocator, req.content_type.?, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const file = parsed.file orelse return .{ .status = .bad_request, .body = "missing file\n" };
    if (!std.mem.eql(u8, file.name, "file")) return .{ .status = .bad_request, .body = "missing file\n" };

    const description = parsed.form.get("description");
    const content_type = file.content_type orelse "application/octet-stream";

    const now_ms: i64 = std.time.milliTimestamp();
    var meta = media.create(
        &app_state.conn,
        allocator,
        info.?.user_id,
        content_type,
        file.data,
        description,
        now_ms,
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    defer meta.deinit(allocator);

    const one_day_ms: i64 = 24 * 60 * 60 * 1000;
    _ = media.pruneOrphansOlderThan(&app_state.conn, now_ms - one_day_ms) catch 0;

    const payload = masto.makeMediaAttachmentPayload(app_state, allocator, meta);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn getMedia(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const id_str = path["/api/v1/media/".len..];
    const media_id = std.fmt.parseInt(i64, id_str, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    var meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (meta == null) return .{ .status = .not_found, .body = "not found\n" };
    defer meta.?.deinit(allocator);
    if (meta.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const payload = masto.makeMediaAttachmentPayload(app_state, allocator, meta.?);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn updateMedia(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const id_str = path["/api/v1/media/".len..];
    const media_id = std.fmt.parseInt(i64, id_str, 10) catch
        return .{ .status = .bad_request, .body = "invalid media id\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const description = parsed.get("description");
    const now_ms: i64 = std.time.milliTimestamp();
    const updated = media.updateDescription(&app_state.conn, media_id, info.?.user_id, description, now_ms) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!updated) return .{ .status = .not_found, .body = "not found\n" };

    var meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (meta == null) return .{ .status = .not_found, .body = "not found\n" };
    defer meta.?.deinit(allocator);

    const payload = masto.makeMediaAttachmentPayload(app_state, allocator, meta.?);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn mediaFileGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
    const token = path["/media/".len..];
    if (token.len == 0) return .{ .status = .not_found, .body = "not found\n" };

    const m = media.lookupByPublicToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (m == null) return .{ .status = .not_found, .body = "not found\n" };

    return .{
        .content_type = m.?.content_type,
        .body = m.?.data,
    };
}

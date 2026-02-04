const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const http_types = @import("../http_types.zig");
const oauth = @import("../oauth.zig");
const url = @import("../util/url.zig");

const TagHistory = struct {
    day: []const u8,
    accounts: []const u8,
    uses: []const u8,
};

const TagPayload = struct {
    name: []const u8,
    url: []const u8,
    history: []const TagHistory,
    following: bool,
};

fn makeTagPayload(app_state: *app.App, allocator: std.mem.Allocator, tag: []const u8, following: bool) TagPayload {
    const base = url.baseUrlAlloc(app_state, allocator) catch "";
    const tag_enc = common.percentEncodeAlloc(allocator, tag) catch tag;
    const tag_url = std.fmt.allocPrint(allocator, "{s}/tags/{s}", .{ base, tag_enc }) catch "";

    return .{
        .name = tag,
        .url = tag_url,
        .history = &.{},
        .following = following,
    };
}

pub fn tagGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
    const prefix = "/api/v1/tags/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const tag = path[prefix.len..];
    if (tag.len == 0 or std.mem.indexOfScalar(u8, tag, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, makeTagPayload(app_state, allocator, tag, false));
}

pub fn tagFollowUnfollow(
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

    const prefix = "/api/v1/tags/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const tag = path[prefix.len .. path.len - suffix.len];
    if (tag.len == 0 or std.mem.indexOfScalar(u8, tag, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const following = std.mem.eql(u8, suffix, "/follow");
    return common.jsonOk(allocator, makeTagPayload(app_state, allocator, tag, following));
}

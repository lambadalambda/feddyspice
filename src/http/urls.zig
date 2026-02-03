const std = @import("std");

const app = @import("../app.zig");
const media = @import("../media.zig");
const users = @import("../users.zig");
const url = @import("../util/url.zig");

pub fn userUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
        username,
    });
}

pub fn mediaUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator, media_id: i64) ?[]u8 {
    var meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch return null;
    if (meta == null) return null;
    defer meta.?.deinit(allocator);

    const base = url.baseUrlAlloc(app_state, allocator) catch return null;
    return std.fmt.allocPrint(allocator, "{s}/media/{s}", .{ base, meta.?.public_token }) catch null;
}

pub fn userAvatarUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) []const u8 {
    if (user.avatar_media_id) |id| {
        if (mediaUrlAlloc(app_state, allocator, id)) |u| return u;
    }
    return url.defaultAvatarUrlAlloc(app_state, allocator) catch "";
}

pub fn userHeaderUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) []const u8 {
    if (user.header_media_id) |id| {
        if (mediaUrlAlloc(app_state, allocator, id)) |u| return u;
    }
    return url.defaultHeaderUrlAlloc(app_state, allocator) catch "";
}

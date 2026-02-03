const std = @import("std");

const app = @import("../app.zig");

pub fn baseUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

pub fn streamingBaseUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    const scheme: []const u8 = switch (app_state.cfg.scheme) {
        .https => "wss",
        .http => "ws",
    };
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme, app_state.cfg.domain });
}

pub fn defaultAvatarUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/static/avatar.png", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

pub fn defaultHeaderUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/static/header.png", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

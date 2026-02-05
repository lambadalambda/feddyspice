const std = @import("std");

const app = @import("../app.zig");

pub fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

pub fn stripQueryAndFragment(s: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, s, '?');
    const h = std.mem.indexOfScalar(u8, s, '#');
    const end = blk: {
        if (q == null and h == null) break :blk s.len;
        if (q != null and h != null) break :blk @min(q.?, h.?);
        break :blk if (q) |qi| qi else h.?;
    };
    return s[0..end];
}

pub fn isHttpOrHttpsUrl(raw: []const u8) bool {
    if (raw.len == 0) return false;
    for (raw) |c| {
        if (c == '\r' or c == '\n' or c == 0) return false;
    }

    const uri = std.Uri.parse(raw) catch return false;
    if (!(std.ascii.eqlIgnoreCase(uri.scheme, "http") or std.ascii.eqlIgnoreCase(uri.scheme, "https"))) return false;
    if (uri.host == null) return false;
    if (uri.user != null or uri.password != null) return false;
    return true;
}

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

test "isHttpOrHttpsUrl accepts only http(s) without userinfo" {
    try std.testing.expect(isHttpOrHttpsUrl("https://example.test/"));
    try std.testing.expect(isHttpOrHttpsUrl("http://example.test:8080/path?x=y"));
    try std.testing.expect(!isHttpOrHttpsUrl(""));
    try std.testing.expect(!isHttpOrHttpsUrl("javascript:alert(1)"));
    try std.testing.expect(!isHttpOrHttpsUrl("file:///etc/passwd"));
    try std.testing.expect(!isHttpOrHttpsUrl("data:text/plain,hi"));
    try std.testing.expect(!isHttpOrHttpsUrl("https://"));
    try std.testing.expect(!isHttpOrHttpsUrl("https://user:pass@example.test/"));
    try std.testing.expect(!isHttpOrHttpsUrl("https://example.test/\r\nx: y"));
}

test "trimTrailingSlash removes at most one slash" {
    try std.testing.expectEqualStrings("", trimTrailingSlash(""));
    try std.testing.expectEqualStrings("", trimTrailingSlash("/"));
    try std.testing.expectEqualStrings("https://example.test", trimTrailingSlash("https://example.test"));
    try std.testing.expectEqualStrings("https://example.test", trimTrailingSlash("https://example.test/"));
    try std.testing.expectEqualStrings("https://example.test//", trimTrailingSlash("https://example.test///"));
}

test "stripQueryAndFragment strips query and fragment" {
    try std.testing.expectEqualStrings("", stripQueryAndFragment(""));
    try std.testing.expectEqualStrings("https://example.test/p", stripQueryAndFragment("https://example.test/p?q=1"));
    try std.testing.expectEqualStrings("https://example.test/p", stripQueryAndFragment("https://example.test/p#x"));
    try std.testing.expectEqualStrings("https://example.test/p", stripQueryAndFragment("https://example.test/p?q=1#x"));
    try std.testing.expectEqualStrings("https://example.test/p", stripQueryAndFragment("https://example.test/p#x?q=1"));
}

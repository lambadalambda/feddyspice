const std = @import("std");

const app = @import("../app.zig");
const http_types = @import("../http_types.zig");
const sessions = @import("../sessions.zig");

pub fn currentUserId(app_state: *app.App, req: http_types.Request) !?i64 {
    const cookie_header = req.cookie orelse return null;
    const token = sessions.parseCookie(cookie_header) orelse return null;
    return try sessions.lookupUserId(&app_state.conn, token);
}

pub fn redirectWithSession(
    allocator: std.mem.Allocator,
    secure_cookie: bool,
    token: []const u8,
    location: []const u8,
) http_types.Response {
    const cookie = cookieValue(allocator, secure_cookie, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const headers = allocator.alloc(std.http.Header, 2) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const common = @import("common.zig");
    headers[0] = .{ .name = "location", .value = if (common.headerValueIsSafe(location)) location else "/" };
    headers[1] = .{ .name = "set-cookie", .value = cookie };

    return .{
        .status = .see_other,
        .body = "redirecting\n",
        .headers = headers,
    };
}

fn cookieValue(allocator: std.mem.Allocator, secure_cookie: bool, token: []const u8) ![]u8 {
    if (secure_cookie) {
        return std.fmt.allocPrint(
            allocator,
            "{s}={s}; HttpOnly; SameSite=Lax; Path=/; Secure",
            .{ sessions.CookieName, token },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{s}={s}; HttpOnly; SameSite=Lax; Path=/",
        .{ sessions.CookieName, token },
    );
}

test "redirectWithSession sanitizes Location header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const resp = redirectWithSession(a, false, "abc", "/\r\nx: y");
    try std.testing.expectEqual(std.http.Status.see_other, resp.status);
    try std.testing.expectEqualStrings("/", resp.headers[0].value);
    try std.testing.expect(std.mem.startsWith(u8, resp.headers[1].value, sessions.CookieName));
}

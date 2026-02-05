const std = @import("std");

const http_types = @import("../http_types.zig");

pub const CookieName = "feddyspice_csrf";
pub const FormFieldName = "csrf";

pub fn issueTokenAlloc(allocator: std.mem.Allocator) ![]u8 {
    var token_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&token_bytes);

    const hex = std.fmt.bytesToHex(token_bytes, .lower);
    return try allocator.dupe(u8, hex[0..]);
}

pub fn cookieValue(allocator: std.mem.Allocator, secure_cookie: bool, token: []const u8) ![]u8 {
    if (secure_cookie) {
        return std.fmt.allocPrint(
            allocator,
            "{s}={s}; HttpOnly; SameSite=Strict; Path=/; Secure",
            .{ CookieName, token },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{s}={s}; HttpOnly; SameSite=Strict; Path=/",
        .{ CookieName, token },
    );
}

pub fn validate(req: http_types.Request, form_token: ?[]const u8) bool {
    const token = form_token orelse return false;
    const cookie_header = req.cookie orelse return false;
    const cookie_token = parseCookie(cookie_header) orelse return false;
    return std.mem.eql(u8, cookie_token, token);
}

pub fn parseCookie(cookie_header: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t");
        const value = part[eq + 1 ..];
        if (std.mem.eql(u8, name, CookieName)) return value;
    }
    return null;
}

test "parseCookie finds token" {
    try std.testing.expectEqualStrings("abc", parseCookie("feddyspice_csrf=abc").?);
    try std.testing.expectEqualStrings("abc", parseCookie("x=y; feddyspice_csrf=abc; z=w").?);
    try std.testing.expect(parseCookie("x=y") == null);
}

test "validate checks cookie and form field" {
    const req: http_types.Request = .{
        .method = .POST,
        .target = "/signup",
        .cookie = "feddyspice_csrf=abc",
    };
    try std.testing.expect(validate(req, "abc"));
    try std.testing.expect(!validate(req, "nope"));
    try std.testing.expect(!validate(req, null));
}

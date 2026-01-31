const std = @import("std");

pub const Response = struct {
    status: std.http.Status,
    content_type: []const u8 = "text/plain; charset=utf-8",
    body: []const u8,
};

pub fn route(method: std.http.Method, target: []const u8) Response {
    const path = targetPath(target);

    if (method == .GET and std.mem.eql(u8, path, "/healthz")) {
        return .{ .status = .ok, .body = "ok\n" };
    }

    return .{ .status = .not_found, .body = "not found\n" };
}

fn targetPath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| {
        return target[0..idx];
    }
    return target;
}

test "GET /healthz -> 200" {
    const resp = route(.GET, "/healthz");
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
}

test "unknown route -> 404" {
    const resp = route(.GET, "/nope");
    try std.testing.expectEqual(std.http.Status.not_found, resp.status);
}

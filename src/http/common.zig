const std = @import("std");

const form = @import("../form.zig");
const http_types = @import("../http_types.zig");

pub fn jsonOk(allocator: std.mem.Allocator, payload: anytype) http_types.Response {
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn bearerToken(authorization: ?[]const u8) ?[]const u8 {
    const h = authorization orelse return null;
    const prefix = "Bearer ";
    if (h.len < prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(h[0..prefix.len], prefix)) return null;
    return std.mem.trim(u8, h[prefix.len..], " \t");
}

pub fn unauthorized(allocator: std.mem.Allocator) http_types.Response {
    const body = std.json.Stringify.valueAlloc(allocator, .{ .@"error" = "unauthorized" }, .{}) catch
        return .{ .status = .unauthorized, .body = "unauthorized\n" };
    return .{
        .status = .unauthorized,
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn queryString(target: []const u8) []const u8 {
    const idx = std.mem.indexOfScalar(u8, target, '?') orelse return "";
    return target[idx + 1 ..];
}

pub fn parseQueryParam(
    allocator: std.mem.Allocator,
    query: []const u8,
    name: []const u8,
) !?[]const u8 {
    if (query.len == 0) return null;
    var parsed = try form.parse(allocator, query);
    return parsed.get(name);
}

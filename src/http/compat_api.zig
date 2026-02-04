const std = @import("std");

const common = @import("common.zig");
const http_types = @import("../http_types.zig");

pub fn maybeHandle(allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) ?http_types.Response {
    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/custom_emojis")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/follow_requests")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/scheduled_statuses")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/lists")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/announcements")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/trends/tags")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/filters")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/suggestions")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/followed_tags")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/preferences")) {
        const payload: struct {} = .{};
        return common.jsonOk(allocator, payload);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/push/subscription")) {
        const payload: struct {} = .{};
        return common.jsonOk(allocator, payload);
    }

    if (std.mem.eql(u8, path, "/api/v1/markers")) {
        if (req.method == .GET or req.method == .POST) {
            const updated_at = "1970-01-01T00:00:00.000Z";
            return common.jsonOk(allocator, .{
                .home = .{ .last_read_id = "0", .version = 0, .updated_at = updated_at },
                .notifications = .{ .last_read_id = "0", .version = 0, .updated_at = updated_at },
            });
        }
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/timelines/tag/")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/timelines/list/")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/link")) {
        return common.jsonOk(allocator, [_]i32{});
    }

    return null;
}

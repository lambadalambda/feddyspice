const std = @import("std");

const app = @import("../app.zig");
const http_types = @import("../http_types.zig");
const url = @import("../util/url.zig");
const version = @import("../version.zig");

fn jsonOk(allocator: std.mem.Allocator, payload: anytype) http_types.Response {
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn instanceV1(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const payload = .{
        .uri = app_state.cfg.domain,
        .title = "feddyspice",
        .short_description = "single-user server",
        .version = version.version,
        .registrations = true,
    };

    return jsonOk(allocator, payload);
}

pub fn instancePeers(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return jsonOk(allocator, [_][]const u8{});
}

pub fn instanceActivity(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return jsonOk(allocator, [_]i32{});
}

pub fn instanceExtendedDescription(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    const updated_at = "1970-01-01T00:00:00.000Z";
    return jsonOk(allocator, .{ .updated_at = updated_at, .content = "" });
}

pub fn directory(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return jsonOk(allocator, [_]i32{});
}

pub fn instanceV2(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const streaming_url = url.streamingBaseUrlAlloc(app_state, allocator) catch "";
    const payload = .{
        .domain = app_state.cfg.domain,
        .title = "feddyspice",
        .version = version.version,
        .source_url = "",
        .description = "single-user server",
        .registrations = .{
            .enabled = true,
            .approval_required = false,
        },
        .thumbnail = .{ .url = "" },
        .languages = [_][]const u8{"en"},
        .configuration = .{
            .urls = .{ .streaming = streaming_url },
            .polls = .{
                .max_characters_per_option = 25,
                .max_expiration = 2629746,
                .max_options = 4,
                .min_expiration = 300,
            },
            .statuses = .{
                .max_characters = 500,
                .max_media_attachments = 4,
            },
            .vapid = .{ .public_key = "" },
        },
        .usage = .{ .users = .{ .active_month = 1 } },
        .rules = [_]struct { id: []const u8, text: []const u8 }{},
    };

    return jsonOk(allocator, payload);
}

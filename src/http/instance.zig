const std = @import("std");

const app = @import("../app.zig");
const db = @import("../db.zig");
const common = @import("common.zig");
const http_types = @import("../http_types.zig");
const url = @import("../util/url.zig");
const version = @import("../version.zig");

const RulePayload = struct {
    id: []const u8,
    text: []const u8,
};

const DomainBlockPayload = struct {
    domain: []const u8,
    digest: []const u8,
    severity: []const u8,
    comment: ?[]const u8 = null,
};

fn countOrZero(conn: *db.Db, sql: [:0]const u8) i64 {
    var stmt = conn.prepareZ(sql) catch return 0;
    defer stmt.finalize();

    switch (stmt.step() catch return 0) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

fn registrationsEnabled(user_count: i64) bool {
    // In single-user mode, registration is only available before the first account exists.
    return user_count == 0;
}

pub fn instanceV1(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const streaming_url = url.streamingBaseUrlAlloc(app_state, allocator) catch "";

    const user_count = countOrZero(&app_state.conn, "SELECT COUNT(*) FROM users;\x00");
    const status_count = countOrZero(&app_state.conn, "SELECT COUNT(*) FROM statuses WHERE deleted_at IS NULL;\x00");
    const domain_count = countOrZero(&app_state.conn, "SELECT COUNT(DISTINCT domain) FROM remote_actors;\x00");
    const registrations_enabled = registrationsEnabled(user_count);

    const payload = .{
        .uri = app_state.cfg.domain,
        .title = "feddyspice",
        .short_description = "single-user server",
        .description = "single-user server",
        .email = "",
        .version = version.version,
        .registrations = registrations_enabled,
        .approval_required = false,
        .invites_enabled = false,
        .urls = .{ .streaming_api = streaming_url },
        .stats = .{ .user_count = user_count, .status_count = status_count, .domain_count = domain_count },
        .languages = [_][]const u8{"en"},
        .rules = [_]RulePayload{},
    };

    return common.jsonOk(allocator, payload);
}

pub fn instancePeers(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return common.jsonOk(allocator, [_][]const u8{});
}

pub fn instanceActivity(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return common.jsonOk(allocator, [_]i32{});
}

pub fn instanceRules(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return common.jsonOk(allocator, [_]RulePayload{});
}

pub fn instanceDomainBlocks(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return common.jsonOk(allocator, [_]DomainBlockPayload{});
}

pub fn instanceTranslationLanguages(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    const payload: struct {} = .{};
    return common.jsonOk(allocator, payload);
}

pub fn instanceExtendedDescription(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    const updated_at = "1970-01-01T00:00:00.000Z";
    return common.jsonOk(allocator, .{ .updated_at = updated_at, .content = "" });
}

pub fn directory(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    _ = app_state;
    return common.jsonOk(allocator, [_]i32{});
}

pub fn instanceV2(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const streaming_url = url.streamingBaseUrlAlloc(app_state, allocator) catch "";
    const user_count = countOrZero(&app_state.conn, "SELECT COUNT(*) FROM users;\x00");
    const registrations_enabled = registrationsEnabled(user_count);

    const payload = .{
        .domain = app_state.cfg.domain,
        .title = "feddyspice",
        .version = version.version,
        .source_url = "",
        .description = "single-user server",
        .registrations = .{
            .enabled = registrations_enabled,
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

    return common.jsonOk(allocator, payload);
}

const std = @import("std");

const app = @import("../app.zig");

pub fn stripLocalBase(app_state: *app.App, iri: []const u8) ?[]const u8 {
    const domain = app_state.cfg.domain;

    const schemes = [_][]const u8{ "http://", "https://" };
    for (schemes) |scheme| {
        if (!std.mem.startsWith(u8, iri, scheme)) continue;
        const rest = iri[scheme.len..];
        if (!std.mem.startsWith(u8, rest, domain)) continue;
        const after_domain = rest[domain.len..];
        if (after_domain.len == 0) return "";
        if (after_domain[0] == '/') return after_domain;
    }
    return null;
}

fn parseLeadingI64(s: []const u8) ?i64 {
    if (s.len == 0) return null;
    var end: usize = 0;
    while (end < s.len and s[end] >= '0' and s[end] <= '9') : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(i64, s[0..end], 10) catch null;
}

pub fn localStatusIdFromIri(app_state: *app.App, iri: []const u8) ?i64 {
    const path = stripLocalBase(app_state, iri) orelse return null;
    if (path.len == 0) return null;

    const api_prefix = "/api/v1/statuses/";
    if (std.mem.startsWith(u8, path, api_prefix)) {
        const rest = path[api_prefix.len..];
        const id = parseLeadingI64(rest) orelse return null;
        if (id <= 0) return null;
        return id;
    }

    const users_prefix = "/users/";
    if (!std.mem.startsWith(u8, path, users_prefix)) return null;
    const rest = path[users_prefix.len..];
    const marker = "/statuses/";
    const idx = std.mem.indexOf(u8, rest, marker) orelse return null;
    if (idx == 0) return null;
    const after_marker = rest[idx + marker.len ..];
    const id = parseLeadingI64(after_marker) orelse return null;
    if (id <= 0) return null;
    return id;
}

test "localStatusIdFromIri parses v1 and AP object URLs" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    try std.testing.expectEqual(@as(?i64, 123), localStatusIdFromIri(&app_state, "https://example.test/api/v1/statuses/123"));
    try std.testing.expectEqual(@as(?i64, 123), localStatusIdFromIri(&app_state, "http://example.test/api/v1/statuses/123"));
    try std.testing.expectEqual(@as(?i64, 123), localStatusIdFromIri(&app_state, "https://example.test/api/v1/statuses/123?x=1"));

    try std.testing.expectEqual(@as(?i64, 456), localStatusIdFromIri(&app_state, "https://example.test/users/alice/statuses/456"));
    try std.testing.expectEqual(@as(?i64, 456), localStatusIdFromIri(&app_state, "http://example.test/users/alice/statuses/456#frag"));

    try std.testing.expectEqual(@as(?i64, null), localStatusIdFromIri(&app_state, "https://other.test/api/v1/statuses/1"));
    try std.testing.expectEqual(@as(?i64, null), localStatusIdFromIri(&app_state, "https://example.test/api/v1/statuses/0"));
    try std.testing.expectEqual(@as(?i64, null), localStatusIdFromIri(&app_state, "https://example.test/api/v1/statuses/not-a-number"));
}

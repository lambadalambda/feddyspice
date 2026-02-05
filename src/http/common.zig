const std = @import("std");

const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const util_html = @import("../util/html.zig");

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

pub fn targetPath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| return target[0..idx];
    return target;
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

pub fn redirect(allocator: std.mem.Allocator, location: []const u8) http_types.Response {
    const headers = allocator.alloc(std.http.Header, 1) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    headers[0] = .{ .name = "location", .value = if (headerValueIsSafe(location)) location else "/" };

    return .{
        .status = .see_other,
        .body = "redirecting\n",
        .headers = headers,
    };
}

pub fn headerValueIsSafe(value: []const u8) bool {
    for (value) |c| {
        if (c == '\r' or c == '\n' or c == 0) return false;
    }
    return true;
}

pub fn safeReturnTo(return_to: ?[]const u8) ?[]const u8 {
    const rt = return_to orelse return null;
    if (!std.mem.startsWith(u8, rt, "/")) return null;
    if (std.mem.indexOf(u8, rt, "://") != null) return null;
    if (!headerValueIsSafe(rt)) return null;
    return rt;
}

pub fn isSameOrigin(req: http_types.Request, expected_scheme: []const u8, expected_host: []const u8) bool {
    const expected_host_port = parseHostHeader(expected_host);
    const expected = HostAndPort{
        .host = expected_host_port.host,
        .port = expected_host_port.port orelse defaultPortForScheme(expected_scheme),
    };

    if (req.origin) |o| return uriHasSameOrigin(o, expected_scheme, expected);
    if (req.referer) |r| return uriHasSameOrigin(r, expected_scheme, expected);
    return true;
}

const HostAndPort = struct {
    host: []const u8,
    port: ?u16,
};

fn parseHostHeader(host_hdr_raw: []const u8) HostAndPort {
    const host_hdr = std.mem.trim(u8, host_hdr_raw, " \t");
    if (host_hdr.len == 0) return .{ .host = host_hdr, .port = null };

    if (host_hdr[0] == '[') {
        const close_i = std.mem.indexOfScalar(u8, host_hdr, ']') orelse
            return .{ .host = host_hdr, .port = null };
        const host = host_hdr[1..close_i];
        if (close_i + 1 < host_hdr.len and host_hdr[close_i + 1] == ':') {
            const port_str = host_hdr[close_i + 2 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch null;
            return .{ .host = host, .port = port };
        }
        return .{ .host = host, .port = null };
    }

    if (std.mem.lastIndexOfScalar(u8, host_hdr, ':')) |colon_i| {
        const host = host_hdr[0..colon_i];
        const port_str = host_hdr[colon_i + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch null;
        if (port != null and host.len > 0) return .{ .host = host, .port = port };
    }

    return .{ .host = host_hdr, .port = null };
}

fn uriHasSameOrigin(uri_str: []const u8, expected_scheme: []const u8, expected: HostAndPort) bool {
    const uri = std.Uri.parse(uri_str) catch return false;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, expected_scheme)) return false;

    var host_buf: [std.Uri.host_name_max]u8 = undefined;
    const host = uri.getHost(&host_buf) catch return false;
    if (!std.ascii.eqlIgnoreCase(host, expected.host)) return false;

    if (expected.port) |p| {
        const got_port: u16 = uri.port orelse defaultPortForScheme(uri.scheme);
        return got_port == p;
    }

    return true;
}

fn defaultPortForScheme(scheme: []const u8) u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    return 443;
}

pub fn percentEncodeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    for (raw) |c| {
        if (isUnreserved(c)) {
            try aw.writer.writeByte(c);
        } else {
            try aw.writer.print("%{X:0>2}", .{c});
        }
    }

    const out = try aw.toOwnedSlice();
    aw.deinit();
    return out;
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

pub fn htmlEscapeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    return util_html.htmlEscapeAlloc(allocator, raw);
}

pub fn htmlPage(allocator: std.mem.Allocator, title: []const u8, inner_html: []const u8) http_types.Response {
    const body = std.fmt.allocPrint(
        allocator,
        \\<!doctype html>
        \\<html>
        \\  <head><meta charset="utf-8"><title>{s}</title></head>
        \\  <body>
        \\    <h1>{s}</h1>
        \\    {s}
        \\  </body>
        \\</html>
    ,
        .{ title, title, inner_html },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "text/html; charset=utf-8",
        .body = body,
    };
}

pub fn isForm(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "application/x-www-form-urlencoded");
}

test "safeReturnTo rejects header injection" {
    try std.testing.expectEqualStrings("/ok", safeReturnTo("/ok").?);
    try std.testing.expect(safeReturnTo("/\r\nx: y") == null);
    try std.testing.expect(safeReturnTo("/\nx") == null);
}

test "redirect sanitizes Location header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const resp = redirect(a, "/\r\nx: y");
    try std.testing.expectEqual(std.http.Status.see_other, resp.status);
    try std.testing.expectEqualStrings("/", resp.headers[0].value);
}

test "isSameOrigin validates Origin/Referer host and port (when present)" {
    const base: http_types.Request = .{
        .method = .POST,
        .target = "/",
        .host = "example.test",
    };

    try std.testing.expect(isSameOrigin(base, "https", "example.test"));

    var origin_ok = base;
    origin_ok.origin = "https://example.test";
    try std.testing.expect(isSameOrigin(origin_ok, "https", "example.test"));

    var origin_bad = base;
    origin_bad.origin = "https://evil.test";
    try std.testing.expect(!isSameOrigin(origin_bad, "https", "example.test"));

    const with_port: http_types.Request = .{
        .method = .POST,
        .target = "/",
        .host = "example.test:8080",
    };
    var origin_port_ok = with_port;
    origin_port_ok.origin = "http://example.test:8080/some/path";
    try std.testing.expect(isSameOrigin(origin_port_ok, "http", "example.test:8080"));

    var origin_port_bad = with_port;
    origin_port_bad.origin = "http://example.test:3000/";
    try std.testing.expect(!isSameOrigin(origin_port_bad, "http", "example.test:8080"));

    var referer_ok = with_port;
    referer_ok.referer = "https://example.test:8080/x";
    try std.testing.expect(isSameOrigin(referer_ok, "https", "example.test:8080"));
}

test "isSameOrigin checks scheme, not just host" {
    const req: http_types.Request = .{
        .method = .POST,
        .target = "/",
        .origin = "http://example.test",
    };

    try std.testing.expect(!isSameOrigin(req, "https", "example.test"));
    try std.testing.expect(isSameOrigin(req, "http", "example.test"));
}

test "isSameOrigin uses configured origin, not Host header" {
    const req: http_types.Request = .{
        .method = .POST,
        .target = "/signup",
        .host = "127.0.0.1:8080",
        .origin = "https://social.example.com",
    };

    try std.testing.expect(isSameOrigin(req, "https", "social.example.com"));
}

pub fn isJson(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "application/json");
}

pub fn isMultipart(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "multipart/form-data");
}

pub fn parseBodyParams(allocator: std.mem.Allocator, req: http_types.Request) !form.Form {
    if (isForm(req.content_type)) return try form.parse(allocator, req.body);
    if (isJson(req.content_type)) return try form.parseJson(allocator, req.body);
    if (isMultipart(req.content_type)) return try form.parseMultipart(allocator, req.content_type.?, req.body);
    return error.UnsupportedContentType;
}

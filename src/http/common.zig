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
    headers[0] = .{ .name = "location", .value = location };

    return .{
        .status = .see_other,
        .body = "redirecting\n",
        .headers = headers,
    };
}

pub fn safeReturnTo(return_to: ?[]const u8) ?[]const u8 {
    const rt = return_to orelse return null;
    if (!std.mem.startsWith(u8, rt, "/")) return null;
    if (std.mem.indexOf(u8, rt, "://") != null) return null;
    return rt;
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

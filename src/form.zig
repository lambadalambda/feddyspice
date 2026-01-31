const std = @import("std");

pub const Form = struct {
    map: std.StringHashMapUnmanaged([]const u8),

    pub fn get(form: *const Form, key: []const u8) ?[]const u8 {
        return form.map.get(key);
    }

    pub fn deinit(form: *Form, allocator: std.mem.Allocator) void {
        form.map.deinit(allocator);
        form.* = undefined;
    }
};

pub fn parse(allocator: std.mem.Allocator, body: []const u8) !Form {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    var it = std.mem.splitScalar(u8, body, '&');
    while (it.next()) |pair_raw| {
        if (pair_raw.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair_raw, '=') orelse continue;

        const key_enc = pair_raw[0..eq];
        const val_enc = pair_raw[eq + 1 ..];

        const key = try decode(allocator, key_enc);
        const value = try decode(allocator, val_enc);

        try map.put(allocator, key, value);
    }

    return .{ .map = map };
}

pub fn parseJson(allocator: std.mem.Allocator, body: []const u8) !Form {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const maybe_val = try jsonValueToStringAlloc(allocator, entry.value_ptr.*);
        if (maybe_val == null) continue;

        const key_copy = try allocator.dupe(u8, key);
        try map.put(allocator, key_copy, maybe_val.?);
    }

    return .{ .map = map };
}

fn jsonValueToStringAlloc(allocator: std.mem.Allocator, val: std.json.Value) !?[]u8 {
    return switch (val) {
        .string => |s| try allocator.dupe(u8, s),
        .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
        .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
        .null => null,
        .array => |arr| blk: {
            // If this is an array of strings, join with "\n" (common for redirect_uris).
            if (arr.items.len == 0) break :blk try allocator.dupe(u8, "");

            var out: std.ArrayList(u8) = .{};
            errdefer out.deinit(allocator);

            for (arr.items, 0..) |item, idx| {
                if (item != .string) return null;
                if (idx != 0) try out.append(allocator, '\n');
                try out.appendSlice(allocator, item.string);
            }

            break :blk try out.toOwnedSlice(allocator);
        },
        else => null,
    };
}

pub fn parseMultipart(allocator: std.mem.Allocator, content_type: []const u8, body: []const u8) !Form {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    const boundary = boundaryFromContentType(content_type) orelse return error.MissingBoundary;

    const delim = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
    const delim_with_lf = try std.fmt.allocPrint(allocator, "\n--{s}", .{boundary});

    var pos: usize = std.mem.indexOf(u8, body, delim) orelse return error.InvalidMultipart;

    while (true) {
        const boundary_pos = std.mem.indexOfPos(u8, body, pos, delim) orelse break;
        pos = boundary_pos + delim.len;

        if (pos + 2 <= body.len and std.mem.eql(u8, body[pos .. pos + 2], "--")) break; // final boundary

        if (pos < body.len and body[pos] == '\r') pos += 1;
        if (pos < body.len and body[pos] == '\n') pos += 1;

        const headers_end_crlf = std.mem.indexOfPos(u8, body, pos, "\r\n\r\n");
        const headers_end_lf = std.mem.indexOfPos(u8, body, pos, "\n\n");

        var headers_end: usize = undefined;
        var sep_len: usize = undefined;
        if (headers_end_crlf) |idx| {
            headers_end = idx;
            sep_len = 4;
        } else if (headers_end_lf) |idx| {
            headers_end = idx;
            sep_len = 2;
        } else {
            return error.InvalidMultipart;
        }

        const headers = body[pos..headers_end];
        const content_start = headers_end + sep_len;

        const next_marker = std.mem.indexOfPos(u8, body, content_start, delim_with_lf) orelse
            return error.InvalidMultipart;

        var content_end: usize = next_marker;
        if (content_end > content_start and body[content_end - 1] == '\r') content_end -= 1;
        const content = body[content_start..content_end];

        const name = multipartPartName(headers) orelse {
            pos = next_marker + 1;
            continue;
        };
        if (std.mem.indexOf(u8, headers, "filename=") != null) {
            pos = next_marker + 1;
            continue;
        }

        const key_copy = try allocator.dupe(u8, name);
        const val_copy = try allocator.dupe(u8, content);
        try map.put(allocator, key_copy, val_copy);

        pos = next_marker + 1;
    }

    return .{ .map = map };
}

fn boundaryFromContentType(content_type: []const u8) ?[]const u8 {
    const needle = "boundary=";
    const idx = std.mem.indexOf(u8, content_type, needle) orelse return null;
    var rest = content_type[idx + needle.len ..];
    rest = std.mem.trim(u8, rest, " \t");
    if (rest.len == 0) return null;

    if (rest[0] == '"') {
        rest = rest[1..];
        const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
        return rest[0..end];
    }

    const end = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
    return std.mem.trimRight(u8, rest[0..end], " \t");
}

fn multipartPartName(headers: []const u8) ?[]const u8 {
    const needle = "name=\"";
    if (std.mem.indexOf(u8, headers, needle)) |idx| {
        const start = idx + needle.len;
        const end = std.mem.indexOfPos(u8, headers, start, "\"") orelse return null;
        return headers[start..end];
    }

    const needle2 = "name=";
    if (std.mem.indexOf(u8, headers, needle2)) |idx| {
        var start = idx + needle2.len;
        if (start >= headers.len) return null;

        if (headers[start] == '"') {
            start += 1;
            const endq = std.mem.indexOfPos(u8, headers, start, "\"") orelse return null;
            return headers[start..endq];
        }

        const end = std.mem.indexOfAnyPos(u8, headers, start, ";\r\n") orelse headers.len;
        return headers[start..end];
    }

    return null;
}

fn decode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, s.len);
    var o: usize = 0;

    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '+') {
            out[o] = ' ';
            o += 1;
            continue;
        }

        if (c == '%' and i + 2 < s.len) {
            const hi = fromHex(s[i + 1]) orelse return error.InvalidEncoding;
            const lo = fromHex(s[i + 2]) orelse return error.InvalidEncoding;
            out[o] = (hi << 4) | lo;
            o += 1;
            i += 2;
            continue;
        }

        out[o] = c;
        o += 1;
    }

    return out[0..o];
}

fn fromHex(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

test "parse: urlencoded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var form = try parse(arena.allocator(), "a=b&c=d+e&x=%2F");

    try std.testing.expectEqualStrings("b", form.get("a").?);
    try std.testing.expectEqualStrings("d e", form.get("c").?);
    try std.testing.expectEqualStrings("/", form.get("x").?);
}

test "parseJson: object to form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var form = try parseJson(arena.allocator(), "{\"a\":\"b\",\"c\":1,\"d\":true}");
    try std.testing.expectEqualStrings("b", form.get("a").?);
    try std.testing.expectEqualStrings("1", form.get("c").?);
    try std.testing.expectEqualStrings("true", form.get("d").?);
}

test "parseMultipart: simple fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ct = "multipart/form-data; boundary=----b";
    const body =
        "------b\r\n" ++
        "Content-Disposition: form-data; name=\"a\"\r\n" ++
        "\r\n" ++
        "b\r\n" ++
        "------b\r\n" ++
        "Content-Disposition: form-data; name=\"c\"\r\n" ++
        "\r\n" ++
        "d\r\n" ++
        "------b--\r\n";

    var form = try parseMultipart(a, ct, body);
    try std.testing.expectEqualStrings("b", form.get("a").?);
    try std.testing.expectEqualStrings("d", form.get("c").?);
}

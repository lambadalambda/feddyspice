const std = @import("std");

pub const Form = struct {
    map: std.StringHashMapUnmanaged([]const u8),

    pub fn get(form: *const Form, key: []const u8) ?[]const u8 {
        return form.map.get(key);
    }

    pub fn deinit(form: *Form, allocator: std.mem.Allocator) void {
        var it = form.map.iterator();
        while (it.next()) |entry| {
            allocator.free(@constCast(entry.key_ptr.*));
            allocator.free(@constCast(entry.value_ptr.*));
        }
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

        try putOrAppend(allocator, &map, key, value);
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
        try putOrAppend(allocator, &map, key_copy, maybe_val.?);
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

const MultipartIter = struct {
    allocator: std.mem.Allocator,
    body: []const u8,
    delim: []u8,
    delim_with_lf: []u8,
    pos: usize,

    const Part = struct {
        headers: []const u8,
        content: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, content_type: []const u8, body: []const u8) !MultipartIter {
        const boundary = boundaryFromContentType(content_type) orelse return error.MissingBoundary;

        const delim = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
        errdefer allocator.free(delim);
        const delim_with_lf = try std.fmt.allocPrint(allocator, "\n--{s}", .{boundary});
        errdefer allocator.free(delim_with_lf);

        const pos = std.mem.indexOf(u8, body, delim) orelse return error.InvalidMultipart;

        return .{
            .allocator = allocator,
            .body = body,
            .delim = delim,
            .delim_with_lf = delim_with_lf,
            .pos = pos,
        };
    }

    pub fn deinit(self: *MultipartIter) void {
        self.allocator.free(self.delim);
        self.allocator.free(self.delim_with_lf);
        self.* = undefined;
    }

    pub fn next(self: *MultipartIter) !?Part {
        const boundary_pos = std.mem.indexOfPos(u8, self.body, self.pos, self.delim) orelse return null;
        var pos = boundary_pos + self.delim.len;

        if (pos + 2 <= self.body.len and std.mem.eql(u8, self.body[pos .. pos + 2], "--")) return null; // final boundary

        if (pos < self.body.len and self.body[pos] == '\r') pos += 1;
        if (pos < self.body.len and self.body[pos] == '\n') pos += 1;

        const headers_end_crlf = std.mem.indexOfPos(u8, self.body, pos, "\r\n\r\n");
        const headers_end_lf = std.mem.indexOfPos(u8, self.body, pos, "\n\n");

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

        const headers = self.body[pos..headers_end];
        const content_start = headers_end + sep_len;

        const next_marker = std.mem.indexOfPos(u8, self.body, content_start, self.delim_with_lf) orelse
            return error.InvalidMultipart;

        var content_end: usize = next_marker;
        if (content_end > content_start and self.body[content_end - 1] == '\r') content_end -= 1;
        const content = self.body[content_start..content_end];

        self.pos = next_marker + 1;
        return .{ .headers = headers, .content = content };
    }
};

pub fn parseMultipart(allocator: std.mem.Allocator, content_type: []const u8, body: []const u8) !Form {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    var iter = try MultipartIter.init(allocator, content_type, body);
    defer iter.deinit();

    while (try iter.next()) |part| {
        const name = multipartPartName(part.headers) orelse continue;
        if (std.mem.indexOf(u8, part.headers, "filename=") != null) continue;

        const key_copy = try allocator.dupe(u8, name);
        const val_copy = try allocator.dupe(u8, part.content);
        try putOrAppend(allocator, &map, key_copy, val_copy);
    }

    return .{ .map = map };
}

pub const MultipartFilePart = struct {
    name: []const u8,
    filename: ?[]const u8,
    content_type: ?[]const u8,
    data: []const u8,
};

pub const MultipartWithFile = struct {
    form: Form,
    file: ?MultipartFilePart,

    pub fn deinit(self: *MultipartWithFile, allocator: std.mem.Allocator) void {
        self.form.deinit(allocator);
        self.* = undefined;
    }
};

pub const MultipartWithFiles = struct {
    form: Form,
    files: []const MultipartFilePart,

    pub fn deinit(self: *MultipartWithFiles, allocator: std.mem.Allocator) void {
        self.form.deinit(allocator);
        if (self.files.len > 0) allocator.free(@constCast(self.files));
        self.* = undefined;
    }
};

pub fn parseMultipartWithFile(
    allocator: std.mem.Allocator,
    content_type: []const u8,
    body: []const u8,
) !MultipartWithFile {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    var file: ?MultipartFilePart = null;

    var iter = try MultipartIter.init(allocator, content_type, body);
    defer iter.deinit();

    while (try iter.next()) |part| {
        const name = multipartPartName(part.headers) orelse continue;

        if (std.mem.indexOf(u8, part.headers, "filename=") != null) {
            if (file == null) {
                file = .{
                    .name = name,
                    .filename = multipartPartFilename(part.headers),
                    .content_type = multipartPartContentType(part.headers),
                    .data = part.content,
                };
            }
            continue;
        }

        const key_copy = try allocator.dupe(u8, name);
        const val_copy = try allocator.dupe(u8, part.content);
        try putOrAppend(allocator, &map, key_copy, val_copy);
    }

    return .{
        .form = .{ .map = map },
        .file = file,
    };
}

pub fn parseMultipartWithFiles(
    allocator: std.mem.Allocator,
    content_type: []const u8,
    body: []const u8,
) !MultipartWithFiles {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(allocator);

    var files: std.ArrayListUnmanaged(MultipartFilePart) = .empty;
    errdefer files.deinit(allocator);

    var iter = try MultipartIter.init(allocator, content_type, body);
    defer iter.deinit();

    while (try iter.next()) |part| {
        const name = multipartPartName(part.headers) orelse continue;

        if (std.mem.indexOf(u8, part.headers, "filename=") != null) {
            try files.append(allocator, .{
                .name = name,
                .filename = multipartPartFilename(part.headers),
                .content_type = multipartPartContentType(part.headers),
                .data = part.content,
            });
            continue;
        }

        const key_copy = try allocator.dupe(u8, name);
        const val_copy = try allocator.dupe(u8, part.content);
        try putOrAppend(allocator, &map, key_copy, val_copy);
    }

    const files_slice = if (files.items.len == 0) &[_]MultipartFilePart{} else try files.toOwnedSlice(allocator);

    return .{
        .form = .{ .map = map },
        .files = files_slice,
    };
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

fn multipartPartFilename(headers: []const u8) ?[]const u8 {
    const needle = "filename=\"";
    if (std.mem.indexOf(u8, headers, needle)) |idx| {
        const start = idx + needle.len;
        const end = std.mem.indexOfPos(u8, headers, start, "\"") orelse return null;
        return headers[start..end];
    }

    const needle2 = "filename=";
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

fn multipartPartContentType(headers: []const u8) ?[]const u8 {
    const prefix = "content-type:";
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |line_raw| {
        const line_no_cr = std.mem.trimRight(u8, line_raw, "\r");
        const line = std.mem.trim(u8, line_no_cr, " \t");
        if (line.len >= prefix.len and std.ascii.eqlIgnoreCase(line[0..prefix.len], prefix)) {
            const rest = std.mem.trim(u8, line[prefix.len..], " \t");
            return if (rest.len == 0) null else rest;
        }
    }
    return null;
}

fn putOrAppend(
    allocator: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged([]const u8),
    key: []u8,
    value: []u8,
) std.mem.Allocator.Error!void {
    const is_array = std.mem.endsWith(u8, key, "[]");
    if (map.getEntry(key)) |entry| {
        allocator.free(key);

        if (is_array) {
            const old = entry.value_ptr.*;
            const combined = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ old, value });
            allocator.free(@constCast(old));
            allocator.free(value);
            entry.value_ptr.* = combined;
            return;
        }

        allocator.free(@constCast(entry.value_ptr.*));
        entry.value_ptr.* = value;
        return;
    }

    try map.put(allocator, key, value);
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

test "parseMultipartWithFile: extracts fields + file" {
    const ct = "multipart/form-data; boundary=abc";
    const body =
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"description\"\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "PNGDATA\r\n" ++
        "--abc--\r\n";

    var parsed = try parseMultipartWithFile(std.testing.allocator, ct, body);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("hello", parsed.form.get("description").?);
    try std.testing.expect(parsed.file != null);
    try std.testing.expectEqualStrings("file", parsed.file.?.name);
    try std.testing.expectEqualStrings("a.png", parsed.file.?.filename.?);
    try std.testing.expectEqualStrings("image/png", parsed.file.?.content_type.?);
    try std.testing.expectEqualStrings("PNGDATA", parsed.file.?.data);
}

test "parse: joins repeated [] keys" {
    var parsed = try parse(std.testing.allocator, "id[]=1&id[]=2");
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("1\n2", parsed.get("id[]").?);
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

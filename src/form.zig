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


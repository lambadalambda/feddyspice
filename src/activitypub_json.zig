const std = @import("std");

const util_url = @import("util/url.zig");

pub fn truthiness(v: ?std.json.Value) bool {
    const val = v orelse return false;
    return switch (val) {
        .bool => |b| b,
        else => false,
    };
}

pub fn containsIri(v: ?std.json.Value, needle: []const u8) bool {
    const val = v orelse return false;
    const want = util_url.trimTrailingSlash(needle);

    switch (val) {
        .string => |s| return std.mem.eql(u8, util_url.trimTrailingSlash(s), want),
        .object => |o| {
            const id_val = o.get("id") orelse return false;
            if (id_val != .string) return false;
            return std.mem.eql(u8, util_url.trimTrailingSlash(id_val.string), want);
        },
        .array => |arr| {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| if (std.mem.eql(u8, util_url.trimTrailingSlash(s), want)) return true,
                    .object => |o| {
                        const id_val = o.get("id") orelse continue;
                        if (id_val != .string) continue;
                        if (std.mem.eql(u8, util_url.trimTrailingSlash(id_val.string), want)) return true;
                    },
                    else => continue,
                }
            }
            return false;
        },
        else => return false,
    }
}

pub fn firstUrlString(val: std.json.Value) ?[]const u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else s,
        .object => |o| {
            if (o.get("url")) |u| {
                if (firstUrlString(u)) |s| return s;
            }
            if (o.get("href")) |h| {
                if (h == .string and h.string.len > 0) return h.string;
            }
            return null;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (firstUrlString(item)) |s| return s;
            }
            return null;
        },
        else => return null,
    }
}

test "truthiness returns true only for boolean true" {
    try std.testing.expect(!truthiness(null));
    try std.testing.expect(truthiness(.{ .bool = true }));
    try std.testing.expect(!truthiness(.{ .bool = false }));
    try std.testing.expect(!truthiness(.{ .integer = 1 }));
    try std.testing.expect(!truthiness(.{ .string = "true" }));
}

test "containsIri matches string, object id, and arrays (trailing slash tolerant)" {
    const want = "https://www.w3.org/ns/activitystreams#Public";

    try std.testing.expect(containsIri(.{ .string = want }, want));
    try std.testing.expect(containsIri(.{ .string = want ++ "/" }, want));
    try std.testing.expect(!containsIri(.{ .string = "https://example.test/x" }, want));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var parsed_obj = try std.json.parseFromSlice(
        std.json.Value,
        a,
        \\{"id":"https://www.w3.org/ns/activitystreams#Public/"}
    ,
        .{},
    );
    defer parsed_obj.deinit();
    try std.testing.expect(containsIri(parsed_obj.value, want));

    var parsed_arr = try std.json.parseFromSlice(
        std.json.Value,
        a,
        \\["https://example.test/other",{"id":"https://www.w3.org/ns/activitystreams#Public/"}]
    ,
        .{},
    );
    defer parsed_arr.deinit();
    try std.testing.expect(containsIri(parsed_arr.value, want));
}

test "firstUrlString extracts url/href from nested structures" {
    try std.testing.expectEqual(@as(?[]const u8, null), firstUrlString(.{ .string = "" }));
    try std.testing.expectEqualStrings("https://example.test/a", firstUrlString(.{ .string = "https://example.test/a" }).?);

    var obj = std.json.ObjectMap.init(std.testing.allocator);
    defer obj.deinit();
    try obj.put("href", .{ .string = "https://example.test/h" });
    try std.testing.expectEqualStrings("https://example.test/h", firstUrlString(.{ .object = obj }).?);
}

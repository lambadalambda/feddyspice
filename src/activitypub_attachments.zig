const std = @import("std");

const util_url = @import("util/url.zig");

fn jsonFirstUrl(val: std.json.Value) ?[]const u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else s,
        .object => |o| {
            if (o.get("url")) |u| {
                if (jsonFirstUrl(u)) |s| return s;
            }
            if (o.get("href")) |h| {
                if (h == .string and h.string.len > 0) return h.string;
            }
            return null;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (jsonFirstUrl(item)) |s| return s;
            }
            return null;
        },
        else => return null,
    }
}

pub fn remoteAttachmentsJsonAlloc(allocator: std.mem.Allocator, note: std.json.ObjectMap) !?[]u8 {
    const val = note.get("attachment") orelse return null;
    const max_attachments: usize = 4;

    const Attachment = struct {
        url: []const u8,
        kind: ?[]const u8 = null,
        media_type: ?[]const u8 = null,
        description: ?[]const u8 = null,
        blurhash: ?[]const u8 = null,
    };

    var list: std.ArrayListUnmanaged(Attachment) = .empty;
    defer list.deinit(allocator);

    const helper = struct {
        fn pushOne(
            alloc: std.mem.Allocator,
            out: *std.ArrayListUnmanaged(Attachment),
            item: std.json.Value,
        ) !void {
            const url = jsonFirstUrl(item) orelse return;
            if (!util_url.isHttpOrHttpsUrl(url)) return;

            var kind: ?[]const u8 = null;
            var media_type: ?[]const u8 = null;
            var description: ?[]const u8 = null;
            var blurhash: ?[]const u8 = null;

            if (item == .object) {
                if (item.object.get("type")) |t| {
                    if (t == .string and t.string.len > 0) kind = t.string;
                }
                if (item.object.get("mediaType")) |t| {
                    if (t == .string and t.string.len > 0) media_type = t.string;
                }
                if (item.object.get("name")) |t| {
                    if (t == .string and t.string.len > 0) description = t.string;
                }
                if (item.object.get("blurhash")) |t| {
                    if (t == .string and t.string.len > 0) blurhash = t.string;
                }
            }

            try out.append(alloc, .{
                .url = url,
                .kind = kind,
                .media_type = media_type,
                .description = description,
                .blurhash = blurhash,
            });
        }
    };

    switch (val) {
        .array => |arr| {
            for (arr.items) |item| {
                if (list.items.len >= max_attachments) break;
                try helper.pushOne(allocator, &list, item);
            }
        },
        else => try helper.pushOne(allocator, &list, val),
    }

    if (list.items.len == 0) return null;
    const json = try std.json.Stringify.valueAlloc(allocator, list.items, .{});
    return json;
}

test "remoteAttachmentsJsonAlloc ignores non-http(s) URLs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const note1 =
        \\{"attachment":[{"url":"javascript:alert(1)","type":"Image"},{"url":"https://cdn.test/a.png","type":"Image"}]}
    ;
    var parsed1 = try std.json.parseFromSlice(std.json.Value, a, note1, .{});
    defer parsed1.deinit();
    const out1 = (try remoteAttachmentsJsonAlloc(a, parsed1.value.object)).?;

    var out1_parsed = try std.json.parseFromSlice(std.json.Value, a, out1, .{});
    defer out1_parsed.deinit();
    try std.testing.expect(out1_parsed.value == .array);
    try std.testing.expectEqual(@as(usize, 1), out1_parsed.value.array.items.len);
}

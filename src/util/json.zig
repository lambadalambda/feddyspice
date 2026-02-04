const std = @import("std");

pub fn maxNestingDepth(json: []const u8) usize {
    var depth: usize = 0;
    var max_depth: usize = 0;

    var in_string: bool = false;
    var escaped: bool = false;

    for (json) |c| {
        if (in_string) {
            if (escaped) {
                escaped = false;
                continue;
            }
            switch (c) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }

        switch (c) {
            '"' => in_string = true,
            '{', '[' => {
                depth += 1;
                max_depth = @max(max_depth, depth);
            },
            '}', ']' => {
                if (depth > 0) depth -= 1;
            },
            else => {},
        }
    }

    return max_depth;
}

/// A cheap “complexity” metric: counts `:` and `,` tokens outside of strings.
/// This correlates with total object members + array elements without fully parsing JSON.
pub fn structuralTokenCount(json: []const u8) usize {
    var count: usize = 0;

    var in_string: bool = false;
    var escaped: bool = false;

    for (json) |c| {
        if (in_string) {
            if (escaped) {
                escaped = false;
                continue;
            }
            switch (c) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }

        switch (c) {
            '"' => in_string = true,
            ':', ',' => count += 1,
            else => {},
        }
    }

    return count;
}

test "maxNestingDepth counts braces and ignores strings" {
    try std.testing.expectEqual(@as(usize, 0), maxNestingDepth(""));
    try std.testing.expectEqual(@as(usize, 1), maxNestingDepth("[]"));
    try std.testing.expectEqual(@as(usize, 1), maxNestingDepth("{}"));
    try std.testing.expectEqual(@as(usize, 2), maxNestingDepth("[[]]"));
    try std.testing.expectEqual(@as(usize, 3), maxNestingDepth("[[[]]]"));
    try std.testing.expectEqual(@as(usize, 2), maxNestingDepth("{\"a\":[1]}"));
    try std.testing.expectEqual(@as(usize, 1), maxNestingDepth("{\"a\":\"[[[]]]\"}"));
    try std.testing.expectEqual(@as(usize, 1), maxNestingDepth("{\"a\":\"\\\\\\\"[\"}"));
}

test "structuralTokenCount counts separators and ignores strings" {
    try std.testing.expectEqual(@as(usize, 0), structuralTokenCount(""));
    try std.testing.expectEqual(@as(usize, 0), structuralTokenCount("[]"));
    try std.testing.expectEqual(@as(usize, 0), structuralTokenCount("{}"));

    try std.testing.expectEqual(@as(usize, 1), structuralTokenCount("{\"a\":1}"));
    try std.testing.expectEqual(@as(usize, 3), structuralTokenCount("{\"a\":1,\"b\":2}"));
    try std.testing.expectEqual(@as(usize, 2), structuralTokenCount("[1,2,3]"));

    try std.testing.expectEqual(@as(usize, 1), structuralTokenCount("{\"a\":\":,\\\"\"}"));
}

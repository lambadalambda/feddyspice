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

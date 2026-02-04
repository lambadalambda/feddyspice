const std = @import("std");

pub fn htmlEscapeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var needed: usize = 0;
    for (raw) |c| {
        needed += switch (c) {
            '&' => 5, // &amp;
            '<', '>' => 4, // &lt; &gt;
            '"' => 6, // &quot;
            '\'' => 5, // &#39;
            else => 1,
        };
    }

    var out = try allocator.alloc(u8, needed);
    var i: usize = 0;

    for (raw) |c| {
        const repl = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            else => null,
        };

        if (repl) |s| {
            @memcpy(out[i..][0..s.len], s);
            i += s.len;
        } else {
            out[i] = c;
            i += 1;
        }
    }

    return out;
}

pub fn textToHtmlAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const escaped = try htmlEscapeAlloc(allocator, text);
    return std.fmt.allocPrint(allocator, "<p>{s}</p>", .{escaped});
}

pub fn textToHtmlWithBreaksAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const escaped = try htmlEscapeAlloc(allocator, text);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    try aw.writer.writeAll("<p>");
    for (escaped) |c| {
        if (c == '\n') {
            try aw.writer.writeAll("<br>");
        } else {
            try aw.writer.writeByte(c);
        }
    }
    try aw.writer.writeAll("</p>");

    const out = try aw.toOwnedSlice();
    aw.deinit();
    return out;
}

pub fn safeHtmlFromRemoteHtmlAlloc(allocator: std.mem.Allocator, remote_html: []const u8) ![]u8 {
    const text = try remoteHtmlToTextAlloc(allocator, remote_html);
    return textToHtmlWithBreaksAlloc(allocator, text);
}

pub fn remoteHtmlToTextAlloc(allocator: std.mem.Allocator, html: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    var i: usize = 0;
    while (i < html.len) {
        const c = html[i];

        if (c == '<') {
            const end = std.mem.indexOfScalarPos(u8, html, i, '>') orelse {
                try aw.writer.writeByte('<');
                i += 1;
                continue;
            };

            const inside_raw = html[i + 1 .. end];
            const inside = std.mem.trim(u8, inside_raw, " \t\r\n");
            if (inside.len == 0) {
                i = end + 1;
                continue;
            }

            if (inside[0] == '!' or inside[0] == '?') {
                i = end + 1;
                continue;
            }

            var is_end: bool = false;
            var tag = inside;
            if (tag[0] == '/') {
                is_end = true;
                tag = std.mem.trimLeft(u8, tag[1..], " \t\r\n");
            }

            var name_end: usize = 0;
            while (name_end < tag.len and tag[name_end] != ' ' and tag[name_end] != '\t' and tag[name_end] != '/' and tag[name_end] != '\r' and tag[name_end] != '\n') : (name_end += 1) {}
            const name = tag[0..name_end];

            if (std.ascii.eqlIgnoreCase(name, "br")) {
                try aw.writer.writeByte('\n');
            } else if (is_end and (std.ascii.eqlIgnoreCase(name, "p") or std.ascii.eqlIgnoreCase(name, "div") or std.ascii.eqlIgnoreCase(name, "li") or std.ascii.eqlIgnoreCase(name, "blockquote"))) {
                try aw.writer.writeByte('\n');
            }

            i = end + 1;
            continue;
        }

        if (c == '&') {
            if (try tryDecodeEntity(html, i, &aw.writer)) |consumed| {
                i += consumed;
                continue;
            }
        }

        try aw.writer.writeByte(c);
        i += 1;
    }

    const out = try aw.toOwnedSlice();
    aw.deinit();

    const trimmed = std.mem.trim(u8, out, " \t\r\n");
    if (trimmed.len == out.len) return out;
    const out2 = try allocator.dupe(u8, trimmed);
    allocator.free(out);
    return out2;
}

fn tryDecodeEntity(html: []const u8, start: usize, writer: *std.Io.Writer) std.Io.Writer.Error!?usize {
    // start points at '&'
    const semi = std.mem.indexOfScalarPos(u8, html, start, ';') orelse return null;
    if (semi <= start + 1) return null;
    if (semi - start > 32) return null;

    const body = html[start + 1 .. semi];

    if (std.ascii.eqlIgnoreCase(body, "amp")) {
        try writer.writeByte('&');
        return semi - start + 1;
    }
    if (std.ascii.eqlIgnoreCase(body, "lt")) {
        try writer.writeByte('<');
        return semi - start + 1;
    }
    if (std.ascii.eqlIgnoreCase(body, "gt")) {
        try writer.writeByte('>');
        return semi - start + 1;
    }
    if (std.ascii.eqlIgnoreCase(body, "quot")) {
        try writer.writeByte('"');
        return semi - start + 1;
    }
    if (std.ascii.eqlIgnoreCase(body, "apos") or std.ascii.eqlIgnoreCase(body, "#39")) {
        try writer.writeByte('\'');
        return semi - start + 1;
    }
    if (std.ascii.eqlIgnoreCase(body, "nbsp")) {
        try writer.writeByte(' ');
        return semi - start + 1;
    }

    if (body.len >= 2 and body[0] == '#') {
        const codepoint: u21 = blk: {
            if (body.len >= 3 and (body[1] == 'x' or body[1] == 'X')) {
                const raw = body[2..];
                const cp = std.fmt.parseInt(u21, raw, 16) catch break :blk 0;
                break :blk cp;
            }
            const raw = body[1..];
            const cp = std.fmt.parseInt(u21, raw, 10) catch break :blk 0;
            break :blk cp;
        };

        if (codepoint == 0 or codepoint > 0x10FFFF) return null;

        var buf: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &buf) catch return null;
        try writer.writeAll(buf[0..len]);
        return semi - start + 1;
    }

    return null;
}

test "htmlEscapeAlloc" {
    const allocator = std.testing.allocator;

    const got = try htmlEscapeAlloc(allocator, "a&b<c>d\"e'f");
    defer allocator.free(got);

    try std.testing.expectEqualStrings("a&amp;b&lt;c&gt;d&quot;e&#39;f", got);
}

test "remoteHtmlToTextAlloc strips tags and decodes entities" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const t1 = try remoteHtmlToTextAlloc(a, "<p>Hello</p>");
    try std.testing.expectEqualStrings("Hello", t1);

    const t2 = try remoteHtmlToTextAlloc(a, "<p>Hello<br>world</p>");
    try std.testing.expectEqualStrings("Hello\nworld", t2);

    const t3 = try remoteHtmlToTextAlloc(a, "a&amp;b &lt;c&gt;");
    try std.testing.expectEqualStrings("a&b <c>", t3);
}

test "safeHtmlFromRemoteHtmlAlloc returns safe HTML" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const got = try safeHtmlFromRemoteHtmlAlloc(a, "<p>Hello</p><script>alert(1)</script>&amp;");
    try std.testing.expectEqualStrings("<p>Hello<br>alert(1)&amp;</p>", got);
}

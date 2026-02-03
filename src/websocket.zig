const std = @import("std");

pub const Error = error{
    InvalidFrame,
    FrameTooLarge,
};

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []u8,
    masked: bool,
};

pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

pub fn computeAcceptKey(sec_websocket_key: []const u8) [28]u8 {
    const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    var h = std.crypto.hash.Sha1.init(.{});
    h.update(sec_websocket_key);
    h.update(guid);

    var digest: [20]u8 = undefined;
    h.final(&digest);

    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

pub fn writeText(writer: anytype, payload: []const u8) !void {
    try writeFrame(writer, .text, payload);
}

pub fn writePong(writer: anytype, payload: []const u8) !void {
    try writeFrame(writer, .pong, payload);
}

pub fn writeClose(writer: anytype, payload: []const u8) !void {
    try writeFrame(writer, .close, payload);
}

fn writeFrame(writer: anytype, opcode: Opcode, payload: []const u8) !void {
    const fin_opcode: u8 = 0x80 | @as(u8, @intFromEnum(opcode));
    try writer.writeByte(fin_opcode);

    if (payload.len < 126) {
        try writer.writeByte(@intCast(payload.len));
    } else if (payload.len <= std.math.maxInt(u16)) {
        try writer.writeByte(126);
        var len_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_be, @intCast(payload.len), .big);
        try writer.writeAll(&len_be);
    } else {
        try writer.writeByte(127);
        var len_be: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_be, @intCast(payload.len), .big);
        try writer.writeAll(&len_be);
    }

    try writer.writeAll(payload);
}

pub fn tryParseFrame(buf: []u8) Error!?ParseResult {
    if (buf.len < 2) return null;

    const b0 = buf[0];
    const b1 = buf[1];

    const fin = (b0 & 0x80) != 0;
    const opcode_raw: u4 = @truncate(b0 & 0x0F);
    const opcode: Opcode = std.meta.intToEnum(Opcode, opcode_raw) catch return error.InvalidFrame;

    const masked = (b1 & 0x80) != 0;
    const len7: u7 = @truncate(b1 & 0x7F);

    var pos: usize = 2;
    var payload_len: usize = 0;

    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (buf.len < pos + 2) return null;
        const p: *const [2]u8 = @ptrCast(buf[pos .. pos + 2].ptr);
        payload_len = std.mem.readInt(u16, p, .big);
        pos += 2;
    } else {
        if (buf.len < pos + 8) return null;
        const p: *const [8]u8 = @ptrCast(buf[pos .. pos + 8].ptr);
        const len64 = std.mem.readInt(u64, p, .big);
        pos += 8;
        if (len64 > @as(u64, std.math.maxInt(usize))) return error.FrameTooLarge;
        payload_len = @intCast(len64);
    }

    if (payload_len > 1024 * 1024) return error.FrameTooLarge;

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (buf.len < pos + 4) return null;
        @memcpy(&mask_key, buf[pos .. pos + 4]);
        pos += 4;
    }

    if (buf.len < pos + payload_len) return null;
    const payload = buf[pos .. pos + payload_len];

    if (masked) {
        for (payload, 0..) |*b, i| {
            b.* ^= mask_key[i % 4];
        }
    }

    return .{
        .frame = .{
            .fin = fin,
            .opcode = opcode,
            .payload = payload,
            .masked = masked,
        },
        .consumed = pos + payload_len,
    };
}

test "computeAcceptKey matches RFC 6455 example" {
    const got = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &got);
}

test "writeText writes unmasked server text frames" {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    const w = out.writer(std.testing.allocator);
    try writeText(w, "hi");

    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0x02, 'h', 'i' }, out.items);
}

test "tryParseFrame decodes masked client text frames" {
    // Client frames are masked. Payload is "hi" with mask key 01 02 03 04.
    var buf: [2 + 4 + 2]u8 = .{
        0x81, // fin + text
        0x80 | 0x02, // masked + len 2
        0x01,
        0x02,
        0x03,
        0x04,
        'h' ^ 0x01,
        'i' ^ 0x02,
    };

    const res = (try tryParseFrame(&buf)).?;
    try std.testing.expect(res.frame.fin);
    try std.testing.expectEqual(Opcode.text, res.frame.opcode);
    try std.testing.expectEqualSlices(u8, "hi", res.frame.payload);
    try std.testing.expectEqual(@as(usize, buf.len), res.consumed);
}

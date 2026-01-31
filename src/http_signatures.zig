const std = @import("std");

const crypto_rsa = @import("crypto_rsa.zig");

pub const Error = crypto_rsa.Error;

pub const SignedHeaders = struct {
    date: []const u8,
    digest: []const u8,
    signature: []const u8,
};

pub fn digestHeaderValueAlloc(allocator: std.mem.Allocator, body: []const u8) Error![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});

    const b64_len = std.base64.standard.Encoder.calcSize(digest.len);
    var out = try allocator.alloc(u8, "SHA-256=".len + b64_len);
    errdefer allocator.free(out);

    @memcpy(out[0.."SHA-256=".len], "SHA-256=");
    _ = std.base64.standard.Encoder.encode(out["SHA-256=".len..], &digest);
    return out;
}

pub fn httpDateAlloc(allocator: std.mem.Allocator, timestamp_sec: i64) std.mem.Allocator.Error![]u8 {
    const ts: u64 = if (timestamp_sec < 0) 0 else @intCast(timestamp_sec);

    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = ts };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const weekday = weekdayAbbrev((@as(u64, epoch_day.day) + 4) % 7);
    const day: u8 = @intCast(month_day.day_index + 1);
    const month = monthAbbrev(month_day.month);
    const year = year_day.year;
    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    return std.fmt.allocPrint(
        allocator,
        "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT",
        .{ weekday, day, month, year, hour, minute, second },
    );
}

fn weekdayAbbrev(idx: u64) []const u8 {
    return switch (idx) {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        else => "Sun",
    };
}

fn monthAbbrev(m: std.time.epoch.Month) []const u8 {
    return switch (m) {
        .jan => "Jan",
        .feb => "Feb",
        .mar => "Mar",
        .apr => "Apr",
        .may => "May",
        .jun => "Jun",
        .jul => "Jul",
        .aug => "Aug",
        .sep => "Sep",
        .oct => "Oct",
        .nov => "Nov",
        .dec => "Dec",
    };
}

pub fn signingStringAlloc(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    host: []const u8,
    date: []const u8,
    digest: []const u8,
) std.mem.Allocator.Error![]u8 {
    var method_buf: [16]u8 = undefined;
    const method_upper = @tagName(method);
    const method_lower = std.ascii.lowerString(method_buf[0..method_upper.len], method_upper);

    return std.fmt.allocPrint(
        allocator,
        "(request-target): {s} {s}\nhost: {s}\ndate: {s}\ndigest: {s}",
        .{ method_lower, target, host, date, digest },
    );
}

fn base64EncodeAlloc(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error![]u8 {
    const b64_len = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, b64_len);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

fn base64DecodeAlloc(allocator: std.mem.Allocator, b64: []const u8) ![]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.InvalidEncoding;
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    std.base64.standard.Decoder.decode(out, b64) catch return error.InvalidEncoding;
    return out;
}

pub fn signRequest(
    allocator: std.mem.Allocator,
    private_key_pem: []const u8,
    key_id: []const u8,
    method: std.http.Method,
    target: []const u8,
    host: []const u8,
    body: []const u8,
    now_sec: i64,
) Error!SignedHeaders {
    const date = try httpDateAlloc(allocator, now_sec);
    const digest = try digestHeaderValueAlloc(allocator, body);
    const signing_string = try signingStringAlloc(allocator, method, target, host, date, digest);

    const sig_bytes = try crypto_rsa.signRsaSha256Pem(allocator, private_key_pem, signing_string);
    const sig_b64 = try base64EncodeAlloc(allocator, sig_bytes);

    const signature = std.fmt.allocPrint(
        allocator,
        "keyId=\"{s}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{s}\"",
        .{ key_id, sig_b64 },
    ) catch return error.OutOfMemory;

    return .{
        .date = date,
        .digest = digest,
        .signature = signature,
    };
}

test "signRequest builds verifiable signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try crypto_rsa.generateRsaKeyPairPem(a, 512);

    const body = "{\"hello\":\"world\"}";
    const date = try httpDateAlloc(a, 0);
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", date);

    const digest = try digestHeaderValueAlloc(a, body);
    try std.testing.expect(std.mem.startsWith(u8, digest, "SHA-256="));

    const key_id = "http://example.test/users/alice#main-key";
    const signed = try signRequest(
        a,
        kp.private_key_pem,
        key_id,
        .POST,
        "/inbox",
        "example.test",
        body,
        0,
    );

    // Reconstruct signing string and verify the signature.
    const signing_string = try signingStringAlloc(a, .POST, "/inbox", "example.test", signed.date, signed.digest);

    const sig_prefix = "signature=\"";
    const sig_b64 = std.mem.indexOf(u8, signed.signature, sig_prefix) orelse return error.TestUnexpectedResult;
    const sig_b64_start = sig_b64 + sig_prefix.len;
    const sig_b64_end = std.mem.indexOfPos(u8, signed.signature, sig_b64_start, "\"") orelse
        return error.TestUnexpectedResult;
    const sig_bytes = try base64DecodeAlloc(a, signed.signature[sig_b64_start..sig_b64_end]);

    try std.testing.expect(try crypto_rsa.verifyRsaSha256Pem(kp.public_key_pem, signing_string, sig_bytes));
}

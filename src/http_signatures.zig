const std = @import("std");

const crypto_rsa = @import("crypto_rsa.zig");

pub const Error = crypto_rsa.Error;

pub const VerifyError = crypto_rsa.Error || std.Io.Writer.Error || error{
    InvalidEncoding,
    InvalidSignatureHeader,
    UnsupportedSignedHeaders,
};

pub const SignedHeaders = struct {
    date: []const u8,
    digest: []const u8,
    signature: []const u8,
};

pub const ParsedSignature = struct {
    key_id: []const u8,
    algorithm: ?[]const u8 = null,
    headers: ?[]const u8 = null,
    signature_b64: []const u8,
};

pub fn parseSignatureHeader(value: []const u8) ?ParsedSignature {
    var key_id: ?[]const u8 = null;
    var algorithm: ?[]const u8 = null;
    var headers: ?[]const u8 = null;
    var signature_b64: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        if (part.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const k = std.mem.trim(u8, part[0..eq], " \t");
        var v = std.mem.trim(u8, part[eq + 1 ..], " \t");
        if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') {
            v = v[1 .. v.len - 1];
        }

        if (std.ascii.eqlIgnoreCase(k, "keyId")) key_id = v;
        if (std.ascii.eqlIgnoreCase(k, "algorithm")) algorithm = v;
        if (std.ascii.eqlIgnoreCase(k, "headers")) headers = v;
        if (std.ascii.eqlIgnoreCase(k, "signature")) signature_b64 = v;
    }

    const kid = key_id orelse return null;
    const sig = signature_b64 orelse return null;
    if (kid.len == 0 or sig.len == 0) return null;

    return .{
        .key_id = kid,
        .algorithm = algorithm,
        .headers = headers,
        .signature_b64 = sig,
    };
}

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

pub const HttpDateParseError = error{InvalidHttpDate};

pub fn parseHttpDateToEpochSeconds(value: []const u8) HttpDateParseError!i64 {
    // IMF-fixdate: "Thu, 01 Jan 1970 00:00:00 GMT"
    // https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1
    if (value.len < "Thu, 01 Jan 1970 00:00:00 GMT".len) return error.InvalidHttpDate;

    const comma_idx = std.mem.indexOfScalar(u8, value, ',') orelse return error.InvalidHttpDate;
    if (comma_idx != 3) return error.InvalidHttpDate;
    if (value.len < comma_idx + 2) return error.InvalidHttpDate;
    if (value[comma_idx + 1] != ' ') return error.InvalidHttpDate;

    var rest = value[comma_idx + 2 ..];
    if (!std.mem.endsWith(u8, rest, " GMT")) return error.InvalidHttpDate;
    rest = rest[0 .. rest.len - " GMT".len];

    var it = std.mem.splitScalar(u8, rest, ' ');
    const day_str = it.next() orelse return error.InvalidHttpDate;
    const mon_str = it.next() orelse return error.InvalidHttpDate;
    const year_str = it.next() orelse return error.InvalidHttpDate;
    const time_str = it.next() orelse return error.InvalidHttpDate;
    if (it.next() != null) return error.InvalidHttpDate;

    if (day_str.len != 2) return error.InvalidHttpDate;
    if (year_str.len != 4) return error.InvalidHttpDate;

    const day: u8 = std.fmt.parseInt(u8, day_str, 10) catch return error.InvalidHttpDate;
    if (day == 0 or day > 31) return error.InvalidHttpDate;

    const year: i32 = std.fmt.parseInt(i32, year_str, 10) catch return error.InvalidHttpDate;
    if (year < 0) return error.InvalidHttpDate;

    const month: u8 = monthFromAbbrev(mon_str) orelse return error.InvalidHttpDate;

    if (time_str.len != 8) return error.InvalidHttpDate;
    if (time_str[2] != ':' or time_str[5] != ':') return error.InvalidHttpDate;

    const hour: u8 = std.fmt.parseInt(u8, time_str[0..2], 10) catch return error.InvalidHttpDate;
    const minute: u8 = std.fmt.parseInt(u8, time_str[3..5], 10) catch return error.InvalidHttpDate;
    const second: u8 = std.fmt.parseInt(u8, time_str[6..8], 10) catch return error.InvalidHttpDate;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidHttpDate;

    const days = daysFromCivil(year, month, day);
    return days * 86_400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

pub fn httpDateWithinSkew(date_value: []const u8, now_sec: i64, max_skew_sec: i64) bool {
    if (max_skew_sec < 0) return false;
    const ts = parseHttpDateToEpochSeconds(date_value) catch return false;
    const delta = if (now_sec >= ts) now_sec - ts else ts - now_sec;
    return delta <= max_skew_sec;
}

fn monthFromAbbrev(s: []const u8) ?u8 {
    if (s.len != 3) return null;
    if (std.ascii.eqlIgnoreCase(s, "jan")) return 1;
    if (std.ascii.eqlIgnoreCase(s, "feb")) return 2;
    if (std.ascii.eqlIgnoreCase(s, "mar")) return 3;
    if (std.ascii.eqlIgnoreCase(s, "apr")) return 4;
    if (std.ascii.eqlIgnoreCase(s, "may")) return 5;
    if (std.ascii.eqlIgnoreCase(s, "jun")) return 6;
    if (std.ascii.eqlIgnoreCase(s, "jul")) return 7;
    if (std.ascii.eqlIgnoreCase(s, "aug")) return 8;
    if (std.ascii.eqlIgnoreCase(s, "sep")) return 9;
    if (std.ascii.eqlIgnoreCase(s, "oct")) return 10;
    if (std.ascii.eqlIgnoreCase(s, "nov")) return 11;
    if (std.ascii.eqlIgnoreCase(s, "dec")) return 12;
    return null;
}

fn daysFromCivil(year_in: i32, month_in: u8, day_in: u8) i64 {
    // Based on Howard Hinnant's civil calendar algorithms.
    // Returns days since 1970-01-01.
    var year: i64 = year_in;
    const month: i64 = month_in;
    const day: i64 = day_in;

    year -= if (month <= 2) 1 else 0;
    const era: i64 = @divFloor(year, 400);
    const yoe: i64 = year - era * 400; // [0, 399]
    const mp: i64 = if (month > 2) month - 3 else month + 9; // [0, 11]
    const doy: i64 = @divFloor(153 * mp + 2, 5) + day - 1; // [0, 365]
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
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

fn base64DecodeAlloc(allocator: std.mem.Allocator, b64: []const u8) VerifyError![]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.InvalidEncoding;
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    std.base64.standard.Decoder.decode(out, b64) catch return error.InvalidEncoding;
    return out;
}

pub fn digestHeaderHasSha256(body: []const u8, digest_header_value: []const u8) bool {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});

    const b64_len = comptime std.base64.standard.Encoder.calcSize(digest.len);
    var b64_buf: [b64_len]u8 = undefined;
    const expected_b64 = std.base64.standard.Encoder.encode(b64_buf[0..], &digest);

    var it = std.mem.splitScalar(u8, digest_header_value, ',');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        if (part.len < "SHA-256=".len) continue;
        if (!std.ascii.eqlIgnoreCase(part[0.."SHA-256=".len], "SHA-256=")) continue;

        const got_b64 = std.mem.trim(u8, part["SHA-256=".len..], " \t");
        if (std.mem.eql(u8, got_b64, expected_b64)) return true;
    }

    return false;
}

fn signingStringFromHeadersAlloc(
    allocator: std.mem.Allocator,
    headers: []const u8,
    method: std.http.Method,
    target: []const u8,
    host: []const u8,
    date: []const u8,
    digest: []const u8,
    content_type: ?[]const u8,
    content_length: ?[]const u8,
) VerifyError![]u8 {
    var method_buf: [16]u8 = undefined;
    const method_upper = @tagName(method);
    const method_lower = std.ascii.lowerString(method_buf[0..method_upper.len], method_upper);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    var first: bool = true;
    var it = std.mem.tokenizeAny(u8, headers, " \t");
    while (it.next()) |h| {
        if (first) {
            first = false;
        } else {
            try aw.writer.writeByte('\n');
        }

        if (std.ascii.eqlIgnoreCase(h, "(request-target)")) {
            try aw.writer.print("(request-target): {s} {s}", .{ method_lower, target });
        } else if (std.ascii.eqlIgnoreCase(h, "host")) {
            try aw.writer.print("host: {s}", .{host});
        } else if (std.ascii.eqlIgnoreCase(h, "date")) {
            try aw.writer.print("date: {s}", .{date});
        } else if (std.ascii.eqlIgnoreCase(h, "digest")) {
            try aw.writer.print("digest: {s}", .{digest});
        } else if (std.ascii.eqlIgnoreCase(h, "content-type")) {
            const ct = content_type orelse return error.InvalidSignatureHeader;
            try aw.writer.print("content-type: {s}", .{ct});
        } else if (std.ascii.eqlIgnoreCase(h, "content-length")) {
            const cl = content_length orelse return error.InvalidSignatureHeader;
            try aw.writer.print("content-length: {s}", .{cl});
        } else {
            return error.UnsupportedSignedHeaders;
        }
    }

    if (first) return error.InvalidSignatureHeader;

    const out = try aw.toOwnedSlice();
    aw.deinit();
    return out;
}

pub fn verifyRequestSignaturePem(
    allocator: std.mem.Allocator,
    public_key_pem: []const u8,
    signature_header_value: []const u8,
    method: std.http.Method,
    target: []const u8,
    host: []const u8,
    date: []const u8,
    digest: []const u8,
    content_type: ?[]const u8,
    content_length: ?[]const u8,
) VerifyError!bool {
    const parsed = parseSignatureHeader(signature_header_value) orelse return error.InvalidSignatureHeader;

    if (parsed.algorithm) |alg| {
        // Some implementations send `hs2019` here but still use RSA-SHA256.
        if (!std.ascii.eqlIgnoreCase(alg, "rsa-sha256") and !std.ascii.eqlIgnoreCase(alg, "hs2019")) return false;
    }

    const headers = parsed.headers orelse return error.InvalidSignatureHeader;
    const signing_string = try signingStringFromHeadersAlloc(
        allocator,
        headers,
        method,
        target,
        host,
        date,
        digest,
        content_type,
        content_length,
    );
    defer allocator.free(signing_string);

    const sig_bytes = try base64DecodeAlloc(allocator, parsed.signature_b64);
    defer allocator.free(sig_bytes);

    return try crypto_rsa.verifyRsaSha256Pem(public_key_pem, signing_string, sig_bytes);
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

    try std.testing.expect(digestHeaderHasSha256(body, signed.digest));
    try std.testing.expect(try verifyRequestSignaturePem(
        a,
        kp.public_key_pem,
        signed.signature,
        .POST,
        "/inbox",
        "example.test",
        signed.date,
        signed.digest,
        null,
        null,
    ));
}

test "verifyRequestSignaturePem returns false on wrong digest value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try crypto_rsa.generateRsaKeyPairPem(a, 512);

    const body = "{\"hello\":\"world\"}";
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

    try std.testing.expect(!digestHeaderHasSha256("tampered", signed.digest));
    try std.testing.expect(!(try verifyRequestSignaturePem(
        a,
        kp.public_key_pem,
        signed.signature,
        .POST,
        "/inbox",
        "example.test",
        signed.date,
        "SHA-256=totally-wrong",
        null,
        null,
    )));
}

test "parseHttpDateToEpochSeconds parses IMF-fixdate" {
    try std.testing.expectEqual(@as(i64, 0), try parseHttpDateToEpochSeconds("Thu, 01 Jan 1970 00:00:00 GMT"));
    try std.testing.expectEqual(@as(i64, 1), try parseHttpDateToEpochSeconds("Thu, 01 Jan 1970 00:00:01 GMT"));
    try std.testing.expectEqual(@as(i64, 86_400), try parseHttpDateToEpochSeconds("Fri, 02 Jan 1970 00:00:00 GMT"));

    try std.testing.expectError(error.InvalidHttpDate, parseHttpDateToEpochSeconds("Thu, 01 Jan 1970 00:00:00"));
    try std.testing.expectError(error.InvalidHttpDate, parseHttpDateToEpochSeconds("Thu, 01 Xxx 1970 00:00:00 GMT"));
    try std.testing.expectError(error.InvalidHttpDate, parseHttpDateToEpochSeconds("Thu, 00 Jan 1970 00:00:00 GMT"));
    try std.testing.expectError(error.InvalidHttpDate, parseHttpDateToEpochSeconds("Thu, 01 Jan -001 00:00:00 GMT"));
    try std.testing.expectError(error.InvalidHttpDate, parseHttpDateToEpochSeconds("Thu, 01 Jan 1970 24:00:00 GMT"));
}

test "httpDateWithinSkew rejects invalid or too old Date headers" {
    try std.testing.expect(httpDateWithinSkew("Thu, 01 Jan 1970 00:00:00 GMT", 0, 0));
    try std.testing.expect(httpDateWithinSkew("Thu, 01 Jan 1970 00:00:00 GMT", 5, 5));
    try std.testing.expect(!httpDateWithinSkew("Thu, 01 Jan 1970 00:00:00 GMT", 6, 5));
    try std.testing.expect(!httpDateWithinSkew("not-a-date", 0, 60));
}

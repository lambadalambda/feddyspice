const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error || error{InvalidToken};

pub const CookieName = "feddyspice_session";

pub fn create(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64) Error![]u8 {
    var token_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&token_bytes);

    const hex = std.fmt.bytesToHex(token_bytes, .lower);
    const token = try allocator.dupe(u8, hex[0..]);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    var stmt = try conn.prepareZ(
        "INSERT INTO sessions(user_id, token_hash, created_at, expires_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 days'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindBlob(2, digest[0..]);

    switch (try stmt.step()) {
        .done => return token,
        .row => return error.Sqlite,
    }
}

pub fn lookupUserId(conn: *db.Db, token: []const u8) Error!?i64 {
    if (token.len == 0) return error.InvalidToken;

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    var stmt = try conn.prepareZ(
        "SELECT user_id FROM sessions WHERE token_hash = ?1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindBlob(1, digest[0..]);

    return switch (try stmt.step()) {
        .done => null,
        .row => stmt.columnInt64(0),
    };
}

pub fn parseCookie(cookie_header: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t");
        const value = part[eq + 1 ..];
        if (std.mem.eql(u8, name, CookieName)) return value;
    }
    return null;
}

test "parseCookie" {
    try std.testing.expectEqualStrings("abc", parseCookie("feddyspice_session=abc").?);
    try std.testing.expectEqualStrings("abc", parseCookie("x=y; feddyspice_session=abc; z=w").?);
    try std.testing.expect(parseCookie("x=y") == null);
}

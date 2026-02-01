const std = @import("std");
const builtin = @import("builtin");

const crypto_rsa = @import("crypto_rsa.zig");
const db = @import("db.zig");

pub const Error = db.Error || crypto_rsa.Error;

pub const KeyPair = struct {
    user_id: i64,
    private_key_pem: []const u8,
    public_key_pem: []const u8,
};

pub fn lookup(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64) Error!?KeyPair {
    var stmt = try conn.prepareZ(
        "SELECT user_id, private_key_pem, public_key_pem FROM actor_keys WHERE user_id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .user_id = stmt.columnInt64(0),
        .private_key_pem = try allocator.dupe(u8, stmt.columnText(1)),
        .public_key_pem = try allocator.dupe(u8, stmt.columnText(2)),
    };
}

pub fn ensureForUser(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64) Error!KeyPair {
    if (try lookup(conn, allocator, user_id)) |existing| return existing;

    const bits: u32 = if (builtin.is_test) 512 else 2048;
    const kp = try crypto_rsa.generateRsaKeyPairPem(allocator, bits);

    var stmt = try conn.prepareZ(
        "INSERT INTO actor_keys(user_id, private_key_pem, public_key_pem, created_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, kp.private_key_pem);
    try stmt.bindText(3, kp.public_key_pem);

    const step_result = stmt.step() catch |err| switch (err) {
        // Handle a common race: another request inserted keys after our initial lookup.
        error.Sqlite => return (try lookup(conn, allocator, user_id)) orelse error.Sqlite,
    };

    switch (step_result) {
        .done => {},
        .row => return error.Sqlite,
    }

    return .{
        .user_id = user_id,
        .private_key_pem = kp.private_key_pem,
        .public_key_pem = kp.public_key_pem,
    };
}

test "ensureForUser creates and persists keys" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const user_id = try @import("users.zig").create(&conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const k1 = try ensureForUser(&conn, a, user_id);
    try std.testing.expect(std.mem.indexOf(u8, k1.public_key_pem, "BEGIN PUBLIC KEY") != null);
    try std.testing.expect(std.mem.indexOf(u8, k1.private_key_pem, "BEGIN") != null);

    const k2 = (try lookup(&conn, a, user_id)).?;
    try std.testing.expectEqualStrings(k1.public_key_pem, k2.public_key_pem);
    try std.testing.expectEqualStrings(k1.private_key_pem, k2.private_key_pem);
}

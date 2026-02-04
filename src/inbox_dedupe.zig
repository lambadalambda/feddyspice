const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error;

pub fn fallbackKeyAlloc(allocator: std.mem.Allocator, actor_id: []const u8, body: []const u8) std.mem.Allocator.Error![]u8 {
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(actor_id);
    hasher.update(&.{0});
    hasher.update(body);
    hasher.final(&digest);

    const hex = std.fmt.bytesToHex(digest, .lower);

    var out = try allocator.alloc(u8, "sha256:".len + hex.len);
    @memcpy(out[0.."sha256:".len], "sha256:");
    @memcpy(out["sha256:".len..], hex[0..]);
    return out;
}

pub fn begin(conn: *db.Db, activity_id: []const u8, user_id: i64, actor_id: []const u8, received_at_ms: i64) Error!bool {
    var stmt = try conn.prepareZ(
        "INSERT INTO inbox_dedupe(activity_id, user_id, actor_id, received_at_ms)\n" ++
            "VALUES (?1, ?2, ?3, ?4)\n" ++
            "ON CONFLICT(activity_id) DO NOTHING;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, activity_id);
    try stmt.bindInt64(2, user_id);
    try stmt.bindText(3, actor_id);
    try stmt.bindInt64(4, received_at_ms);

    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn clear(conn: *db.Db, activity_id: []const u8) Error!void {
    var stmt = try conn.prepareZ("DELETE FROM inbox_dedupe WHERE activity_id=?1;\x00");
    defer stmt.finalize();
    try stmt.bindText(1, activity_id);
    _ = try stmt.step();
}

test "inbox_dedupe: begin is idempotent and clear re-allows" {
    const migrations = @import("migrations.zig");
    const password = @import("password.zig");

    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    var salt: [password.SaltLen]u8 = [_]u8{0} ** password.SaltLen;
    var hash: [password.HashLen]u8 = [_]u8{0} ** password.HashLen;

    var user_stmt = try conn.prepareZ(
        "INSERT INTO users(username, password_salt, password_hash, created_at)\n" ++
            "VALUES (?1, ?2, ?3, '2020-01-01T00:00:00.000Z');\x00",
    );
    defer user_stmt.finalize();
    try user_stmt.bindText(1, "alice");
    try user_stmt.bindBlob(2, salt[0..]);
    try user_stmt.bindBlob(3, hash[0..]);
    _ = try user_stmt.step();

    const user_id = conn.lastInsertRowId();
    const now_ms: i64 = 123;

    const activity_id = "https://remote.test/activities/1";
    const actor_id = "https://remote.test/users/bob";

    try std.testing.expect(try begin(&conn, activity_id, user_id, actor_id, now_ms));
    try std.testing.expect(!try begin(&conn, activity_id, user_id, actor_id, now_ms));

    try clear(&conn, activity_id);
    try std.testing.expect(try begin(&conn, activity_id, user_id, actor_id, now_ms));
}

test "inbox_dedupe: fallbackKeyAlloc is stable and actor-scoped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const k1 = try fallbackKeyAlloc(a, "https://remote.test/users/a", "body");
    const k2 = try fallbackKeyAlloc(a, "https://remote.test/users/a", "body");
    const k3 = try fallbackKeyAlloc(a, "https://remote.test/users/b", "body");
    const k4 = try fallbackKeyAlloc(a, "https://remote.test/users/a", "body2");

    try std.testing.expect(std.mem.startsWith(u8, k1, "sha256:"));
    try std.testing.expectEqualStrings(k1, k2);
    try std.testing.expect(!std.mem.eql(u8, k1, k3));
    try std.testing.expect(!std.mem.eql(u8, k1, k4));
}

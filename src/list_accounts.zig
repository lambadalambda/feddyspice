const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub fn add(conn: *db.Db, list_id: i64, remote_actor_id: []const u8) db.Error!void {
    var stmt = try conn.prepareZ(
        "INSERT INTO list_accounts(list_id, remote_actor_id, created_at)\n" ++
            "VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))\n" ++
            "ON CONFLICT(list_id, remote_actor_id) DO NOTHING;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, list_id);
    try stmt.bindText(2, remote_actor_id);
    _ = try stmt.step();
}

pub fn remove(conn: *db.Db, list_id: i64, remote_actor_id: []const u8) db.Error!void {
    var stmt = try conn.prepareZ("DELETE FROM list_accounts WHERE list_id = ?1 AND remote_actor_id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, list_id);
    try stmt.bindText(2, remote_actor_id);
    _ = try stmt.step();
}

pub fn listRemoteActorIds(conn: *db.Db, allocator: std.mem.Allocator, list_id: i64, limit: usize) Error![][]u8 {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT remote_actor_id FROM list_accounts WHERE list_id = ?1 ORDER BY rowid DESC LIMIT ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, list_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (out.items) |s| allocator.free(s);
        out.deinit(allocator);
    }

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, try allocator.dupe(u8, stmt.columnText(0))),
        }
    }

    return out.toOwnedSlice(allocator);
}

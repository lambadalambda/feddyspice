const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub fn add(conn: *db.Db, status_id: i64, remote_actor_id: []const u8) db.Error!void {
    var stmt = try conn.prepareZ(
        "INSERT INTO status_recipients(status_id, remote_actor_id, created_at)\n" ++
            "VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))\n" ++
            "ON CONFLICT(status_id, remote_actor_id) DO NOTHING;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
    try stmt.bindText(2, remote_actor_id);
    _ = try stmt.step();
}

pub fn listRemoteActorIds(conn: *db.Db, allocator: std.mem.Allocator, status_id: i64, limit: usize) Error![][]u8 {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT remote_actor_id FROM status_recipients WHERE status_id = ?1 ORDER BY rowid DESC LIMIT ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
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

test "status_recipients: add + listRemoteActorIds" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const user_id = try @import("users.zig").create(&conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const st = try @import("statuses.zig").create(&conn, a, user_id, "hello", "direct");

    try @import("remote_actors.zig").upsert(&conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    try add(&conn, st.id, "https://remote.test/users/bob");
    const ids = try listRemoteActorIds(&conn, a, st.id, 10);
    try std.testing.expectEqual(@as(usize, 1), ids.len);
    try std.testing.expectEqualStrings("https://remote.test/users/bob", ids[0]);
}

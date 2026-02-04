const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const Notification = struct {
    id: i64,
    user_id: i64,
    kind: []const u8,
    actor_id: []const u8,
    status_id: ?i64,
    created_at: []const u8,
};

pub fn create(
    conn: *db.Db,
    user_id: i64,
    kind: []const u8,
    actor_id: []const u8,
    status_id: ?i64,
) db.Error!i64 {
    var stmt = try conn.prepareZ(
        "INSERT INTO notifications(user_id, type, actor_id, status_id, created_at)\n" ++
            "VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, kind);
    try stmt.bindText(3, actor_id);
    if (status_id) |sid| {
        try stmt.bindInt64(4, sid);
    } else {
        try stmt.bindNull(4);
    }

    _ = try stmt.step();
    return conn.lastInsertRowId();
}

pub fn list(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    limit: usize,
    max_id: ?i64,
) Error![]Notification {
    const lim: i64 = @intCast(@min(limit, 200));
    const max: i64 = max_id orelse std.math.maxInt(i64);

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, type, actor_id, status_id, created_at\n" ++
            "FROM notifications\n" ++
            "WHERE user_id = ?1 AND id < ?2\n" ++
            "ORDER BY id DESC\n" ++
            "LIMIT ?3;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, max);
    try stmt.bindInt64(3, lim);

    var out: std.ArrayListUnmanaged(Notification) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, .{
                .id = stmt.columnInt64(0),
                .user_id = stmt.columnInt64(1),
                .kind = try allocator.dupe(u8, stmt.columnText(2)),
                .actor_id = try allocator.dupe(u8, stmt.columnText(3)),
                .status_id = if (stmt.columnType(4) == .null) null else stmt.columnInt64(4),
                .created_at = try allocator.dupe(u8, stmt.columnText(5)),
            }),
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn lookupById(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, notification_id: i64) Error!?Notification {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, type, actor_id, status_id, created_at FROM notifications WHERE user_id = ?1 AND id = ?2 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, notification_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .kind = try allocator.dupe(u8, stmt.columnText(2)),
        .actor_id = try allocator.dupe(u8, stmt.columnText(3)),
        .status_id = if (stmt.columnType(4) == .null) null else stmt.columnInt64(4),
        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
    };
}

pub fn count(conn: *db.Db, user_id: i64) db.Error!i64 {
    var stmt = try conn.prepareZ("SELECT COUNT(*) FROM notifications WHERE user_id = ?1;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);

    switch (try stmt.step()) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

pub fn dismiss(conn: *db.Db, user_id: i64, notification_id: i64) db.Error!bool {
    var stmt = try conn.prepareZ("DELETE FROM notifications WHERE user_id = ?1 AND id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, notification_id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn clear(conn: *db.Db, user_id: i64) db.Error!void {
    var stmt = try conn.prepareZ("DELETE FROM notifications WHERE user_id = ?1;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    _ = try stmt.step();
}

test "notifications: create/list/dismiss/clear" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const user_id = try @import("users.zig").create(&conn, std.testing.allocator, "alice", "password", params);

    try @import("remote_actors.zig").upsert(&conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const n1_id = try create(&conn, user_id, "follow", "https://remote.test/users/bob", null);
    try std.testing.expect(n1_id > 0);

    const n2_id = try create(&conn, user_id, "mention", "https://remote.test/users/bob", -123);
    try std.testing.expect(n2_id > n1_id);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const list1 = try list(&conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 2), list1.len);
    try std.testing.expectEqualStrings("mention", list1[0].kind);
    try std.testing.expectEqual(@as(?i64, -123), list1[0].status_id);
    try std.testing.expectEqualStrings("follow", list1[1].kind);
    try std.testing.expectEqual(@as(?i64, null), list1[1].status_id);

    const count1 = try count(&conn, user_id);
    try std.testing.expectEqual(@as(i64, 2), count1);

    const got = (try lookupById(&conn, a, user_id, n2_id)).?;
    try std.testing.expectEqualStrings("mention", got.kind);

    try std.testing.expect(try dismiss(&conn, user_id, n2_id));

    const list2 = try list(&conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 1), list2.len);

    const count2 = try count(&conn, user_id);
    try std.testing.expectEqual(@as(i64, 1), count2);

    try clear(&conn, user_id);
    const list3 = try list(&conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 0), list3.len);

    const count3 = try count(&conn, user_id);
    try std.testing.expectEqual(@as(i64, 0), count3);
}

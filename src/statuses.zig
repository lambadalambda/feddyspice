const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error || error{
    InvalidText,
};

pub const Status = struct {
    id: i64,
    user_id: i64,
    text: []const u8,
    visibility: []const u8,
    created_at: []const u8,
};

pub fn create(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    text: []const u8,
    visibility: []const u8,
) Error!Status {
    if (text.len == 0) return error.InvalidText;

    var stmt = try conn.prepareZ(
        "INSERT INTO statuses(user_id, text, visibility, created_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, text);
    try stmt.bindText(3, visibility);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    const id = conn.lastInsertRowId();
    return (try lookup(conn, allocator, id)).?;
}

pub fn lookup(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?Status {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, text, visibility, created_at FROM statuses WHERE id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .text = try allocator.dupe(u8, stmt.columnText(2)),
        .visibility = try allocator.dupe(u8, stmt.columnText(3)),
        .created_at = try allocator.dupe(u8, stmt.columnText(4)),
    };
}

pub fn listByUser(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    limit: usize,
    max_id: ?i64,
) Error![]Status {
    const max = max_id orelse std.math.maxInt(i64);
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, text, visibility, created_at FROM statuses WHERE user_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, max);
    try stmt.bindInt64(3, lim);

    var out: std.ArrayListUnmanaged(Status) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                try out.append(allocator, .{
                    .id = stmt.columnInt64(0),
                    .user_id = stmt.columnInt64(1),
                    .text = try allocator.dupe(u8, stmt.columnText(2)),
                    .visibility = try allocator.dupe(u8, stmt.columnText(3)),
                    .created_at = try allocator.dupe(u8, stmt.columnText(4)),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

test "create + list + lookup" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const salt: @import("password.zig").Salt = .{0x01} ** @import("password.zig").SaltLen;

    const user_id = try @import("users.zig").createWithSalt(
        &conn,
        std.testing.allocator,
        "alice",
        "password",
        salt,
        params,
    );

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const s1 = try create(&conn, a, user_id, "hello", "public");
    const s2 = try create(&conn, a, user_id, "world", "public");

    try std.testing.expect(s2.id > s1.id);

    const got = (try lookup(&conn, a, s1.id)).?;
    try std.testing.expectEqualStrings("hello", got.text);

    const list = try listByUser(&conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqualStrings("world", list[0].text);
    try std.testing.expectEqualStrings("hello", list[1].text);
}

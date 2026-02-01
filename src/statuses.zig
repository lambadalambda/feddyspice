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
    deleted_at: ?[]const u8,
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
        "SELECT id, user_id, text, visibility, created_at, deleted_at FROM statuses WHERE id = ?1 AND deleted_at IS NULL LIMIT 1;\x00",
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
        .deleted_at = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
    };
}

pub fn lookupIncludingDeleted(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?Status {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, text, visibility, created_at, deleted_at FROM statuses WHERE id = ?1 LIMIT 1;\x00",
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
        .deleted_at = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
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
        "SELECT id, user_id, text, visibility, created_at, deleted_at FROM statuses WHERE user_id = ?1 AND id < ?2 AND deleted_at IS NULL ORDER BY id DESC LIMIT ?3;\x00",
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
                    .deleted_at = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn listByUserBeforeCreatedAt(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    limit: usize,
    before_created_at: ?[]const u8,
    before_id: ?i64,
) Error![]Status {
    const lim: i64 = @intCast(@min(limit, 200));

    var out: std.ArrayListUnmanaged(Status) = .empty;
    errdefer out.deinit(allocator);

    if (before_created_at == null) {
        var stmt = try conn.prepareZ(
            "SELECT id, user_id, text, visibility, created_at, deleted_at FROM statuses WHERE user_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC, id DESC LIMIT ?2;\x00",
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, user_id);
        try stmt.bindInt64(2, lim);

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
                        .deleted_at = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
                    });
                },
            }
        }

        return out.toOwnedSlice(allocator);
    }

    const anchor_id = before_id orelse std.math.maxInt(i64);

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, text, visibility, created_at, deleted_at FROM statuses WHERE user_id = ?1 AND deleted_at IS NULL AND (created_at < ?2 OR (created_at = ?2 AND id < ?3)) ORDER BY created_at DESC, id DESC LIMIT ?4;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, before_created_at.?);
    try stmt.bindInt64(3, anchor_id);
    try stmt.bindInt64(4, lim);

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
                    .deleted_at = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn markDeleted(conn: *db.Db, id: i64, user_id: i64) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE statuses SET deleted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND user_id = ?2 AND deleted_at IS NULL;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return conn.changes() > 0;
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

    try std.testing.expect(try markDeleted(&conn, s2.id, user_id));
    try std.testing.expect((try lookup(&conn, a, s2.id)) == null);
    try std.testing.expect((try lookupIncludingDeleted(&conn, a, s2.id)).?.deleted_at != null);

    const list2 = try listByUser(&conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 1), list2.len);
    try std.testing.expectEqualStrings("hello", list2[0].text);
}

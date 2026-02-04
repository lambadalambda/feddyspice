const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const List = struct {
    id: i64,
    user_id: i64,
    title: []const u8,
    replies_policy: []const u8,
    created_at: []const u8,
    updated_at: []const u8,
};

pub fn create(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    title: []const u8,
    replies_policy: []const u8,
) Error!List {
    var stmt = try conn.prepareZ(
        "INSERT INTO lists(user_id, title, replies_policy, created_at, updated_at)\n" ++
            "VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, title);
    try stmt.bindText(3, replies_policy);
    _ = try stmt.step();

    const id = conn.lastInsertRowId();
    return (try lookupByIdForUser(conn, allocator, id, user_id)).?;
}

pub fn lookupByIdForUser(conn: *db.Db, allocator: std.mem.Allocator, id: i64, user_id: i64) Error!?List {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, title, replies_policy, created_at, updated_at\n" ++
            "FROM lists\n" ++
            "WHERE id = ?1 AND user_id = ?2\n" ++
            "LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .title = try allocator.dupe(u8, stmt.columnText(2)),
        .replies_policy = try allocator.dupe(u8, stmt.columnText(3)),
        .created_at = try allocator.dupe(u8, stmt.columnText(4)),
        .updated_at = try allocator.dupe(u8, stmt.columnText(5)),
    };
}

pub fn listByUser(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, limit: usize) Error![]List {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, title, replies_policy, created_at, updated_at\n" ++
            "FROM lists\n" ++
            "WHERE user_id = ?1\n" ++
            "ORDER BY id DESC\n" ++
            "LIMIT ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged(List) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, .{
                .id = stmt.columnInt64(0),
                .user_id = stmt.columnInt64(1),
                .title = try allocator.dupe(u8, stmt.columnText(2)),
                .replies_policy = try allocator.dupe(u8, stmt.columnText(3)),
                .created_at = try allocator.dupe(u8, stmt.columnText(4)),
                .updated_at = try allocator.dupe(u8, stmt.columnText(5)),
            }),
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn update(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    id: i64,
    user_id: i64,
    title_opt: ?[]const u8,
    replies_policy_opt: ?[]const u8,
) Error!?List {
    const existing = try lookupByIdForUser(conn, allocator, id, user_id);
    if (existing == null) return null;

    const new_title = title_opt orelse existing.?.title;
    const new_policy = replies_policy_opt orelse existing.?.replies_policy;

    var stmt = try conn.prepareZ(
        "UPDATE lists\n" ++
            "SET title = ?3, replies_policy = ?4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')\n" ++
            "WHERE id = ?1 AND user_id = ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);
    try stmt.bindText(3, new_title);
    try stmt.bindText(4, new_policy);
    _ = try stmt.step();

    return (try lookupByIdForUser(conn, allocator, id, user_id)).?;
}

pub fn delete(conn: *db.Db, id: i64, user_id: i64) db.Error!bool {
    var stmt = try conn.prepareZ("DELETE FROM lists WHERE id = ?1 AND user_id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

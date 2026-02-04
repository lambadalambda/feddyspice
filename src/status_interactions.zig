const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const Interaction = struct {
    favourited: bool,
    reblogged: bool,
    bookmarked: bool,
    pinned: bool,
    muted: bool,
};

fn setField(
    conn: *db.Db,
    sql: [:0]const u8,
    user_id: i64,
    status_id: i64,
    value: bool,
    now_ms: i64,
) db.Error!void {
    var stmt = try conn.prepareZ(sql);
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, status_id);
    try stmt.bindInt64(3, if (value) 1 else 0);
    try stmt.bindInt64(4, now_ms);
    _ = try stmt.step();
}

const set_favourited_sql: [:0]const u8 =
    "INSERT INTO status_interactions(user_id, status_id, favourited, updated_at_ms)\n" ++
    "VALUES (?1, ?2, ?3, ?4)\n" ++
    "ON CONFLICT(user_id, status_id) DO UPDATE SET favourited=excluded.favourited, updated_at_ms=excluded.updated_at_ms;\x00";

const set_reblogged_sql: [:0]const u8 =
    "INSERT INTO status_interactions(user_id, status_id, reblogged, updated_at_ms)\n" ++
    "VALUES (?1, ?2, ?3, ?4)\n" ++
    "ON CONFLICT(user_id, status_id) DO UPDATE SET reblogged=excluded.reblogged, updated_at_ms=excluded.updated_at_ms;\x00";

const set_bookmarked_sql: [:0]const u8 =
    "INSERT INTO status_interactions(user_id, status_id, bookmarked, updated_at_ms)\n" ++
    "VALUES (?1, ?2, ?3, ?4)\n" ++
    "ON CONFLICT(user_id, status_id) DO UPDATE SET bookmarked=excluded.bookmarked, updated_at_ms=excluded.updated_at_ms;\x00";

const set_pinned_sql: [:0]const u8 =
    "INSERT INTO status_interactions(user_id, status_id, pinned, updated_at_ms)\n" ++
    "VALUES (?1, ?2, ?3, ?4)\n" ++
    "ON CONFLICT(user_id, status_id) DO UPDATE SET pinned=excluded.pinned, updated_at_ms=excluded.updated_at_ms;\x00";

const set_muted_sql: [:0]const u8 =
    "INSERT INTO status_interactions(user_id, status_id, muted, updated_at_ms)\n" ++
    "VALUES (?1, ?2, ?3, ?4)\n" ++
    "ON CONFLICT(user_id, status_id) DO UPDATE SET muted=excluded.muted, updated_at_ms=excluded.updated_at_ms;\x00";

pub fn setFavourited(conn: *db.Db, user_id: i64, status_id: i64, value: bool, now_ms: i64) db.Error!void {
    return setField(conn, set_favourited_sql, user_id, status_id, value, now_ms);
}

pub fn setReblogged(conn: *db.Db, user_id: i64, status_id: i64, value: bool, now_ms: i64) db.Error!void {
    return setField(conn, set_reblogged_sql, user_id, status_id, value, now_ms);
}

pub fn setBookmarked(conn: *db.Db, user_id: i64, status_id: i64, value: bool, now_ms: i64) db.Error!void {
    return setField(conn, set_bookmarked_sql, user_id, status_id, value, now_ms);
}

pub fn setPinned(conn: *db.Db, user_id: i64, status_id: i64, value: bool, now_ms: i64) db.Error!void {
    return setField(conn, set_pinned_sql, user_id, status_id, value, now_ms);
}

pub fn setMuted(conn: *db.Db, user_id: i64, status_id: i64, value: bool, now_ms: i64) db.Error!void {
    return setField(conn, set_muted_sql, user_id, status_id, value, now_ms);
}

pub fn lookup(conn: *db.Db, user_id: i64, status_id: i64) db.Error!?Interaction {
    var stmt = try conn.prepareZ(
        "SELECT favourited, reblogged, bookmarked, pinned, muted\n" ++
            "FROM status_interactions\n" ++
            "WHERE user_id = ?1 AND status_id = ?2\n" ++
            "LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, status_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .favourited = stmt.columnInt64(0) != 0,
        .reblogged = stmt.columnInt64(1) != 0,
        .bookmarked = stmt.columnInt64(2) != 0,
        .pinned = stmt.columnInt64(3) != 0,
        .muted = stmt.columnInt64(4) != 0,
    };
}

pub fn listPinnedStatusIds(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, limit: usize) Error![]i64 {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT status_id FROM status_interactions\n" ++
            "WHERE user_id = ?1 AND pinned = 1\n" ++
            "ORDER BY updated_at_ms DESC, status_id DESC\n" ++
            "LIMIT ?2;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged(i64) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, stmt.columnInt64(0)),
        }
    }

    return out.toOwnedSlice(allocator);
}

const count_favourited_sql: [:0]const u8 =
    "SELECT COUNT(*) FROM status_interactions WHERE status_id = ?1 AND favourited = 1;\x00";

pub fn countFavourited(conn: *db.Db, status_id: i64) db.Error!i64 {
    var stmt = try conn.prepareZ(count_favourited_sql);
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
    switch (try stmt.step()) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

const count_reblogged_sql: [:0]const u8 =
    "SELECT COUNT(*) FROM status_interactions WHERE status_id = ?1 AND reblogged = 1;\x00";

pub fn countReblogged(conn: *db.Db, status_id: i64) db.Error!i64 {
    var stmt = try conn.prepareZ(count_reblogged_sql);
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
    switch (try stmt.step()) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

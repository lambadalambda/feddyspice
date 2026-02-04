const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const Filter = struct {
    id: i64,
    user_id: i64,
    phrase: []const u8,
    context: []const u8,
    irreversible: bool,
    whole_word: bool,
    expires_at: ?[]const u8,
    created_at: []const u8,
    updated_at: []const u8,
};

pub fn create(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    phrase: []const u8,
    context: []const u8,
    irreversible: bool,
    whole_word: bool,
    expires_at: ?[]const u8,
) Error!Filter {
    var stmt = try conn.prepareZ(
        "INSERT INTO filters(user_id, phrase, context, irreversible, whole_word, expires_at, created_at, updated_at)\n" ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, phrase);
    try stmt.bindText(3, context);
    try stmt.bindInt64(4, if (irreversible) 1 else 0);
    try stmt.bindInt64(5, if (whole_word) 1 else 0);
    if (expires_at) |ts| {
        try stmt.bindText(6, ts);
    } else {
        try stmt.bindNull(6);
    }
    _ = try stmt.step();

    const id = conn.lastInsertRowId();
    return (try lookupByIdForUser(conn, allocator, id, user_id)).?;
}

pub fn lookupByIdForUser(conn: *db.Db, allocator: std.mem.Allocator, id: i64, user_id: i64) Error!?Filter {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, phrase, context, irreversible, whole_word, expires_at, created_at, updated_at\n" ++
            "FROM filters\n" ++
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
        .phrase = try allocator.dupe(u8, stmt.columnText(2)),
        .context = try allocator.dupe(u8, stmt.columnText(3)),
        .irreversible = stmt.columnInt64(4) != 0,
        .whole_word = stmt.columnInt64(5) != 0,
        .expires_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
        .created_at = try allocator.dupe(u8, stmt.columnText(7)),
        .updated_at = try allocator.dupe(u8, stmt.columnText(8)),
    };
}

pub fn listByUser(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, limit: usize) Error![]Filter {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, phrase, context, irreversible, whole_word, expires_at, created_at, updated_at\n" ++
            "FROM filters\n" ++
            "WHERE user_id = ?1\n" ++
            "ORDER BY id DESC\n" ++
            "LIMIT ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged(Filter) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, .{
                .id = stmt.columnInt64(0),
                .user_id = stmt.columnInt64(1),
                .phrase = try allocator.dupe(u8, stmt.columnText(2)),
                .context = try allocator.dupe(u8, stmt.columnText(3)),
                .irreversible = stmt.columnInt64(4) != 0,
                .whole_word = stmt.columnInt64(5) != 0,
                .expires_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
                .created_at = try allocator.dupe(u8, stmt.columnText(7)),
                .updated_at = try allocator.dupe(u8, stmt.columnText(8)),
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
    phrase_opt: ?[]const u8,
    context_opt: ?[]const u8,
    irreversible_opt: ?bool,
    whole_word_opt: ?bool,
) Error!?Filter {
    const existing = try lookupByIdForUser(conn, allocator, id, user_id);
    if (existing == null) return null;

    const new_phrase = phrase_opt orelse existing.?.phrase;
    const new_context = context_opt orelse existing.?.context;
    const new_irrev = irreversible_opt orelse existing.?.irreversible;
    const new_whole = whole_word_opt orelse existing.?.whole_word;

    var stmt = try conn.prepareZ(
        "UPDATE filters\n" ++
            "SET phrase = ?3, context = ?4, irreversible = ?5, whole_word = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')\n" ++
            "WHERE id = ?1 AND user_id = ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);
    try stmt.bindText(3, new_phrase);
    try stmt.bindText(4, new_context);
    try stmt.bindInt64(5, if (new_irrev) 1 else 0);
    try stmt.bindInt64(6, if (new_whole) 1 else 0);
    _ = try stmt.step();

    return (try lookupByIdForUser(conn, allocator, id, user_id)).?;
}

pub fn delete(conn: *db.Db, id: i64, user_id: i64) db.Error!bool {
    var stmt = try conn.prepareZ("DELETE FROM filters WHERE id = ?1 AND user_id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    try stmt.bindInt64(2, user_id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

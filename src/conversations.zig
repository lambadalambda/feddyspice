const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const Conversation = struct {
    id: i64,
    user_id: i64,
    remote_actor_id: []const u8,
    last_status_id: i64,
    unread: bool,
    hidden: bool,
    updated_at_ms: i64,

    pub fn deinit(self: *Conversation, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        self.* = undefined;
    }
};

pub fn upsertDirect(
    conn: *db.Db,
    user_id: i64,
    remote_actor_id: []const u8,
    last_status_id: i64,
    updated_at_ms: i64,
) db.Error!void {
    var stmt = try conn.prepareZ(
        \\INSERT INTO conversations(user_id, remote_actor_id, last_status_id, unread, hidden, updated_at_ms)
        \\VALUES (?1, ?2, ?3, 1, 0, ?4)
        \\ON CONFLICT(user_id, remote_actor_id) DO UPDATE SET
        \\  last_status_id=excluded.last_status_id,
        \\  unread=1,
        \\  hidden=0,
        \\  updated_at_ms=excluded.updated_at_ms;
    ++ "\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, remote_actor_id);
    try stmt.bindInt64(3, last_status_id);
    try stmt.bindInt64(4, updated_at_ms);
    _ = try stmt.step();
}

pub fn listVisible(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, limit: usize) Error![]Conversation {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT id, user_id, remote_actor_id, last_status_id, unread, hidden, updated_at_ms\n" ++
            "FROM conversations\n" ++
            "WHERE user_id = ?1 AND hidden = 0\n" ++
            "ORDER BY updated_at_ms DESC, id DESC\n" ++
            "LIMIT ?2;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged(Conversation) = .empty;
    errdefer {
        for (out.items) |*c| c.deinit(allocator);
        out.deinit(allocator);
    }

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                try out.append(allocator, .{
                    .id = stmt.columnInt64(0),
                    .user_id = stmt.columnInt64(1),
                    .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
                    .last_status_id = stmt.columnInt64(3),
                    .unread = stmt.columnInt64(4) != 0,
                    .hidden = stmt.columnInt64(5) != 0,
                    .updated_at_ms = stmt.columnInt64(6),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn lookupById(conn: *db.Db, allocator: std.mem.Allocator, user_id: i64, id: i64) Error!?Conversation {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, remote_actor_id, last_status_id, unread, hidden, updated_at_ms\n" ++
            "FROM conversations\n" ++
            "WHERE user_id = ?1 AND id = ?2\n" ++
            "LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .last_status_id = stmt.columnInt64(3),
        .unread = stmt.columnInt64(4) != 0,
        .hidden = stmt.columnInt64(5) != 0,
        .updated_at_ms = stmt.columnInt64(6),
    };
}

pub fn markRead(conn: *db.Db, user_id: i64, id: i64) db.Error!bool {
    var stmt = try conn.prepareZ("UPDATE conversations SET unread = 0 WHERE user_id = ?1 AND id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn hide(conn: *db.Db, user_id: i64, id: i64) db.Error!bool {
    var stmt = try conn.prepareZ("UPDATE conversations SET hidden = 1 WHERE user_id = ?1 AND id = ?2;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

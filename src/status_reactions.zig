const std = @import("std");

const db = @import("db.zig");
const remote_actors = @import("remote_actors.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub fn countActive(conn: *db.Db, status_id: i64, kind: []const u8) db.Error!i64 {
    var stmt = try conn.prepareZ(
        "SELECT COUNT(*) FROM status_reactions WHERE status_id = ?1 AND kind = ?2 AND active = 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, status_id);
    try stmt.bindText(2, kind);

    switch (try stmt.step()) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

pub fn listActiveRemoteActors(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    status_id: i64,
    kind: []const u8,
    limit: usize,
) Error![]remote_actors.RemoteActor {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT a.id, a.inbox, a.shared_inbox, a.preferred_username, a.domain, a.public_key_pem, a.avatar_url, a.header_url\n" ++
            "FROM status_reactions r\n" ++
            "JOIN remote_actors a ON a.id = r.remote_actor_id\n" ++
            "WHERE r.status_id = ?1 AND r.kind = ?2 AND r.active = 1\n" ++
            "ORDER BY r.updated_at_ms DESC, a.id ASC\n" ++
            "LIMIT ?3;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, status_id);
    try stmt.bindText(2, kind);
    try stmt.bindInt64(3, lim);

    var out: std.ArrayListUnmanaged(remote_actors.RemoteActor) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                const shared = if (stmt.columnType(2) == .null) null else try allocator.dupe(u8, stmt.columnText(2));
                const avatar_url = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6));
                const header_url = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7));

                out.append(allocator, .{
                    .id = try allocator.dupe(u8, stmt.columnText(0)),
                    .inbox = try allocator.dupe(u8, stmt.columnText(1)),
                    .shared_inbox = shared,
                    .preferred_username = try allocator.dupe(u8, stmt.columnText(3)),
                    .domain = try allocator.dupe(u8, stmt.columnText(4)),
                    .public_key_pem = try allocator.dupe(u8, stmt.columnText(5)),
                    .avatar_url = avatar_url,
                    .header_url = header_url,
                }) catch return error.OutOfMemory;
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn activate(
    conn: *db.Db,
    status_id: i64,
    remote_actor_id: []const u8,
    kind: []const u8,
    activity_id: ?[]const u8,
    now_ms: i64,
) db.Error!bool {
    var exists_stmt = try conn.prepareZ(
        "SELECT active FROM status_reactions WHERE status_id = ?1 AND remote_actor_id = ?2 AND kind = ?3 LIMIT 1;\x00",
    );
    defer exists_stmt.finalize();

    try exists_stmt.bindInt64(1, status_id);
    try exists_stmt.bindText(2, remote_actor_id);
    try exists_stmt.bindText(3, kind);

    const existing_active: ?bool = switch (try exists_stmt.step()) {
        .done => null,
        .row => exists_stmt.columnInt64(0) != 0,
    };

    if (existing_active == null) {
        var insert_stmt = try conn.prepareZ(
            "INSERT INTO status_reactions(status_id, remote_actor_id, kind, activity_id, active, updated_at_ms)\n" ++
                "VALUES (?1, ?2, ?3, ?4, 1, ?5);\x00",
        );
        defer insert_stmt.finalize();

        try insert_stmt.bindInt64(1, status_id);
        try insert_stmt.bindText(2, remote_actor_id);
        try insert_stmt.bindText(3, kind);
        if (activity_id) |aid| {
            try insert_stmt.bindText(4, aid);
        } else {
            try insert_stmt.bindNull(4);
        }
        try insert_stmt.bindInt64(5, now_ms);
        _ = try insert_stmt.step();
        return true;
    }

    var update_stmt = try conn.prepareZ(
        "UPDATE status_reactions SET\n" ++
            "  activity_id = COALESCE(?4, activity_id),\n" ++
            "  active = 1,\n" ++
            "  updated_at_ms = ?5\n" ++
            "WHERE status_id = ?1 AND remote_actor_id = ?2 AND kind = ?3;\x00",
    );
    defer update_stmt.finalize();

    try update_stmt.bindInt64(1, status_id);
    try update_stmt.bindText(2, remote_actor_id);
    try update_stmt.bindText(3, kind);
    if (activity_id) |aid| {
        try update_stmt.bindText(4, aid);
    } else {
        try update_stmt.bindNull(4);
    }
    try update_stmt.bindInt64(5, now_ms);
    _ = try update_stmt.step();

    return !existing_active.?;
}

pub fn undo(
    conn: *db.Db,
    status_id: i64,
    remote_actor_id: []const u8,
    kind: []const u8,
    now_ms: i64,
) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE status_reactions SET active = 0, updated_at_ms = ?4\n" ++
            "WHERE status_id = ?1 AND remote_actor_id = ?2 AND kind = ?3 AND active = 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, status_id);
    try stmt.bindText(2, remote_actor_id);
    try stmt.bindText(3, kind);
    try stmt.bindInt64(4, now_ms);
    _ = try stmt.step();

    return conn.changes() > 0;
}

pub fn undoByActivityId(conn: *db.Db, remote_actor_id: []const u8, activity_id: []const u8, now_ms: i64) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE status_reactions SET active = 0, updated_at_ms = ?3\n" ++
            "WHERE remote_actor_id = ?1 AND activity_id = ?2 AND active = 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, remote_actor_id);
    try stmt.bindText(2, activity_id);
    try stmt.bindInt64(3, now_ms);
    _ = try stmt.step();

    return conn.changes() > 0;
}

test "status_reactions: activate/undo" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const user_id = try @import("users.zig").create(&conn, a, "alice", "password", params);
    const st = try @import("statuses.zig").create(&conn, a, user_id, "hello", "public", null);

    const remote_actor_id = "https://remote.test/users/bob";
    try @import("remote_actors.zig").upsert(&conn, .{
        .id = remote_actor_id,
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const now_ms: i64 = 1234;
    try std.testing.expect(try activate(&conn, st.id, remote_actor_id, "favourite", "https://remote.test/likes/1", now_ms));
    try std.testing.expectEqual(@as(i64, 1), try countActive(&conn, st.id, "favourite"));

    try std.testing.expect(!try activate(&conn, st.id, remote_actor_id, "favourite", "https://remote.test/likes/2", now_ms + 1));
    try std.testing.expectEqual(@as(i64, 1), try countActive(&conn, st.id, "favourite"));

    try std.testing.expect(try undoByActivityId(&conn, remote_actor_id, "https://remote.test/likes/2", now_ms + 2));
    try std.testing.expectEqual(@as(i64, 0), try countActive(&conn, st.id, "favourite"));
    try std.testing.expect(!try undoByActivityId(&conn, remote_actor_id, "https://remote.test/likes/2", now_ms + 3));

    try std.testing.expect(try activate(&conn, st.id, remote_actor_id, "favourite", "https://remote.test/likes/3", now_ms + 4));
    try std.testing.expectEqual(@as(i64, 1), try countActive(&conn, st.id, "favourite"));
    try std.testing.expect(try undo(&conn, st.id, remote_actor_id, "favourite", now_ms + 5));
    try std.testing.expectEqual(@as(i64, 0), try countActive(&conn, st.id, "favourite"));
    try std.testing.expect(!try undo(&conn, st.id, remote_actor_id, "favourite", now_ms + 6));
}

const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const FollowState = enum {
    pending,
    accepted,

    pub fn asText(state: FollowState) []const u8 {
        return switch (state) {
            .pending => "pending",
            .accepted => "accepted",
        };
    }

    pub fn parse(s: []const u8) ?FollowState {
        if (std.mem.eql(u8, s, "pending")) return .pending;
        if (std.mem.eql(u8, s, "accepted")) return .accepted;
        return null;
    }
};

pub const Follow = struct {
    id: i64,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
    state: FollowState,
};

pub fn createPending(
    conn: *db.Db,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) db.Error!i64 {
    var stmt = try conn.prepareZ(
        "INSERT INTO follows(user_id, remote_actor_id, follow_activity_id, state, created_at, updated_at) VALUES (?1, ?2, ?3, 'pending', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, remote_actor_id);
    try stmt.bindText(3, follow_activity_id);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return conn.lastInsertRowId();
}

pub fn lookupByActivityId(conn: *db.Db, allocator: std.mem.Allocator, follow_activity_id: []const u8) Error!?Follow {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, remote_actor_id, follow_activity_id, state FROM follows WHERE follow_activity_id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, follow_activity_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    const state = FollowState.parse(stmt.columnText(4)) orelse .pending;

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .follow_activity_id = try allocator.dupe(u8, stmt.columnText(3)),
        .state = state,
    };
}

pub fn markAcceptedByActivityId(conn: *db.Db, follow_activity_id: []const u8) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE follows SET state='accepted', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE follow_activity_id = ?1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, follow_activity_id);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return conn.changes() > 0;
}

pub fn countAccepted(conn: *db.Db, user_id: i64) db.Error!i64 {
    var stmt = try conn.prepareZ("SELECT COUNT(*) FROM follows WHERE user_id = ?1 AND state = 'accepted';\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);

    switch (try stmt.step()) {
        .row => {},
        .done => return 0,
    }

    return stmt.columnInt64(0);
}

pub fn listAcceptedRemoteActorIds(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    limit: usize,
) Error![][]u8 {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT remote_actor_id FROM follows WHERE user_id = ?1 AND state = 'accepted' ORDER BY id DESC LIMIT ?2;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, user_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (out.items) |s| allocator.free(s);
        out.deinit(allocator);
    }

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                try out.append(allocator, try allocator.dupe(u8, stmt.columnText(0)));
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

test "createPending + markAcceptedByActivityId" {
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

    const follow_id = try createPending(&conn, user_id, "https://remote.test/users/bob", "http://example.test/follows/1");
    try std.testing.expect(follow_id > 0);

    try std.testing.expect(try markAcceptedByActivityId(&conn, "http://example.test/follows/1"));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const f = (try lookupByActivityId(&conn, arena.allocator(), "http://example.test/follows/1")).?;
    try std.testing.expectEqual(FollowState.accepted, f.state);

    try std.testing.expectEqual(@as(i64, 1), try countAccepted(&conn, user_id));

    const ids = try listAcceptedRemoteActorIds(&conn, arena.allocator(), user_id, 10);
    try std.testing.expectEqual(@as(usize, 1), ids.len);
    try std.testing.expectEqualStrings("https://remote.test/users/bob", ids[0]);
}

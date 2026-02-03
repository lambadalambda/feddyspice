const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const RemoteStatus = struct {
    id: i64,
    remote_uri: []const u8,
    remote_actor_id: []const u8,
    content_html: []const u8,
    attachments_json: ?[]const u8 = null,
    visibility: []const u8,
    created_at: []const u8,
    deleted_at: ?[]const u8,
};

fn nextNegativeId(conn: *db.Db) db.Error!i64 {
    var stmt = try conn.prepareZ("SELECT MIN(id) FROM remote_statuses;\x00");
    defer stmt.finalize();

    switch (try stmt.step()) {
        .done => return -1,
        .row => {},
    }

    if (stmt.columnType(0) == .null) return -1;
    const min_id = stmt.columnInt64(0);
    return min_id - 1;
}

pub fn lookup(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?RemoteStatus {
    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE id = ?1 AND deleted_at IS NULL LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .content_html = try allocator.dupe(u8, stmt.columnText(3)),
        .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
        .visibility = try allocator.dupe(u8, stmt.columnText(4)),
        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
        .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
    };
}

pub fn lookupIncludingDeleted(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?RemoteStatus {
    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .content_html = try allocator.dupe(u8, stmt.columnText(3)),
        .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
        .visibility = try allocator.dupe(u8, stmt.columnText(4)),
        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
        .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
    };
}

pub fn lookupByUri(conn: *db.Db, allocator: std.mem.Allocator, remote_uri: []const u8) Error!?RemoteStatus {
    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE remote_uri = ?1 AND deleted_at IS NULL LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, remote_uri);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .content_html = try allocator.dupe(u8, stmt.columnText(3)),
        .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
        .visibility = try allocator.dupe(u8, stmt.columnText(4)),
        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
        .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
    };
}

pub fn lookupByUriIncludingDeleted(conn: *db.Db, allocator: std.mem.Allocator, remote_uri: []const u8) Error!?RemoteStatus {
    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE remote_uri = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, remote_uri);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
        .content_html = try allocator.dupe(u8, stmt.columnText(3)),
        .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
        .visibility = try allocator.dupe(u8, stmt.columnText(4)),
        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
        .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
    };
}

pub fn markDeletedByUri(conn: *db.Db, remote_uri: []const u8, deleted_at: ?[]const u8) db.Error!bool {
    if (deleted_at) |ts| {
        var stmt = try conn.prepareZ(
            "UPDATE remote_statuses SET deleted_at = ?2 WHERE remote_uri = ?1 AND deleted_at IS NULL;\x00",
        );
        defer stmt.finalize();
        try stmt.bindText(1, remote_uri);
        try stmt.bindText(2, ts);

        switch (try stmt.step()) {
            .done => {},
            .row => return error.Sqlite,
        }

        return conn.changes() > 0;
    }

    var stmt = try conn.prepareZ(
        "UPDATE remote_statuses SET deleted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE remote_uri = ?1 AND deleted_at IS NULL;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, remote_uri);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return conn.changes() > 0;
}

pub fn createIfNotExists(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    remote_uri: []const u8,
    remote_actor_id: []const u8,
    content_html: []const u8,
    attachments_json: ?[]const u8,
    visibility: []const u8,
    created_at: []const u8,
) Error!RemoteStatus {
    if (try lookupByUri(conn, allocator, remote_uri)) |existing| return existing;

    const id = try nextNegativeId(conn);

    var stmt = try conn.prepareZ(
        "INSERT INTO remote_statuses(id, remote_uri, remote_actor_id, content_html, attachments_json, visibility, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, id);
    try stmt.bindText(2, remote_uri);
    try stmt.bindText(3, remote_actor_id);
    try stmt.bindText(4, content_html);
    if (attachments_json) |aj| {
        try stmt.bindText(5, aj);
    } else {
        try stmt.bindNull(5);
    }
    try stmt.bindText(6, visibility);
    try stmt.bindText(7, created_at);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return (try lookup(conn, allocator, id)).?;
}

pub fn listLatest(conn: *db.Db, allocator: std.mem.Allocator, limit: usize) Error![]RemoteStatus {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE deleted_at IS NULL ORDER BY id DESC LIMIT ?1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, lim);

    var out: std.ArrayListUnmanaged(RemoteStatus) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                try out.append(allocator, .{
                    .id = stmt.columnInt64(0),
                    .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
                    .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
                    .content_html = try allocator.dupe(u8, stmt.columnText(3)),
                    .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
                    .visibility = try allocator.dupe(u8, stmt.columnText(4)),
                    .created_at = try allocator.dupe(u8, stmt.columnText(5)),
                    .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn listLatestBeforeCreatedAt(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    limit: usize,
    before_created_at: ?[]const u8,
    before_id: ?i64,
) Error![]RemoteStatus {
    const lim: i64 = @intCast(@min(limit, 200));

    var out: std.ArrayListUnmanaged(RemoteStatus) = .empty;
    errdefer out.deinit(allocator);

    if (before_created_at == null) {
        var stmt = try conn.prepareZ(
            "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE deleted_at IS NULL ORDER BY created_at DESC, id DESC LIMIT ?1;\x00",
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, lim);

        while (true) {
            switch (try stmt.step()) {
                .done => break,
                .row => {
                    try out.append(allocator, .{
                        .id = stmt.columnInt64(0),
                        .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
                        .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
                        .content_html = try allocator.dupe(u8, stmt.columnText(3)),
                        .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
                        .visibility = try allocator.dupe(u8, stmt.columnText(4)),
                        .created_at = try allocator.dupe(u8, stmt.columnText(5)),
                        .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
                    });
                },
            }
        }

        return out.toOwnedSlice(allocator);
    }

    const anchor_id = before_id orelse std.math.maxInt(i64);

    var stmt = try conn.prepareZ(
        "SELECT id, remote_uri, remote_actor_id, content_html, visibility, created_at, deleted_at, attachments_json FROM remote_statuses WHERE deleted_at IS NULL AND (created_at < ?1 OR (created_at = ?1 AND id < ?2)) ORDER BY created_at DESC, id DESC LIMIT ?3;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, before_created_at.?);
    try stmt.bindInt64(2, anchor_id);
    try stmt.bindInt64(3, lim);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                try out.append(allocator, .{
                    .id = stmt.columnInt64(0),
                    .remote_uri = try allocator.dupe(u8, stmt.columnText(1)),
                    .remote_actor_id = try allocator.dupe(u8, stmt.columnText(2)),
                    .content_html = try allocator.dupe(u8, stmt.columnText(3)),
                    .attachments_json = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7)),
                    .visibility = try allocator.dupe(u8, stmt.columnText(4)),
                    .created_at = try allocator.dupe(u8, stmt.columnText(5)),
                    .deleted_at = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6)),
                });
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

test "createIfNotExists assigns negative ids" {
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    _ = user_id;
    const s1 = try createIfNotExists(
        &conn,
        a,
        "https://remote.test/notes/1",
        "https://remote.test/users/bob",
        "<p>one</p>",
        null,
        "public",
        "2020-01-01T00:00:00.000Z",
    );
    const s2 = try createIfNotExists(
        &conn,
        a,
        "https://remote.test/notes/2",
        "https://remote.test/users/bob",
        "<p>two</p>",
        null,
        "public",
        "2020-01-01T00:00:01.000Z",
    );

    try std.testing.expect(s1.id < 0);
    try std.testing.expect(s2.id < s1.id);

    try std.testing.expect(try markDeletedByUri(&conn, "https://remote.test/notes/2", "2020-01-01T00:00:02.000Z"));
    try std.testing.expect((try lookupByUri(&conn, a, "https://remote.test/notes/2")) == null);
    try std.testing.expect((try lookupByUriIncludingDeleted(&conn, a, "https://remote.test/notes/2")).?.deleted_at != null);
}

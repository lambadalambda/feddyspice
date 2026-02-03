const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const Media = struct {
    id: i64,
    user_id: i64,
    public_token: []const u8,
    content_type: []const u8,
    data: []const u8,
    description: ?[]const u8,
    created_at_ms: i64,
    updated_at_ms: i64,

    pub fn deinit(self: *Media, allocator: std.mem.Allocator) void {
        allocator.free(self.public_token);
        allocator.free(self.content_type);
        allocator.free(self.data);
        if (self.description) |d| allocator.free(d);
        self.* = undefined;
    }
};

pub const MediaMeta = struct {
    id: i64,
    user_id: i64,
    public_token: []const u8,
    content_type: []const u8,
    description: ?[]const u8,
    created_at_ms: i64,
    updated_at_ms: i64,

    pub fn deinit(self: *MediaMeta, allocator: std.mem.Allocator) void {
        allocator.free(self.public_token);
        allocator.free(self.content_type);
        if (self.description) |d| allocator.free(d);
        self.* = undefined;
    }
};

pub fn create(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    content_type: []const u8,
    data: []const u8,
    description: ?[]const u8,
    now_ms: i64,
) Error!MediaMeta {
    const token = try generatePublicTokenHexAlloc(allocator);
    defer allocator.free(token);
    return createWithToken(conn, allocator, user_id, token, content_type, data, description, now_ms);
}

pub fn createWithToken(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    user_id: i64,
    public_token: []const u8,
    content_type: []const u8,
    data: []const u8,
    description: ?[]const u8,
    now_ms: i64,
) Error!MediaMeta {
    var stmt = try conn.prepareZ(
        "INSERT INTO media_attachments(user_id, public_token, content_type, data, description, created_at_ms, updated_at_ms)\n" ++
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6);\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, user_id);
    try stmt.bindText(2, public_token);
    try stmt.bindText(3, content_type);
    try stmt.bindBlob(4, data);
    if (description) |d| {
        try stmt.bindText(5, d);
    } else {
        try stmt.bindNull(5);
    }
    try stmt.bindInt64(6, now_ms);

    _ = try stmt.step();
    const id = conn.lastInsertRowId();
    return (try lookupMeta(conn, allocator, id)).?;
}

pub fn lookup(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?Media {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, public_token, content_type, data, description, created_at_ms, updated_at_ms\n" ++
            "FROM media_attachments WHERE id=?1 LIMIT 1;\x00",
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
        .public_token = try allocator.dupe(u8, stmt.columnText(2)),
        .content_type = try allocator.dupe(u8, stmt.columnText(3)),
        .data = try allocator.dupe(u8, stmt.columnBlob(4)),
        .description = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
        .created_at_ms = stmt.columnInt64(6),
        .updated_at_ms = stmt.columnInt64(7),
    };
}

pub fn lookupMeta(conn: *db.Db, allocator: std.mem.Allocator, id: i64) Error!?MediaMeta {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, public_token, content_type, description, created_at_ms, updated_at_ms\n" ++
            "FROM media_attachments WHERE id=?1 LIMIT 1;\x00",
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
        .public_token = try allocator.dupe(u8, stmt.columnText(2)),
        .content_type = try allocator.dupe(u8, stmt.columnText(3)),
        .description = if (stmt.columnType(4) == .null) null else try allocator.dupe(u8, stmt.columnText(4)),
        .created_at_ms = stmt.columnInt64(5),
        .updated_at_ms = stmt.columnInt64(6),
    };
}

pub fn lookupByPublicToken(conn: *db.Db, allocator: std.mem.Allocator, token: []const u8) Error!?Media {
    var stmt = try conn.prepareZ(
        "SELECT id, user_id, public_token, content_type, data, description, created_at_ms, updated_at_ms\n" ++
            "FROM media_attachments WHERE public_token=?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, token);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .public_token = try allocator.dupe(u8, stmt.columnText(2)),
        .content_type = try allocator.dupe(u8, stmt.columnText(3)),
        .data = try allocator.dupe(u8, stmt.columnBlob(4)),
        .description = if (stmt.columnType(5) == .null) null else try allocator.dupe(u8, stmt.columnText(5)),
        .created_at_ms = stmt.columnInt64(6),
        .updated_at_ms = stmt.columnInt64(7),
    };
}

pub fn updateDescription(
    conn: *db.Db,
    media_id: i64,
    user_id: i64,
    description: ?[]const u8,
    now_ms: i64,
) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE media_attachments SET description=?1, updated_at_ms=?2 WHERE id=?3 AND user_id=?4;\x00",
    );
    defer stmt.finalize();
    if (description) |d| {
        try stmt.bindText(1, d);
    } else {
        try stmt.bindNull(1);
    }
    try stmt.bindInt64(2, now_ms);
    try stmt.bindInt64(3, media_id);
    try stmt.bindInt64(4, user_id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn attachToStatus(conn: *db.Db, status_id: i64, media_id: i64, position: i64) db.Error!bool {
    var stmt = try conn.prepareZ(
        "INSERT INTO status_media_attachments(status_id, media_id, position) VALUES (?1, ?2, ?3)\n" ++
            "ON CONFLICT(media_id) DO NOTHING;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
    try stmt.bindInt64(2, media_id);
    try stmt.bindInt64(3, position);
    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn listForStatus(conn: *db.Db, allocator: std.mem.Allocator, status_id: i64) Error![]MediaMeta {
    var stmt = try conn.prepareZ(
        "SELECT m.id, m.user_id, m.public_token, m.content_type, m.description, m.created_at_ms, m.updated_at_ms\n" ++
            "FROM status_media_attachments sma\n" ++
            "JOIN media_attachments m ON m.id = sma.media_id\n" ++
            "WHERE sma.status_id = ?1\n" ++
            "ORDER BY sma.position ASC;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);

    var out: std.ArrayListUnmanaged(MediaMeta) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => try out.append(allocator, .{
                .id = stmt.columnInt64(0),
                .user_id = stmt.columnInt64(1),
                .public_token = try allocator.dupe(u8, stmt.columnText(2)),
                .content_type = try allocator.dupe(u8, stmt.columnText(3)),
                .description = if (stmt.columnType(4) == .null) null else try allocator.dupe(u8, stmt.columnText(4)),
                .created_at_ms = stmt.columnInt64(5),
                .updated_at_ms = stmt.columnInt64(6),
            }),
        }
    }

    return out.toOwnedSlice(allocator);
}

pub fn deleteForStatus(conn: *db.Db, status_id: i64) db.Error!void {
    var stmt = try conn.prepareZ(
        "DELETE FROM media_attachments WHERE id IN (SELECT media_id FROM status_media_attachments WHERE status_id=?1);\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, status_id);
    _ = try stmt.step();
}

pub fn pruneOrphansOlderThan(conn: *db.Db, cutoff_ms: i64) db.Error!i64 {
    var stmt = try conn.prepareZ(
        "DELETE FROM media_attachments\n" ++
            "WHERE id IN (\n" ++
            "  SELECT m.id\n" ++
            "  FROM media_attachments m\n" ++
            "  LEFT JOIN status_media_attachments sma ON sma.media_id = m.id\n" ++
            "  WHERE sma.media_id IS NULL AND m.created_at_ms < ?1\n" ++
            ");\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, cutoff_ms);
    _ = try stmt.step();
    return conn.changes();
}

test "media: create/lookup and attach to status" {
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

    const now_ms: i64 = 123;
    var meta = try createWithToken(
        &conn,
        std.testing.allocator,
        user_id,
        "token123",
        "image/png",
        "pngdata",
        "desc",
        now_ms,
    );
    defer meta.deinit(std.testing.allocator);
    try std.testing.expectEqual(user_id, meta.user_id);
    try std.testing.expectEqualStrings("token123", meta.public_token);

    var full = (try lookup(&conn, std.testing.allocator, meta.id)).?;
    defer full.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("token123", full.public_token);
    try std.testing.expectEqualStrings("image/png", full.content_type);
    try std.testing.expectEqualStrings("pngdata", full.data);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const st = try @import("statuses.zig").create(&conn, a, user_id, "hello", "public");
    try std.testing.expect(try attachToStatus(&conn, st.id, meta.id, 0));

    const list = try listForStatus(&conn, std.testing.allocator, st.id);
    defer {
        for (list) |*m| {
            m.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(list);
    }
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqual(meta.id, list[0].id);
}

fn generatePublicTokenHexAlloc(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const encoded = std.fmt.bytesToHex(bytes, .lower);
    return allocator.dupe(u8, encoded[0..]);
}

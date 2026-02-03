const std = @import("std");

const db = @import("db.zig");
const password = @import("password.zig");

pub const Error = db.Error || password.Error || error{
    SingleUserOnly,
    InvalidUsername,
    InvalidPasswordHash,
};

pub const Credentials = struct {
    id: i64,
    username: []const u8,
    password_salt: password.Salt,
    password_hash: password.Hash,
};

pub const User = struct {
    id: i64,
    username: []const u8,
    created_at: []const u8,
    display_name: []const u8,
    note: []const u8,
    avatar_media_id: ?i64,
    header_media_id: ?i64,
};

pub fn count(conn: *db.Db) db.Error!i64 {
    var stmt = try conn.prepareZ("SELECT COUNT(*) FROM users;\x00");
    defer stmt.finalize();

    switch (try stmt.step()) {
        .row => return stmt.columnInt64(0),
        .done => return 0,
    }
}

pub fn createWithSalt(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
    plaintext_password: []const u8,
    salt: password.Salt,
    params: password.Params,
) Error!i64 {
    if (username.len == 0) return error.InvalidUsername;
    if (try count(conn) > 0) return error.SingleUserOnly;

    const pw_hash = try password.hashPassword(allocator, plaintext_password, salt, params);

    var stmt = try conn.prepareZ(
        "INSERT INTO users(username, password_salt, password_hash, created_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, username);
    try stmt.bindBlob(2, salt[0..]);
    try stmt.bindBlob(3, pw_hash[0..]);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return conn.lastInsertRowId();
}

pub fn create(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
    plaintext_password: []const u8,
    params: password.Params,
) Error!i64 {
    var salt: password.Salt = undefined;
    std.crypto.random.bytes(&salt);
    return createWithSalt(conn, allocator, username, plaintext_password, salt, params);
}

pub fn lookupCredentials(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
) (Error || std.mem.Allocator.Error)!?Credentials {
    var stmt = try conn.prepareZ(
        "SELECT id, username, password_salt, password_hash FROM users WHERE username = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, username);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    const id = stmt.columnInt64(0);

    const username_col = stmt.columnText(1);
    const username_copy = try allocator.dupe(u8, username_col);

    const salt_bytes = stmt.columnBlob(2);
    const hash_bytes = stmt.columnBlob(3);
    if (salt_bytes.len != password.SaltLen) return error.InvalidPasswordHash;
    if (hash_bytes.len != password.HashLen) return error.InvalidPasswordHash;

    var salt: password.Salt = undefined;
    @memcpy(&salt, salt_bytes);

    var pw_hash: password.Hash = undefined;
    @memcpy(&pw_hash, hash_bytes);

    return .{
        .id = id,
        .username = username_copy,
        .password_salt = salt,
        .password_hash = pw_hash,
    };
}

pub fn lookupUserById(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    id: i64,
) (db.Error || std.mem.Allocator.Error)!?User {
    var stmt = try conn.prepareZ(
        "SELECT id, username, created_at, display_name, note, avatar_media_id, header_media_id FROM users WHERE id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .username = try allocator.dupe(u8, stmt.columnText(1)),
        .created_at = try allocator.dupe(u8, stmt.columnText(2)),
        .display_name = try allocator.dupe(u8, stmt.columnText(3)),
        .note = try allocator.dupe(u8, stmt.columnText(4)),
        .avatar_media_id = if (stmt.columnType(5) == .null) null else stmt.columnInt64(5),
        .header_media_id = if (stmt.columnType(6) == .null) null else stmt.columnInt64(6),
    };
}

pub fn lookupUserByUsername(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
) (db.Error || std.mem.Allocator.Error)!?User {
    var stmt = try conn.prepareZ(
        "SELECT id, username, created_at, display_name, note, avatar_media_id, header_media_id FROM users WHERE username = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, username);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .username = try allocator.dupe(u8, stmt.columnText(1)),
        .created_at = try allocator.dupe(u8, stmt.columnText(2)),
        .display_name = try allocator.dupe(u8, stmt.columnText(3)),
        .note = try allocator.dupe(u8, stmt.columnText(4)),
        .avatar_media_id = if (stmt.columnType(5) == .null) null else stmt.columnInt64(5),
        .header_media_id = if (stmt.columnType(6) == .null) null else stmt.columnInt64(6),
    };
}

pub fn lookupFirstUser(conn: *db.Db, allocator: std.mem.Allocator) (db.Error || std.mem.Allocator.Error)!?User {
    var stmt = try conn.prepareZ(
        "SELECT id, username, created_at, display_name, note, avatar_media_id, header_media_id FROM users ORDER BY id ASC LIMIT 1;\x00",
    );
    defer stmt.finalize();

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .username = try allocator.dupe(u8, stmt.columnText(1)),
        .created_at = try allocator.dupe(u8, stmt.columnText(2)),
        .display_name = try allocator.dupe(u8, stmt.columnText(3)),
        .note = try allocator.dupe(u8, stmt.columnText(4)),
        .avatar_media_id = if (stmt.columnType(5) == .null) null else stmt.columnInt64(5),
        .header_media_id = if (stmt.columnType(6) == .null) null else stmt.columnInt64(6),
    };
}

pub fn updateProfile(
    conn: *db.Db,
    user_id: i64,
    display_name: []const u8,
    note: []const u8,
    avatar_media_id: ?i64,
    header_media_id: ?i64,
) db.Error!bool {
    var stmt = try conn.prepareZ(
        "UPDATE users SET display_name=?1, note=?2, avatar_media_id=?3, header_media_id=?4 WHERE id=?5;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, display_name);
    try stmt.bindText(2, note);
    if (avatar_media_id) |id| {
        try stmt.bindInt64(3, id);
    } else {
        try stmt.bindNull(3);
    }
    if (header_media_id) |id| {
        try stmt.bindInt64(4, id);
    } else {
        try stmt.bindNull(4);
    }
    try stmt.bindInt64(5, user_id);
    _ = try stmt.step();
    return conn.changes() > 0;
}

pub fn freeCredentials(allocator: std.mem.Allocator, creds: *Credentials) void {
    allocator.free(creds.username);
    creds.* = undefined;
}

pub fn verifyLogin(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
    plaintext_password: []const u8,
    params: password.Params,
) Error!bool {
    return (try authenticate(conn, allocator, username, plaintext_password, params)) != null;
}

pub fn authenticate(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    username: []const u8,
    plaintext_password: []const u8,
    params: password.Params,
) Error!?i64 {
    const creds_opt = try lookupCredentials(conn, allocator, username);
    if (creds_opt == null) return null;
    var creds = creds_opt.?;
    defer freeCredentials(allocator, &creds);

    const ok = try password.verifyPassword(
        allocator,
        plaintext_password,
        creds.password_salt,
        creds.password_hash,
        params,
    );
    if (!ok) return null;
    return creds.id;
}

test "create single user and verify password" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: password.Params = .{ .t = 1, .m = 8, .p = 1 };
    const salt: password.Salt = .{0x02} ** password.SaltLen;

    _ = try createWithSalt(&conn, std.testing.allocator, "alice", "password", salt, params);

    try std.testing.expect(try verifyLogin(&conn, std.testing.allocator, "alice", "password", params));
    try std.testing.expect(!(try verifyLogin(&conn, std.testing.allocator, "alice", "wrong", params)));
    try std.testing.expect(!(try verifyLogin(&conn, std.testing.allocator, "missing", "password", params)));
}

test "enforces single-user" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: password.Params = .{ .t = 1, .m = 8, .p = 1 };
    const salt: password.Salt = .{0x03} ** password.SaltLen;

    _ = try createWithSalt(&conn, std.testing.allocator, "alice", "password", salt, params);
    try std.testing.expectError(
        error.SingleUserOnly,
        createWithSalt(&conn, std.testing.allocator, "bob", "password", salt, params),
    );
}

test "lookupUserByUsername" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    const params: password.Params = .{ .t = 1, .m = 8, .p = 1 };
    const salt: password.Salt = .{0x04} ** password.SaltLen;

    const id = try createWithSalt(&conn, std.testing.allocator, "alice", "password", salt, params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const got = (try lookupUserByUsername(&conn, arena.allocator(), "alice")).?;
    try std.testing.expectEqual(id, got.id);
    try std.testing.expectEqualStrings("alice", got.username);
}

const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error;

pub const RemoteActor = struct {
    id: []const u8,
    inbox: []const u8,
    shared_inbox: ?[]const u8,
    preferred_username: []const u8,
    domain: []const u8,
    public_key_pem: []const u8,
    avatar_url: ?[]const u8 = null,
    header_url: ?[]const u8 = null,
};

pub fn upsert(conn: *db.Db, actor: RemoteActor) db.Error!void {
    var stmt = try conn.prepareZ(
        \\INSERT INTO remote_actors(id, inbox, shared_inbox, preferred_username, domain, public_key_pem, avatar_url, header_url, discovered_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        \\ON CONFLICT(id) DO UPDATE SET
        \\  inbox=excluded.inbox,
        \\  shared_inbox=excluded.shared_inbox,
        \\  preferred_username=excluded.preferred_username,
        \\  domain=excluded.domain,
        \\  public_key_pem=excluded.public_key_pem,
        \\  avatar_url=excluded.avatar_url,
        \\  header_url=excluded.header_url,
        \\  discovered_at=excluded.discovered_at;
    ++ "\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, actor.id);
    try stmt.bindText(2, actor.inbox);
    if (actor.shared_inbox) |s| {
        try stmt.bindText(3, s);
    } else {
        try stmt.bindNull(3);
    }
    try stmt.bindText(4, actor.preferred_username);
    try stmt.bindText(5, actor.domain);
    try stmt.bindText(6, actor.public_key_pem);
    if (actor.avatar_url) |u| {
        try stmt.bindText(7, u);
    } else {
        try stmt.bindNull(7);
    }
    if (actor.header_url) |u| {
        try stmt.bindText(8, u);
    } else {
        try stmt.bindNull(8);
    }

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }
}

pub fn lookupById(conn: *db.Db, allocator: std.mem.Allocator, id: []const u8) Error!?RemoteActor {
    var stmt = try conn.prepareZ(
        "SELECT id, inbox, shared_inbox, preferred_username, domain, public_key_pem, avatar_url, header_url FROM remote_actors WHERE id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    const shared = if (stmt.columnType(2) == .null) null else try allocator.dupe(u8, stmt.columnText(2));
    const avatar_url = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6));
    const header_url = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7));

    return .{
        .id = try allocator.dupe(u8, stmt.columnText(0)),
        .inbox = try allocator.dupe(u8, stmt.columnText(1)),
        .shared_inbox = shared,
        .preferred_username = try allocator.dupe(u8, stmt.columnText(3)),
        .domain = try allocator.dupe(u8, stmt.columnText(4)),
        .public_key_pem = try allocator.dupe(u8, stmt.columnText(5)),
        .avatar_url = avatar_url,
        .header_url = header_url,
    };
}

pub fn lookupRowIdById(conn: *db.Db, id: []const u8) db.Error!?i64 {
    var stmt = try conn.prepareZ("SELECT rowid FROM remote_actors WHERE id = ?1 LIMIT 1;\x00");
    defer stmt.finalize();
    try stmt.bindText(1, id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return stmt.columnInt64(0);
}

pub fn lookupByRowId(conn: *db.Db, allocator: std.mem.Allocator, rowid: i64) Error!?RemoteActor {
    var stmt = try conn.prepareZ(
        "SELECT id, inbox, shared_inbox, preferred_username, domain, public_key_pem, avatar_url, header_url FROM remote_actors WHERE rowid = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, rowid);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    const shared = if (stmt.columnType(2) == .null) null else try allocator.dupe(u8, stmt.columnText(2));
    const avatar_url = if (stmt.columnType(6) == .null) null else try allocator.dupe(u8, stmt.columnText(6));
    const header_url = if (stmt.columnType(7) == .null) null else try allocator.dupe(u8, stmt.columnText(7));

    return .{
        .id = try allocator.dupe(u8, stmt.columnText(0)),
        .inbox = try allocator.dupe(u8, stmt.columnText(1)),
        .shared_inbox = shared,
        .preferred_username = try allocator.dupe(u8, stmt.columnText(3)),
        .domain = try allocator.dupe(u8, stmt.columnText(4)),
        .public_key_pem = try allocator.dupe(u8, stmt.columnText(5)),
        .avatar_url = avatar_url,
        .header_url = header_url,
    };
}

test "upsert + lookupById" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    try upsert(&conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const got = (try lookupById(&conn, arena.allocator(), "https://remote.test/users/bob")).?;
    try std.testing.expectEqualStrings("bob", got.preferred_username);
}

test "lookupRowIdById + lookupByRowId" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try @import("migrations.zig").migrate(&conn);

    try upsert(&conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const rowid = (try lookupRowIdById(&conn, "https://remote.test/users/bob")).?;
    try std.testing.expect(rowid > 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const got = (try lookupByRowId(&conn, arena.allocator(), rowid)).?;
    try std.testing.expectEqualStrings("https://remote.test/users/bob", got.id);
}

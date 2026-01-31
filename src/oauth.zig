const std = @import("std");

const db = @import("db.zig");

pub const Error = db.Error || std.mem.Allocator.Error || error{
    NotFound,
};

pub const AppCredentials = struct {
    id: i64,
    client_id: []const u8,
    client_secret: []const u8,
};

pub const App = struct {
    id: i64,
    name: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uris: []const u8,
    scopes: []const u8,
    website: []const u8,
};

pub fn createApp(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    name: []const u8,
    redirect_uris: []const u8,
    scopes: []const u8,
    website: []const u8,
) Error!AppCredentials {
    var client_id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&client_id_bytes);
    const client_id_hex = std.fmt.bytesToHex(client_id_bytes, .lower);
    const client_id = try allocator.dupe(u8, client_id_hex[0..]);

    var client_secret_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&client_secret_bytes);
    const client_secret_hex = std.fmt.bytesToHex(client_secret_bytes, .lower);
    const client_secret = try allocator.dupe(u8, client_secret_hex[0..]);

    var stmt = try conn.prepareZ(
        "INSERT INTO oauth_apps(name, client_id, client_secret, redirect_uris, scopes, website, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, name);
    try stmt.bindText(2, client_id);
    try stmt.bindText(3, client_secret);
    try stmt.bindText(4, redirect_uris);
    try stmt.bindText(5, scopes);
    try stmt.bindText(6, website);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    return .{
        .id = conn.lastInsertRowId(),
        .client_id = client_id,
        .client_secret = client_secret,
    };
}

pub fn lookupAppByClientId(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    client_id: []const u8,
) Error!?App {
    var stmt = try conn.prepareZ(
        "SELECT id, name, client_id, client_secret, redirect_uris, scopes, website FROM oauth_apps WHERE client_id = ?1 LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, client_id);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .id = stmt.columnInt64(0),
        .name = try allocator.dupe(u8, stmt.columnText(1)),
        .client_id = try allocator.dupe(u8, stmt.columnText(2)),
        .client_secret = try allocator.dupe(u8, stmt.columnText(3)),
        .redirect_uris = try allocator.dupe(u8, stmt.columnText(4)),
        .scopes = try allocator.dupe(u8, stmt.columnText(5)),
        .website = try allocator.dupe(u8, stmt.columnText(6)),
    };
}

pub fn redirectUriAllowed(redirect_uris: []const u8, redirect_uri: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, redirect_uris, " \t\r\n");
    while (it.next()) |uri| {
        if (std.mem.eql(u8, uri, redirect_uri)) return true;
    }
    return false;
}

pub const AuthCode = struct {
    app_id: i64,
    user_id: i64,
    redirect_uri: []const u8,
    scopes: []const u8,
};

pub fn createAuthCode(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    app_id: i64,
    user_id: i64,
    redirect_uri: []const u8,
    scopes: []const u8,
) Error![]u8 {
    var code_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&code_bytes);
    const code_hex = std.fmt.bytesToHex(code_bytes, .lower);
    const code = try allocator.dupe(u8, code_hex[0..]);

    var stmt = try conn.prepareZ(
        "INSERT INTO oauth_auth_codes(code, app_id, user_id, redirect_uri, scopes, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now','+10 minutes'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, code);
    try stmt.bindInt64(2, app_id);
    try stmt.bindInt64(3, user_id);
    try stmt.bindText(4, redirect_uri);
    try stmt.bindText(5, scopes);

    switch (try stmt.step()) {
        .done => return code,
        .row => return error.Sqlite,
    }
}

pub fn consumeAuthCode(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    code: []const u8,
) Error!?AuthCode {
    try conn.execZ("BEGIN IMMEDIATE;\x00");
    errdefer conn.execZ("ROLLBACK;\x00") catch {};

    var stmt = try conn.prepareZ(
        "SELECT app_id, user_id, redirect_uri, scopes FROM oauth_auth_codes WHERE code = ?1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindText(1, code);

    switch (try stmt.step()) {
        .done => {
            try conn.execZ("COMMIT;\x00");
            return null;
        },
        .row => {},
    }

    const out: AuthCode = .{
        .app_id = stmt.columnInt64(0),
        .user_id = stmt.columnInt64(1),
        .redirect_uri = try allocator.dupe(u8, stmt.columnText(2)),
        .scopes = try allocator.dupe(u8, stmt.columnText(3)),
    };

    var del = try conn.prepareZ("DELETE FROM oauth_auth_codes WHERE code = ?1;\x00");
    defer del.finalize();
    try del.bindText(1, code);
    switch (try del.step()) {
        .done => {},
        .row => return error.Sqlite,
    }

    try conn.execZ("COMMIT;\x00");
    return out;
}

pub const AccessTokenInfo = struct {
    user_id: i64,
    app_id: i64,
    scopes: []const u8,
};

pub fn createAccessToken(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    app_id: i64,
    user_id: i64,
    scopes: []const u8,
) Error![]u8 {
    var token_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&token_bytes);
    const token_hex = std.fmt.bytesToHex(token_bytes, .lower);
    const token = try allocator.dupe(u8, token_hex[0..]);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    var stmt = try conn.prepareZ(
        "INSERT INTO oauth_access_tokens(token_hash, app_id, user_id, scopes, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now','+365 days'));\x00",
    );
    defer stmt.finalize();

    try stmt.bindBlob(1, digest[0..]);
    try stmt.bindInt64(2, app_id);
    try stmt.bindInt64(3, user_id);
    try stmt.bindText(4, scopes);

    switch (try stmt.step()) {
        .done => return token,
        .row => return error.Sqlite,
    }
}

pub fn verifyAccessToken(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    token: []const u8,
) Error!?AccessTokenInfo {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    var stmt = try conn.prepareZ(
        "SELECT user_id, app_id, scopes FROM oauth_access_tokens WHERE token_hash = ?1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') LIMIT 1;\x00",
    );
    defer stmt.finalize();

    try stmt.bindBlob(1, digest[0..]);

    switch (try stmt.step()) {
        .done => return null,
        .row => {},
    }

    return .{
        .user_id = stmt.columnInt64(0),
        .app_id = stmt.columnInt64(1),
        .scopes = try allocator.dupe(u8, stmt.columnText(2)),
    };
}

test "create app, auth code, access token" {
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const creds = try createApp(&conn, a, "pl-fe", "urn:ietf:wg:oauth:2.0:oob", "read write follow", "");
    const app_row = (try lookupAppByClientId(&conn, a, creds.client_id)).?;
    try std.testing.expect(redirectUriAllowed(app_row.redirect_uris, "urn:ietf:wg:oauth:2.0:oob"));

    const code = try createAuthCode(&conn, a, creds.id, user_id, "urn:ietf:wg:oauth:2.0:oob", "read write");
    const consumed = (try consumeAuthCode(&conn, a, code)).?;
    try std.testing.expectEqual(creds.id, consumed.app_id);
    try std.testing.expectEqual(user_id, consumed.user_id);

    const token = try createAccessToken(&conn, a, creds.id, user_id, consumed.scopes);
    const tok_info = (try verifyAccessToken(&conn, a, token)).?;
    try std.testing.expectEqual(user_id, tok_info.user_id);
    try std.testing.expectEqual(creds.id, tok_info.app_id);
}


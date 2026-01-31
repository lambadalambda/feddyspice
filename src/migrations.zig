const std = @import("std");

const db = @import("db.zig");

pub fn migrate(conn: *db.Db) !void {
    try conn.execZ(schema_migrations_sql);

    var exists_stmt = try conn.prepareZ(migration_exists_sql);
    defer exists_stmt.finalize();

    var insert_stmt = try conn.prepareZ(migration_insert_sql);
    defer insert_stmt.finalize();

    for (migrations) |m| {
        exists_stmt.reset();
        try exists_stmt.bindInt64(1, m.version);

        const already_applied = switch (try exists_stmt.step()) {
            .row => true,
            .done => false,
        };

        if (already_applied) continue;

        {
            try conn.execZ(begin_sql);
            errdefer conn.execZ(rollback_sql) catch {};

            try conn.execZ(m.sql);

            insert_stmt.reset();
            try insert_stmt.bindInt64(1, m.version);
            try insert_stmt.bindText(2, m.name);

            switch (try insert_stmt.step()) {
                .done => {},
                .row => return error.UnexpectedRow,
            }

            try conn.execZ(commit_sql);
        }
    }
}

const Migration = struct {
    version: i64,
    name: []const u8,
    sql: [:0]const u8,
};

const migrations = [_]Migration{
    .{
        .version = 1,
        .name = "create_users",
        .sql = users_v1_sql,
    },
    .{
        .version = 2,
        .name = "create_sessions",
        .sql = sessions_v2_sql,
    },
    .{
        .version = 3,
        .name = "create_oauth",
        .sql = oauth_v3_sql,
    },
    .{
        .version = 4,
        .name = "create_statuses",
        .sql = statuses_v4_sql,
    },
};

const schema_migrations_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS schema_migrations (
    \\  version INTEGER PRIMARY KEY,
    \\  name TEXT NOT NULL,
    \\  applied_at TEXT NOT NULL
    \\);
    ++ "\x00";

const migration_exists_sql: [:0]const u8 =
    "SELECT 1 FROM schema_migrations WHERE version = ?1 LIMIT 1;\x00";

const migration_insert_sql: [:0]const u8 =
    "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'));\x00";

const begin_sql: [:0]const u8 = "BEGIN IMMEDIATE;\x00";
const commit_sql: [:0]const u8 = "COMMIT;\x00";
const rollback_sql: [:0]const u8 = "ROLLBACK;\x00";

const users_v1_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS users (
    \\  id INTEGER PRIMARY KEY,
    \\  username TEXT NOT NULL UNIQUE,
    \\  password_salt BLOB NOT NULL,
    \\  password_hash BLOB NOT NULL,
    \\  created_at TEXT NOT NULL
    \\);
    ++ "\x00";

const sessions_v2_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS sessions (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  token_hash BLOB NOT NULL UNIQUE,
    \\  created_at TEXT NOT NULL,
    \\  expires_at TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
    ++ "\x00";

const oauth_v3_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS oauth_apps (
    \\  id INTEGER PRIMARY KEY,
    \\  name TEXT NOT NULL,
    \\  client_id TEXT NOT NULL UNIQUE,
    \\  client_secret TEXT NOT NULL,
    \\  redirect_uris TEXT NOT NULL,
    \\  scopes TEXT NOT NULL,
    \\  website TEXT NOT NULL,
    \\  created_at TEXT NOT NULL
    \\);
    \\
    \\CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    \\  code TEXT PRIMARY KEY,
    \\  app_id INTEGER NOT NULL REFERENCES oauth_apps(id) ON DELETE CASCADE,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  redirect_uri TEXT NOT NULL,
    \\  scopes TEXT NOT NULL,
    \\  created_at TEXT NOT NULL,
    \\  expires_at TEXT NOT NULL
    \\);
    \\
    \\CREATE INDEX IF NOT EXISTS oauth_auth_codes_user_id ON oauth_auth_codes(user_id);
    \\
    \\CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    \\  id INTEGER PRIMARY KEY,
    \\  token_hash BLOB NOT NULL UNIQUE,
    \\  app_id INTEGER NOT NULL REFERENCES oauth_apps(id) ON DELETE CASCADE,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  scopes TEXT NOT NULL,
    \\  created_at TEXT NOT NULL,
    \\  expires_at TEXT NOT NULL
    \\);
    \\
    \\CREATE INDEX IF NOT EXISTS oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
    ++ "\x00";

const statuses_v4_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS statuses (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  text TEXT NOT NULL,
    \\  visibility TEXT NOT NULL,
    \\  created_at TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS statuses_user_id_id ON statuses(user_id, id);
    ++ "\x00";

test "migrate: creates users table and records version" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try migrate(&conn);

    var table_stmt = try conn.prepareZ("SELECT name FROM sqlite_master WHERE type='table' AND name='users';\x00");
    defer table_stmt.finalize();

    try std.testing.expectEqual(db.Stmt.Step.row, try table_stmt.step());
    try std.testing.expectEqualStrings("users", table_stmt.columnText(0));
    try std.testing.expectEqual(db.Stmt.Step.done, try table_stmt.step());

    var v_stmt = try conn.prepareZ("SELECT version FROM schema_migrations ORDER BY version;\x00");
    defer v_stmt.finalize();

    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 1), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 2), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 3), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 4), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.done, try v_stmt.step());
}

test "migrate: is idempotent" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();

    try migrate(&conn);
    try migrate(&conn);

    var stmt = try conn.prepareZ("SELECT COUNT(*) FROM schema_migrations;\x00");
    defer stmt.finalize();

    try std.testing.expectEqual(db.Stmt.Step.row, try stmt.step());
    try std.testing.expectEqual(@as(i64, 4), stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.done, try stmt.step());
}

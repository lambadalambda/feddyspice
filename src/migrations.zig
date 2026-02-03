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
    .{
        .version = 5,
        .name = "create_actor_keys",
        .sql = actor_keys_v5_sql,
    },
    .{
        .version = 6,
        .name = "create_remote_actors_and_follows",
        .sql = remote_actors_and_follows_v6_sql,
    },
    .{
        .version = 7,
        .name = "create_remote_statuses",
        .sql = remote_statuses_v7_sql,
    },
    .{
        .version = 8,
        .name = "create_followers",
        .sql = followers_v8_sql,
    },
    .{
        .version = 9,
        .name = "add_deleted_at",
        .sql = deleted_at_v9_sql,
    },
    .{
        .version = 10,
        .name = "create_jobs",
        .sql = jobs_v10_sql,
    },
    .{
        .version = 11,
        .name = "create_inbox_dedupe",
        .sql = inbox_dedupe_v11_sql,
    },
    .{
        .version = 12,
        .name = "create_media",
        .sql = media_v12_sql,
    },
    .{
        .version = 13,
        .name = "media_public_token",
        .sql = media_public_token_v13_sql,
    },
    .{
        .version = 14,
        .name = "create_notifications",
        .sql = notifications_v14_sql,
    },
    .{
        .version = 15,
        .name = "remote_actor_profile_media",
        .sql = remote_actor_profile_media_v15_sql,
    },
    .{
        .version = 16,
        .name = "remote_status_attachments",
        .sql = remote_status_attachments_v16_sql,
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

const actor_keys_v5_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS actor_keys (
    \\  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    \\  private_key_pem TEXT NOT NULL,
    \\  public_key_pem TEXT NOT NULL,
    \\  created_at TEXT NOT NULL
    \\);
++ "\x00";

const remote_actors_and_follows_v6_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS remote_actors (
    \\  id TEXT PRIMARY KEY,
    \\  inbox TEXT NOT NULL,
    \\  shared_inbox TEXT,
    \\  preferred_username TEXT NOT NULL,
    \\  domain TEXT NOT NULL,
    \\  public_key_pem TEXT NOT NULL,
    \\  discovered_at TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS remote_actors_domain_username ON remote_actors(domain, preferred_username);
    \\
    \\CREATE TABLE IF NOT EXISTS follows (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  remote_actor_id TEXT NOT NULL REFERENCES remote_actors(id) ON DELETE CASCADE,
    \\  follow_activity_id TEXT NOT NULL UNIQUE,
    \\  state TEXT NOT NULL,
    \\  created_at TEXT NOT NULL,
    \\  updated_at TEXT NOT NULL
    \\);
    \\CREATE UNIQUE INDEX IF NOT EXISTS follows_user_remote_actor_id ON follows(user_id, remote_actor_id);
++ "\x00";

const remote_statuses_v7_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS remote_statuses (
    \\  id INTEGER PRIMARY KEY,
    \\  remote_uri TEXT NOT NULL UNIQUE,
    \\  remote_actor_id TEXT NOT NULL REFERENCES remote_actors(id) ON DELETE CASCADE,
    \\  content_html TEXT NOT NULL,
    \\  visibility TEXT NOT NULL,
    \\  created_at TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS remote_statuses_remote_actor_id_id ON remote_statuses(remote_actor_id, id);
++ "\x00";

const followers_v8_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS followers (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  remote_actor_id TEXT NOT NULL REFERENCES remote_actors(id) ON DELETE CASCADE,
    \\  follow_activity_id TEXT NOT NULL UNIQUE,
    \\  state TEXT NOT NULL,
    \\  created_at TEXT NOT NULL,
    \\  updated_at TEXT NOT NULL
    \\);
    \\CREATE UNIQUE INDEX IF NOT EXISTS followers_user_remote_actor_id ON followers(user_id, remote_actor_id);
++ "\x00";

const deleted_at_v9_sql: [:0]const u8 =
    \\ALTER TABLE statuses ADD COLUMN deleted_at TEXT;
    \\ALTER TABLE remote_statuses ADD COLUMN deleted_at TEXT;
    \\CREATE INDEX IF NOT EXISTS statuses_user_id_deleted_at ON statuses(user_id, deleted_at);
    \\CREATE INDEX IF NOT EXISTS remote_statuses_remote_actor_id_deleted_at ON remote_statuses(remote_actor_id, deleted_at);
++ "\x00";

const jobs_v10_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS jobs (
    \\  id INTEGER PRIMARY KEY,
    \\  type TEXT NOT NULL,
    \\  payload_json TEXT NOT NULL,
    \\  state TEXT NOT NULL,
    \\  run_at_ms INTEGER NOT NULL,
    \\  attempts INTEGER NOT NULL,
    \\  max_attempts INTEGER NOT NULL,
    \\  last_error TEXT,
    \\  locked_at_ms INTEGER,
    \\  dedupe_key TEXT UNIQUE,
    \\  created_at_ms INTEGER NOT NULL,
    \\  updated_at_ms INTEGER NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS jobs_state_run_at_ms ON jobs(state, run_at_ms);
    \\CREATE INDEX IF NOT EXISTS jobs_state_locked_at_ms ON jobs(state, locked_at_ms);
++ "\x00";

const inbox_dedupe_v11_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS inbox_dedupe (
    \\  activity_id TEXT PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  actor_id TEXT NOT NULL,
    \\  received_at_ms INTEGER NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS inbox_dedupe_user_id_received_at_ms ON inbox_dedupe(user_id, received_at_ms);
++ "\x00";

const media_v12_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS media_attachments (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  content_type TEXT NOT NULL,
    \\  data BLOB NOT NULL,
    \\  description TEXT,
    \\  created_at_ms INTEGER NOT NULL,
    \\  updated_at_ms INTEGER NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS media_attachments_user_id_created_at_ms ON media_attachments(user_id, created_at_ms);
    \\
    \\CREATE TABLE IF NOT EXISTS status_media_attachments (
    \\  status_id INTEGER NOT NULL REFERENCES statuses(id) ON DELETE CASCADE,
    \\  media_id INTEGER NOT NULL REFERENCES media_attachments(id) ON DELETE CASCADE,
    \\  position INTEGER NOT NULL,
    \\  PRIMARY KEY(status_id, media_id),
    \\  UNIQUE(media_id)
    \\);
    \\CREATE INDEX IF NOT EXISTS status_media_attachments_media_id ON status_media_attachments(media_id);
++ "\x00";

const media_public_token_v13_sql: [:0]const u8 =
    \\ALTER TABLE media_attachments ADD COLUMN public_token TEXT;
    \\UPDATE media_attachments
    \\SET public_token = lower(hex(randomblob(16)))
    \\WHERE public_token IS NULL;
    \\CREATE UNIQUE INDEX IF NOT EXISTS media_attachments_public_token ON media_attachments(public_token);
++ "\x00";

const notifications_v14_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS notifications (
    \\  id INTEGER PRIMARY KEY,
    \\  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\  type TEXT NOT NULL,
    \\  actor_id TEXT NOT NULL REFERENCES remote_actors(id) ON DELETE CASCADE,
    \\  status_id INTEGER,
    \\  created_at TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS notifications_user_id_id ON notifications(user_id, id);
++ "\x00";

const remote_actor_profile_media_v15_sql: [:0]const u8 =
    \\ALTER TABLE remote_actors ADD COLUMN avatar_url TEXT;
    \\ALTER TABLE remote_actors ADD COLUMN header_url TEXT;
++ "\x00";

const remote_status_attachments_v16_sql: [:0]const u8 =
    \\ALTER TABLE remote_statuses ADD COLUMN attachments_json TEXT;
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
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 5), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 6), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 7), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 8), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 9), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 10), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 11), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 12), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 13), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 14), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 15), v_stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.row, try v_stmt.step());
    try std.testing.expectEqual(@as(i64, 16), v_stmt.columnInt64(0));
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
    try std.testing.expectEqual(@as(i64, 16), stmt.columnInt64(0));
    try std.testing.expectEqual(db.Stmt.Step.done, try stmt.step());
}

const std = @import("std");

const db = @import("db.zig");
const migrations = @import("migrations.zig");

pub const Error = db.Error;

pub fn allowNow(conn: *db.Db, key: []const u8, window_ms: i64, limit: i64) Error!bool {
    return allow(conn, key, std.time.milliTimestamp(), window_ms, limit);
}

pub fn allow(conn: *db.Db, key: []const u8, now_ms: i64, window_ms: i64, limit: i64) Error!bool {
    if (window_ms <= 0) return true;
    if (limit <= 0) return false;

    var sel = try conn.prepareZ(
        "SELECT window_start_ms, count FROM rate_limits WHERE key=?1 LIMIT 1;\x00",
    );
    defer sel.finalize();
    try sel.bindText(1, key);

    switch (try sel.step()) {
        .done => {
            var ins = try conn.prepareZ(
                "INSERT INTO rate_limits(key, window_start_ms, count) VALUES (?1, ?2, ?3);\x00",
            );
            defer ins.finalize();
            try ins.bindText(1, key);
            try ins.bindInt64(2, now_ms);
            try ins.bindInt64(3, 1);
            _ = try ins.step();
            return true;
        },
        .row => {},
    }

    const start_ms = sel.columnInt64(0);
    const count = sel.columnInt64(1);

    const elapsed = now_ms - start_ms;
    if (elapsed < 0 or elapsed >= window_ms) {
        var reset = try conn.prepareZ(
            "UPDATE rate_limits SET window_start_ms=?2, count=1 WHERE key=?1;\x00",
        );
        defer reset.finalize();
        try reset.bindText(1, key);
        try reset.bindInt64(2, now_ms);
        _ = try reset.step();
        return true;
    }

    if (count >= limit) return false;

    var bump = try conn.prepareZ(
        "UPDATE rate_limits SET count = count + 1 WHERE key=?1;\x00",
    );
    defer bump.finalize();
    try bump.bindText(1, key);
    _ = try bump.step();
    return true;
}

test "rate_limit: allow increments and denies within window" {
    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    const key = "login";
    const window_ms: i64 = 1000;

    try std.testing.expect(try allow(&conn, key, 0, window_ms, 2));
    try std.testing.expect(try allow(&conn, key, 1, window_ms, 2));
    try std.testing.expect(!try allow(&conn, key, 2, window_ms, 2));

    // After window, allow again.
    try std.testing.expect(try allow(&conn, key, 1000, window_ms, 2));
    try std.testing.expect(try allow(&conn, key, 1001, window_ms, 2));
    try std.testing.expect(!try allow(&conn, key, 1002, window_ms, 2));
}

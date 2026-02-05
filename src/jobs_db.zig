const std = @import("std");

const db = @import("db.zig");
const jobs = @import("jobs.zig");

pub const Error =
    db.Error ||
    std.mem.Allocator.Error ||
    error{
        InvalidPayload,
        UnknownJobType,
    };

pub const ClaimedJob = struct {
    id: i64,
    attempts: i64,
    max_attempts: i64,
    job: jobs.Job,

    pub fn deinit(self: *ClaimedJob, allocator: std.mem.Allocator) void {
        self.job.deinit(allocator);
        self.* = undefined;
    }
};

pub const EnqueueOptions = struct {
    /// Optional unique key to suppress duplicate jobs.
    dedupe_key: ?[]const u8 = null,
    max_attempts: i64 = 10,
    run_at_ms: ?i64 = null,
    now_ms: ?i64 = null,
};

pub fn enqueue(conn: *db.Db, allocator: std.mem.Allocator, job: jobs.Job, opts: EnqueueOptions) Error!bool {
    const now_ms: i64 = opts.now_ms orelse std.time.milliTimestamp();
    const run_at_ms: i64 = opts.run_at_ms orelse now_ms;

    const encoded = try encodeJob(allocator, job);
    defer allocator.free(encoded.payload_json);
    defer if (encoded.dedupe_key) |k| allocator.free(k);

    const dedupe_key = opts.dedupe_key orelse encoded.dedupe_key;

    var stmt = try conn.prepareZ(
        "INSERT INTO jobs(type, payload_json, state, run_at_ms, attempts, max_attempts, last_error, locked_at_ms, dedupe_key, created_at_ms, updated_at_ms)\n" ++
            "VALUES (?1, ?2, 'queued', ?3, 0, ?4, NULL, NULL, ?5, ?6, ?6)\n" ++
            "ON CONFLICT(dedupe_key) DO NOTHING;\x00",
    );
    defer stmt.finalize();

    try stmt.bindText(1, encoded.job_type);
    try stmt.bindText(2, encoded.payload_json);
    try stmt.bindInt64(3, run_at_ms);
    try stmt.bindInt64(4, opts.max_attempts);
    if (dedupe_key) |k| {
        try stmt.bindText(5, k);
    } else {
        try stmt.bindNull(5);
    }
    try stmt.bindInt64(6, now_ms);

    switch (try stmt.step()) {
        .done => {},
        .row => return error.InvalidPayload,
    }

    return conn.changes() > 0;
}

pub const ClaimOptions = struct {
    now_ms: i64,
    lock_timeout_ms: i64 = 60_000,
};

pub fn claimNext(conn: *db.Db, allocator: std.mem.Allocator, opts: ClaimOptions) Error!?ClaimedJob {
    try conn.execZ("BEGIN IMMEDIATE;\x00");
    errdefer conn.execZ("ROLLBACK;\x00") catch {};

    const stale_before_ms: i64 = opts.now_ms - opts.lock_timeout_ms;
    {
        var release = try conn.prepareZ(
            "UPDATE jobs\n" ++
                "SET state='queued', locked_at_ms=NULL, run_at_ms=?1, updated_at_ms=?1\n" ++
                "WHERE state='running' AND locked_at_ms IS NOT NULL AND locked_at_ms <= ?2;\x00",
        );
        defer release.finalize();
        try release.bindInt64(1, opts.now_ms);
        try release.bindInt64(2, stale_before_ms);
        _ = try release.step();
    }

    var stmt = try conn.prepareZ(
        "SELECT id, type, payload_json, attempts, max_attempts\n" ++
            "FROM jobs\n" ++
            "WHERE state='queued' AND run_at_ms <= ?1\n" ++
            "ORDER BY run_at_ms ASC, id ASC\n" ++
            "LIMIT 1;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, opts.now_ms);

    const step = try stmt.step();
    if (step == .done) {
        try conn.execZ("COMMIT;\x00");
        return null;
    }

    const id = stmt.columnInt64(0);
    const typ = stmt.columnText(1);
    const payload = stmt.columnText(2);
    const attempts = stmt.columnInt64(3);
    const max_attempts = stmt.columnInt64(4);

    {
        var upd = try conn.prepareZ(
            "UPDATE jobs SET state='running', locked_at_ms=?1, updated_at_ms=?1 WHERE id=?2;\x00",
        );
        defer upd.finalize();
        try upd.bindInt64(1, opts.now_ms);
        try upd.bindInt64(2, id);
        _ = try upd.step();
    }

    try conn.execZ("COMMIT;\x00");

    const decoded = try decodeJob(allocator, typ, payload);
    return .{
        .id = id,
        .attempts = attempts,
        .max_attempts = max_attempts,
        .job = decoded,
    };
}

pub fn finishSuccess(conn: *db.Db, id: i64) Error!void {
    var stmt = try conn.prepareZ("DELETE FROM jobs WHERE id=?1;\x00");
    defer stmt.finalize();
    try stmt.bindInt64(1, id);
    _ = try stmt.step();
}

pub fn finishFailure(
    conn: *db.Db,
    id: i64,
    attempts: i64,
    max_attempts: i64,
    err: anyerror,
    now_ms: i64,
) Error!void {
    const new_attempts = attempts + 1;
    const err_name = @errorName(err);

    if (new_attempts >= max_attempts) {
        var stmt = try conn.prepareZ(
            "UPDATE jobs SET state='dead', attempts=?1, last_error=?2, locked_at_ms=NULL, updated_at_ms=?3 WHERE id=?4;\x00",
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, new_attempts);
        try stmt.bindText(2, err_name);
        try stmt.bindInt64(3, now_ms);
        try stmt.bindInt64(4, id);
        _ = try stmt.step();
        return;
    }

    const delay_ms = backoffMs(new_attempts);
    const next_run_ms = now_ms + delay_ms;

    var stmt = try conn.prepareZ(
        "UPDATE jobs\n" ++
            "SET state='queued', run_at_ms=?1, attempts=?2, last_error=?3, locked_at_ms=NULL, updated_at_ms=?4\n" ++
            "WHERE id=?5;\x00",
    );
    defer stmt.finalize();
    try stmt.bindInt64(1, next_run_ms);
    try stmt.bindInt64(2, new_attempts);
    try stmt.bindText(3, err_name);
    try stmt.bindInt64(4, now_ms);
    try stmt.bindInt64(5, id);
    _ = try stmt.step();
}

pub fn backoffMs(attempt: i64) i64 {
    if (attempt <= 0) return 0;
    const base_ms: i64 = 1000;
    const max_ms: i64 = 5 * 60 * 1000;

    const shift: u6 = @intCast(@min(@as(i64, 10), attempt - 1));
    const raw = base_ms << shift;
    return @min(raw, max_ms);
}

const EncodedJob = struct {
    job_type: []const u8,
    payload_json: []u8,
    dedupe_key: ?[]u8,
};

fn encodeJob(allocator: std.mem.Allocator, job: jobs.Job) Error!EncodedJob {
    switch (job) {
        .send_follow => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .follow_activity_id = j.follow_activity_id };
            return .{
                .job_type = "send_follow",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_follow:{d}:{s}", .{ j.user_id, j.remote_actor_id }),
            };
        },
        .send_undo_follow => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .follow_activity_id = j.follow_activity_id };
            return .{
                .job_type = "send_undo_follow",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_undo_follow:{d}:{s}", .{ j.user_id, j.remote_actor_id }),
            };
        },
        .send_like => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .remote_status_uri = j.remote_status_uri };
            return .{
                .job_type = "send_like",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_like:{d}:{s}", .{ j.user_id, j.remote_status_uri }),
            };
        },
        .send_undo_like => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .remote_status_uri = j.remote_status_uri };
            return .{
                .job_type = "send_undo_like",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_undo_like:{d}:{s}", .{ j.user_id, j.remote_status_uri }),
            };
        },
        .send_announce => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .remote_status_uri = j.remote_status_uri };
            return .{
                .job_type = "send_announce",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_announce:{d}:{s}", .{ j.user_id, j.remote_status_uri }),
            };
        },
        .send_undo_announce => |j| {
            const payload = .{ .user_id = j.user_id, .remote_actor_id = j.remote_actor_id, .remote_status_uri = j.remote_status_uri };
            return .{
                .job_type = "send_undo_announce",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "send_undo_announce:{d}:{s}", .{ j.user_id, j.remote_status_uri }),
            };
        },
        .accept_inbound_follow => |j| {
            const payload = .{
                .user_id = j.user_id,
                .username = j.username,
                .remote_actor_id = j.remote_actor_id,
                .remote_follow_activity_id = j.remote_follow_activity_id,
            };
            return .{
                .job_type = "accept_inbound_follow",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "accept_inbound_follow:{d}:{s}", .{ j.user_id, j.remote_follow_activity_id }),
            };
        },
        .deliver_actor_update => |j| {
            const payload = .{ .user_id = j.user_id };
            return .{
                .job_type = "deliver_actor_update",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "deliver_actor_update:{d}", .{j.user_id}),
            };
        },
        .deliver_status => |j| {
            const payload = .{ .user_id = j.user_id, .status_id = j.status_id };
            return .{
                .job_type = "deliver_status",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "deliver_status:{d}", .{j.status_id}),
            };
        },
        .deliver_delete => |j| {
            const payload = .{ .user_id = j.user_id, .status_id = j.status_id };
            return .{
                .job_type = "deliver_delete",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "deliver_delete:{d}", .{j.status_id}),
            };
        },
        .backfill_thread => |j| {
            const payload = .{ .user_id = j.user_id, .status_id = j.status_id, .in_reply_to_uri = j.in_reply_to_uri };
            return .{
                .job_type = "backfill_thread",
                .payload_json = try std.json.Stringify.valueAlloc(allocator, payload, .{}),
                .dedupe_key = try std.fmt.allocPrint(allocator, "backfill_thread:{d}", .{j.status_id}),
            };
        },
    }
}

fn decodeJob(allocator: std.mem.Allocator, job_type: []const u8, payload_json: []const u8) Error!jobs.Job {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPayload,
    };
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidPayload;
    const o = parsed.value.object;

    if (std.mem.eql(u8, job_type, "send_follow")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const follow_activity_id_val = o.get("follow_activity_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (follow_activity_id_val != .string) return error.InvalidPayload;

        return .{
            .send_follow = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .follow_activity_id = try allocator.dupe(u8, follow_activity_id_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "send_undo_follow")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const follow_activity_id_val = o.get("follow_activity_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (follow_activity_id_val != .string) return error.InvalidPayload;

        return .{
            .send_undo_follow = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .follow_activity_id = try allocator.dupe(u8, follow_activity_id_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "send_like")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const remote_status_uri_val = o.get("remote_status_uri") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (remote_status_uri_val != .string) return error.InvalidPayload;

        return .{
            .send_like = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .remote_status_uri = try allocator.dupe(u8, remote_status_uri_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "send_undo_like")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const remote_status_uri_val = o.get("remote_status_uri") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (remote_status_uri_val != .string) return error.InvalidPayload;

        return .{
            .send_undo_like = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .remote_status_uri = try allocator.dupe(u8, remote_status_uri_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "send_announce")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const remote_status_uri_val = o.get("remote_status_uri") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (remote_status_uri_val != .string) return error.InvalidPayload;

        return .{
            .send_announce = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .remote_status_uri = try allocator.dupe(u8, remote_status_uri_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "send_undo_announce")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const remote_status_uri_val = o.get("remote_status_uri") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (remote_status_uri_val != .string) return error.InvalidPayload;

        return .{
            .send_undo_announce = .{
                .user_id = user_id_val.integer,
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .remote_status_uri = try allocator.dupe(u8, remote_status_uri_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "accept_inbound_follow")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const username_val = o.get("username") orelse return error.InvalidPayload;
        const remote_actor_id_val = o.get("remote_actor_id") orelse return error.InvalidPayload;
        const remote_follow_activity_id_val = o.get("remote_follow_activity_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (username_val != .string) return error.InvalidPayload;
        if (remote_actor_id_val != .string) return error.InvalidPayload;
        if (remote_follow_activity_id_val != .string) return error.InvalidPayload;

        return .{
            .accept_inbound_follow = .{
                .user_id = user_id_val.integer,
                .username = try allocator.dupe(u8, username_val.string),
                .remote_actor_id = try allocator.dupe(u8, remote_actor_id_val.string),
                .remote_follow_activity_id = try allocator.dupe(u8, remote_follow_activity_id_val.string),
            },
        };
    }

    if (std.mem.eql(u8, job_type, "deliver_actor_update")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        return .{ .deliver_actor_update = .{ .user_id = user_id_val.integer } };
    }

    if (std.mem.eql(u8, job_type, "deliver_status")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const status_id_val = o.get("status_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (status_id_val != .integer) return error.InvalidPayload;

        return .{ .deliver_status = .{ .user_id = user_id_val.integer, .status_id = status_id_val.integer } };
    }

    if (std.mem.eql(u8, job_type, "deliver_delete")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const status_id_val = o.get("status_id") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (status_id_val != .integer) return error.InvalidPayload;

        return .{ .deliver_delete = .{ .user_id = user_id_val.integer, .status_id = status_id_val.integer } };
    }

    if (std.mem.eql(u8, job_type, "backfill_thread")) {
        const user_id_val = o.get("user_id") orelse return error.InvalidPayload;
        const status_id_val = o.get("status_id") orelse return error.InvalidPayload;
        const in_reply_to_uri_val = o.get("in_reply_to_uri") orelse return error.InvalidPayload;
        if (user_id_val != .integer) return error.InvalidPayload;
        if (status_id_val != .integer) return error.InvalidPayload;
        if (in_reply_to_uri_val != .string) return error.InvalidPayload;

        return .{
            .backfill_thread = .{
                .user_id = user_id_val.integer,
                .status_id = status_id_val.integer,
                .in_reply_to_uri = try allocator.dupe(u8, in_reply_to_uri_val.string),
            },
        };
    }

    return error.UnknownJobType;
}

test "jobs_db: enqueue + claim + success deletes job" {
    const allocator = std.testing.allocator;
    const migrations = @import("migrations.zig");

    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    const now_ms: i64 = 1_000_000;

    const enq = try enqueue(&conn, allocator, .{ .deliver_status = .{ .user_id = 1, .status_id = 2 } }, .{
        .now_ms = now_ms,
        .run_at_ms = now_ms,
        .max_attempts = 3,
    });
    try std.testing.expect(enq);

    var claimed = (try claimNext(&conn, allocator, .{ .now_ms = now_ms })).?;
    defer claimed.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 0), claimed.attempts);
    try std.testing.expectEqual(@as(i64, 3), claimed.max_attempts);
    try std.testing.expect(claimed.job == .deliver_status);
    try std.testing.expectEqual(@as(i64, 1), claimed.job.deliver_status.user_id);
    try std.testing.expectEqual(@as(i64, 2), claimed.job.deliver_status.status_id);

    try finishSuccess(&conn, claimed.id);

    var check = try conn.prepareZ("SELECT COUNT(*) FROM jobs;\x00");
    defer check.finalize();
    try std.testing.expectEqual(db.Stmt.Step.row, try check.step());
    try std.testing.expectEqual(@as(i64, 0), check.columnInt64(0));
}

test "jobs_db: enqueue dedupe_key suppresses duplicates" {
    const allocator = std.testing.allocator;
    const migrations = @import("migrations.zig");

    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    const now_ms: i64 = 1_000_000;
    const job: jobs.Job = .{ .deliver_status = .{ .user_id = 1, .status_id = 2 } };

    try std.testing.expect(try enqueue(&conn, allocator, job, .{ .now_ms = now_ms, .run_at_ms = now_ms, .max_attempts = 3 }));
    try std.testing.expect(!try enqueue(&conn, allocator, job, .{ .now_ms = now_ms, .run_at_ms = now_ms, .max_attempts = 3 }));

    var check = try conn.prepareZ("SELECT COUNT(*) FROM jobs;\x00");
    defer check.finalize();
    try std.testing.expectEqual(db.Stmt.Step.row, try check.step());
    try std.testing.expectEqual(@as(i64, 1), check.columnInt64(0));
}

test "jobs_db: failure reschedules with backoff" {
    const allocator = std.testing.allocator;
    const migrations = @import("migrations.zig");

    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    const now_ms: i64 = 1_000_000;

    _ = try enqueue(&conn, allocator, .{ .deliver_delete = .{ .user_id = 1, .status_id = 2 } }, .{
        .now_ms = now_ms,
        .run_at_ms = now_ms,
        .max_attempts = 3,
    });

    var claimed = (try claimNext(&conn, allocator, .{ .now_ms = now_ms })).?;
    defer claimed.deinit(allocator);

    try finishFailure(&conn, claimed.id, claimed.attempts, claimed.max_attempts, error.NetworkDisabled, now_ms);

    // Not ready yet at the original time.
    try std.testing.expect((try claimNext(&conn, allocator, .{ .now_ms = now_ms })) == null);

    const later = now_ms + backoffMs(1);
    var claimed2 = (try claimNext(&conn, allocator, .{ .now_ms = later })).?;
    defer claimed2.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 1), claimed2.attempts);
    try std.testing.expect(claimed2.job == .deliver_delete);
}

test "jobs_db: max_attempts marks job dead" {
    const allocator = std.testing.allocator;
    const migrations = @import("migrations.zig");

    var conn = try db.Db.openZ(":memory:");
    defer conn.close();
    try migrations.migrate(&conn);

    const now_ms: i64 = 1_000_000;

    _ = try enqueue(&conn, allocator, .{ .deliver_status = .{ .user_id = 1, .status_id = 2 } }, .{
        .now_ms = now_ms,
        .run_at_ms = now_ms,
        .max_attempts = 1,
    });

    var claimed = (try claimNext(&conn, allocator, .{ .now_ms = now_ms })).?;
    defer claimed.deinit(allocator);

    try finishFailure(&conn, claimed.id, claimed.attempts, claimed.max_attempts, error.NetworkDisabled, now_ms);

    try std.testing.expect((try claimNext(&conn, allocator, .{ .now_ms = now_ms + 999_999 })) == null);

    var check = try conn.prepareZ("SELECT state, attempts FROM jobs;\x00");
    defer check.finalize();
    try std.testing.expectEqual(db.Stmt.Step.row, try check.step());
    try std.testing.expectEqualStrings("dead", check.columnText(0));
    try std.testing.expectEqual(@as(i64, 1), check.columnInt64(1));
}

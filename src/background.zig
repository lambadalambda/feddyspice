const std = @import("std");

const app = @import("app.zig");
const config = @import("config.zig");
const db = @import("db.zig");
const federation = @import("federation.zig");
const log = @import("log.zig");
const statuses = @import("statuses.zig");
const users = @import("users.zig");

fn isInMemory(app_state: *app.App) bool {
    return std.mem.eql(u8, app_state.cfg.db_path, ":memory:");
}

pub fn sendFollow(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) void {
    if (isInMemory(app_state)) {
        federation.sendFollowActivity(app_state, allocator, user_id, remote_actor_id, follow_activity_id) catch {};
        return;
    }

    const job = std.heap.page_allocator.create(SendFollowJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    const remote_actor_id_copy = std.heap.page_allocator.dupe(u8, remote_actor_id) catch return;
    errdefer std.heap.page_allocator.free(remote_actor_id_copy);

    const follow_activity_id_copy = std.heap.page_allocator.dupe(u8, follow_activity_id) catch return;
    errdefer std.heap.page_allocator.free(follow_activity_id_copy);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .remote_actor_id = remote_actor_id_copy,
        .follow_activity_id = follow_activity_id_copy,
    };

    var t = std.Thread.spawn(.{}, SendFollowJob.run, .{job}) catch return;
    t.detach();
}

pub fn acceptInboundFollow(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    username: []const u8,
    remote_actor_id: []const u8,
    remote_follow_activity_id: []const u8,
) void {
    if (isInMemory(app_state)) {
        federation.acceptInboundFollow(app_state, allocator, user_id, username, remote_actor_id, remote_follow_activity_id) catch {};
        return;
    }

    const job = std.heap.page_allocator.create(AcceptInboundFollowJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    const username_copy = std.heap.page_allocator.dupe(u8, username) catch return;
    errdefer std.heap.page_allocator.free(username_copy);

    const remote_actor_id_copy = std.heap.page_allocator.dupe(u8, remote_actor_id) catch return;
    errdefer std.heap.page_allocator.free(remote_actor_id_copy);

    const follow_id_copy = std.heap.page_allocator.dupe(u8, remote_follow_activity_id) catch return;
    errdefer std.heap.page_allocator.free(follow_id_copy);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .username = username_copy,
        .remote_actor_id = remote_actor_id_copy,
        .remote_follow_activity_id = follow_id_copy,
    };

    var t = std.Thread.spawn(.{}, AcceptInboundFollowJob.run, .{job}) catch return;
    t.detach();
}

pub fn deliverStatusToFollowers(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
) void {
    app_state.logger.debug("deliverStatusToFollowers: in_memory={any} user_id={d} status_id={d}", .{ isInMemory(app_state), user_id, status_id });
    if (isInMemory(app_state)) {
        const user = users.lookupUserById(&app_state.conn, allocator, user_id) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: user lookup err={any}", .{err});
            return;
        };
        if (user == null) return;
        const st = statuses.lookup(&app_state.conn, allocator, status_id) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: status lookup err={any}", .{err});
            return;
        };
        if (st == null) return;
        federation.deliverStatusToFollowers(app_state, allocator, user.?, st.?) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: delivery failed err={any}", .{err});
        };
        return;
    }

    const job = std.heap.page_allocator.create(DeliverStatusJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .status_id = status_id,
    };

    var t = std.Thread.spawn(.{}, DeliverStatusJob.run, .{job}) catch return;
    t.detach();
}

pub fn deliverDeleteToFollowers(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
) void {
    if (isInMemory(app_state)) {
        const user = users.lookupUserById(&app_state.conn, allocator, user_id) catch null;
        if (user == null) return;
        const st = statuses.lookupIncludingDeleted(&app_state.conn, allocator, status_id) catch null;
        if (st == null) return;
        if (st.?.deleted_at == null) return;
        federation.deliverDeleteToFollowers(app_state, allocator, user.?, st.?) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: delivery failed err={any}", .{err});
        };
        return;
    }

    const job = std.heap.page_allocator.create(DeliverDeleteJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .status_id = status_id,
    };

    var t = std.Thread.spawn(.{}, DeliverDeleteJob.run, .{job}) catch return;
    t.detach();
}

const SendFollowJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    remote_actor_id: []u8,
    follow_activity_id: []u8,

    fn run(job: *@This()) void {
        defer {
            std.heap.page_allocator.free(job.remote_actor_id);
            std.heap.page_allocator.free(job.follow_activity_id);
            std.heap.page_allocator.destroy(job);
        }

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
        };

        federation.sendFollowActivity(&thread_app, a, job.user_id, job.remote_actor_id, job.follow_activity_id) catch {};
    }
};

const AcceptInboundFollowJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    username: []u8,
    remote_actor_id: []u8,
    remote_follow_activity_id: []u8,

    fn run(job: *@This()) void {
        defer {
            std.heap.page_allocator.free(job.username);
            std.heap.page_allocator.free(job.remote_actor_id);
            std.heap.page_allocator.free(job.remote_follow_activity_id);
            std.heap.page_allocator.destroy(job);
        }

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
        };

        federation.acceptInboundFollow(
            &thread_app,
            a,
            job.user_id,
            job.username,
            job.remote_actor_id,
            job.remote_follow_activity_id,
        ) catch {};
    }
};

const DeliverStatusJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    status_id: i64,

    fn run(job: *@This()) void {
        defer std.heap.page_allocator.destroy(job);

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
        };

        const user = users.lookupUserById(&thread_app.conn, a, job.user_id) catch null;
        if (user == null) return;
        const st = statuses.lookup(&thread_app.conn, a, job.status_id) catch null;
        if (st == null) return;

        federation.deliverStatusToFollowers(&thread_app, a, user.?, st.?) catch {};
    }
};

const DeliverDeleteJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    status_id: i64,

    fn run(job: *@This()) void {
        defer std.heap.page_allocator.destroy(job);

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
        };

        const user = users.lookupUserById(&thread_app.conn, a, job.user_id) catch null;
        if (user == null) return;
        const st = statuses.lookupIncludingDeleted(&thread_app.conn, a, job.status_id) catch null;
        if (st == null) return;
        if (st.?.deleted_at == null) return;

        federation.deliverDeleteToFollowers(&thread_app, a, user.?, st.?) catch {};
    }
};

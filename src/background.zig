const std = @import("std");

const app = @import("app.zig");
const config = @import("config.zig");
const db = @import("db.zig");
const federation = @import("federation.zig");
const jobs = @import("jobs.zig");
const log = @import("log.zig");
const statuses = @import("statuses.zig");
const users = @import("users.zig");
const transport = @import("transport.zig");
const jobs_db = @import("jobs_db.zig");
const streaming_hub = @import("streaming_hub.zig");

pub const RunError = federation.Error || statuses.Error;

pub fn runJob(app_state: *app.App, allocator: std.mem.Allocator, job: jobs.Job) RunError!void {
    switch (job) {
        .send_follow => |j| {
            try federation.sendFollowActivity(app_state, allocator, j.user_id, j.remote_actor_id, j.follow_activity_id);
        },
        .send_undo_follow => |j| {
            try federation.sendUndoFollowActivity(app_state, allocator, j.user_id, j.remote_actor_id, j.follow_activity_id);
        },
        .send_like => |j| {
            try federation.sendLikeActivity(app_state, allocator, j.user_id, j.remote_actor_id, j.remote_status_uri);
        },
        .send_undo_like => |j| {
            try federation.sendUndoLikeActivity(app_state, allocator, j.user_id, j.remote_actor_id, j.remote_status_uri);
        },
        .accept_inbound_follow => |j| {
            try federation.acceptInboundFollow(
                app_state,
                allocator,
                j.user_id,
                j.username,
                j.remote_actor_id,
                j.remote_follow_activity_id,
            );
        },
        .deliver_status => |j| {
            const user = users.lookupUserById(&app_state.conn, allocator, j.user_id) catch return;
            if (user == null) return;
            const st = statuses.lookup(&app_state.conn, allocator, j.status_id) catch return;
            if (st == null) return;
            try federation.deliverStatusToFollowers(app_state, allocator, user.?, st.?);
        },
        .deliver_delete => |j| {
            const user = users.lookupUserById(&app_state.conn, allocator, j.user_id) catch return;
            if (user == null) return;
            const st = statuses.lookupIncludingDeleted(&app_state.conn, allocator, j.status_id) catch return;
            if (st == null) return;
            if (st.?.deleted_at == null) return;
            try federation.deliverDeleteToFollowers(app_state, allocator, user.?, st.?);
        },
    }
}

pub fn sendFollow(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            federation.sendFollowActivity(app_state, allocator, user_id, remote_actor_id, follow_activity_id) catch |err| {
                app_state.logger.err("sendFollow: sync deliver failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
            };
            return;
        },
        .disabled => {
            const remote_actor_id_copy = app_state.allocator.dupe(u8, remote_actor_id) catch return;
            errdefer app_state.allocator.free(remote_actor_id_copy);
            const follow_activity_id_copy = app_state.allocator.dupe(u8, follow_activity_id) catch return;
            errdefer app_state.allocator.free(follow_activity_id_copy);
            app_state.jobs_queue.push(app_state.allocator, .{
                .send_follow = .{
                    .user_id = user_id,
                    .remote_actor_id = remote_actor_id_copy,
                    .follow_activity_id = follow_activity_id_copy,
                },
            }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{
        .send_follow = .{
            .user_id = user_id,
            .remote_actor_id = @constCast(remote_actor_id),
            .follow_activity_id = @constCast(follow_activity_id),
        },
    }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("sendFollow: enqueue failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
        // Fallback to per-job thread execution.
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

    var t = std.Thread.spawn(.{}, SendFollowJob.run, .{job}) catch |err| {
        app_state.logger.err("sendFollow: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn sendUndoFollow(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            federation.sendUndoFollowActivity(app_state, allocator, user_id, remote_actor_id, follow_activity_id) catch |err| {
                app_state.logger.err("sendUndoFollow: sync deliver failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
            };
            return;
        },
        .disabled => {
            const remote_actor_id_copy = app_state.allocator.dupe(u8, remote_actor_id) catch return;
            errdefer app_state.allocator.free(remote_actor_id_copy);
            const follow_activity_id_copy = app_state.allocator.dupe(u8, follow_activity_id) catch return;
            errdefer app_state.allocator.free(follow_activity_id_copy);
            app_state.jobs_queue.push(app_state.allocator, .{
                .send_undo_follow = .{
                    .user_id = user_id,
                    .remote_actor_id = remote_actor_id_copy,
                    .follow_activity_id = follow_activity_id_copy,
                },
            }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{
        .send_undo_follow = .{
            .user_id = user_id,
            .remote_actor_id = @constCast(remote_actor_id),
            .follow_activity_id = @constCast(follow_activity_id),
        },
    }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("sendUndoFollow: enqueue failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
        // Fallback to per-job thread execution.
    }

    const job = std.heap.page_allocator.create(SendUndoFollowJob) catch return;
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

    var t = std.Thread.spawn(.{}, SendUndoFollowJob.run, .{job}) catch |err| {
        app_state.logger.err("sendUndoFollow: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn sendLike(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            federation.sendLikeActivity(app_state, allocator, user_id, remote_actor_id, remote_status_uri) catch |err| {
                app_state.logger.err("sendLike: sync deliver failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
            };
            return;
        },
        .disabled => {
            const remote_actor_id_copy = app_state.allocator.dupe(u8, remote_actor_id) catch return;
            errdefer app_state.allocator.free(remote_actor_id_copy);
            const remote_status_uri_copy = app_state.allocator.dupe(u8, remote_status_uri) catch return;
            errdefer app_state.allocator.free(remote_status_uri_copy);
            app_state.jobs_queue.push(app_state.allocator, .{
                .send_like = .{
                    .user_id = user_id,
                    .remote_actor_id = remote_actor_id_copy,
                    .remote_status_uri = remote_status_uri_copy,
                },
            }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{
        .send_like = .{
            .user_id = user_id,
            .remote_actor_id = @constCast(remote_actor_id),
            .remote_status_uri = @constCast(remote_status_uri),
        },
    }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("sendLike: enqueue failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
        // Fallback to per-job thread execution.
    }

    const job = std.heap.page_allocator.create(SendLikeJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    const remote_actor_id_copy = std.heap.page_allocator.dupe(u8, remote_actor_id) catch return;
    errdefer std.heap.page_allocator.free(remote_actor_id_copy);

    const remote_status_uri_copy = std.heap.page_allocator.dupe(u8, remote_status_uri) catch return;
    errdefer std.heap.page_allocator.free(remote_status_uri_copy);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .remote_actor_id = remote_actor_id_copy,
        .remote_status_uri = remote_status_uri_copy,
    };

    var t = std.Thread.spawn(.{}, SendLikeJob.run, .{job}) catch |err| {
        app_state.logger.err("sendLike: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn sendUndoLike(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            federation.sendUndoLikeActivity(app_state, allocator, user_id, remote_actor_id, remote_status_uri) catch |err| {
                app_state.logger.err("sendUndoLike: sync deliver failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
            };
            return;
        },
        .disabled => {
            const remote_actor_id_copy = app_state.allocator.dupe(u8, remote_actor_id) catch return;
            errdefer app_state.allocator.free(remote_actor_id_copy);
            const remote_status_uri_copy = app_state.allocator.dupe(u8, remote_status_uri) catch return;
            errdefer app_state.allocator.free(remote_status_uri_copy);
            app_state.jobs_queue.push(app_state.allocator, .{
                .send_undo_like = .{
                    .user_id = user_id,
                    .remote_actor_id = remote_actor_id_copy,
                    .remote_status_uri = remote_status_uri_copy,
                },
            }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{
        .send_undo_like = .{
            .user_id = user_id,
            .remote_actor_id = @constCast(remote_actor_id),
            .remote_status_uri = @constCast(remote_status_uri),
        },
    }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("sendUndoLike: enqueue failed remote_actor_id={s} err={any}", .{ remote_actor_id, err });
        // Fallback to per-job thread execution.
    }

    const job = std.heap.page_allocator.create(SendUndoLikeJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    const remote_actor_id_copy = std.heap.page_allocator.dupe(u8, remote_actor_id) catch return;
    errdefer std.heap.page_allocator.free(remote_actor_id_copy);

    const remote_status_uri_copy = std.heap.page_allocator.dupe(u8, remote_status_uri) catch return;
    errdefer std.heap.page_allocator.free(remote_status_uri_copy);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .remote_actor_id = remote_actor_id_copy,
        .remote_status_uri = remote_status_uri_copy,
    };

    var t = std.Thread.spawn(.{}, SendUndoLikeJob.run, .{job}) catch |err| {
        app_state.logger.err("sendUndoLike: thread spawn failed err={any}", .{err});
        return;
    };
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
    switch (app_state.jobs_mode) {
        .sync => {
            federation.acceptInboundFollow(app_state, allocator, user_id, username, remote_actor_id, remote_follow_activity_id) catch {};
            return;
        },
        .disabled => {
            const username_copy = app_state.allocator.dupe(u8, username) catch return;
            errdefer app_state.allocator.free(username_copy);
            const remote_actor_id_copy = app_state.allocator.dupe(u8, remote_actor_id) catch return;
            errdefer app_state.allocator.free(remote_actor_id_copy);
            const follow_id_copy = app_state.allocator.dupe(u8, remote_follow_activity_id) catch return;
            errdefer app_state.allocator.free(follow_id_copy);
            app_state.jobs_queue.push(app_state.allocator, .{
                .accept_inbound_follow = .{
                    .user_id = user_id,
                    .username = username_copy,
                    .remote_actor_id = remote_actor_id_copy,
                    .remote_follow_activity_id = follow_id_copy,
                },
            }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{
        .accept_inbound_follow = .{
            .user_id = user_id,
            .username = @constCast(username),
            .remote_actor_id = @constCast(remote_actor_id),
            .remote_follow_activity_id = @constCast(remote_follow_activity_id),
        },
    }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("acceptInboundFollow: enqueue failed err={any}", .{err});
        // Fallback to per-job thread execution.
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

    var t = std.Thread.spawn(.{}, AcceptInboundFollowJob.run, .{job}) catch |err| {
        app_state.logger.err("acceptInboundFollow: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn deliverStatusToFollowers(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            const user = users.lookupUserById(&app_state.conn, allocator, user_id) catch return;
            if (user == null) return;
            const st = statuses.lookup(&app_state.conn, allocator, status_id) catch return;
            if (st == null) return;
            federation.deliverStatusToFollowers(app_state, allocator, user.?, st.?) catch {};
            return;
        },
        .disabled => {
            app_state.jobs_queue.push(app_state.allocator, .{ .deliver_status = .{ .user_id = user_id, .status_id = status_id } }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{ .deliver_status = .{ .user_id = user_id, .status_id = status_id } }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("deliverStatusToFollowers: enqueue failed err={any}", .{err});
        // Fallback to per-job thread execution.
    }

    const job = std.heap.page_allocator.create(DeliverStatusJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .status_id = status_id,
    };

    var t = std.Thread.spawn(.{}, DeliverStatusJob.run, .{job}) catch |err| {
        app_state.logger.err("deliverStatusToFollowers: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn deliverDeleteToFollowers(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
) void {
    switch (app_state.jobs_mode) {
        .sync => {
            const user = users.lookupUserById(&app_state.conn, allocator, user_id) catch return;
            if (user == null) return;
            const st = statuses.lookupIncludingDeleted(&app_state.conn, allocator, status_id) catch return;
            if (st == null) return;
            if (st.?.deleted_at == null) return;
            federation.deliverDeleteToFollowers(app_state, allocator, user.?, st.?) catch {};
            return;
        },
        .disabled => {
            app_state.jobs_queue.push(app_state.allocator, .{ .deliver_delete = .{ .user_id = user_id, .status_id = status_id } }) catch {};
            return;
        },
        .spawn => {},
    }

    if (jobs_db.enqueue(&app_state.conn, allocator, .{ .deliver_delete = .{ .user_id = user_id, .status_id = status_id } }, .{})) |_| {
        return;
    } else |err| {
        app_state.logger.err("deliverDeleteToFollowers: enqueue failed err={any}", .{err});
        // Fallback to per-job thread execution.
    }

    const job = std.heap.page_allocator.create(DeliverDeleteJob) catch return;
    errdefer std.heap.page_allocator.destroy(job);

    job.* = .{
        .cfg = app_state.cfg,
        .logger = app_state.logger,
        .user_id = user_id,
        .status_id = status_id,
    };

    var t = std.Thread.spawn(.{}, DeliverDeleteJob.run, .{job}) catch |err| {
        app_state.logger.err("deliverDeleteToFollowers: thread spawn failed err={any}", .{err});
        return;
    };
    t.detach();
}

pub fn runQueued(app_state: *app.App, allocator: std.mem.Allocator) RunError!void {
    var list = app_state.jobs_queue.drain();
    defer {
        for (list.items) |*j| j.deinit(app_state.allocator);
        list.deinit(app_state.allocator);
    }

    for (list.items) |job| {
        runJob(app_state, allocator, job) catch continue;
    }
}

const SendFollowJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    remote_actor_id: []u8,
    follow_activity_id: []u8,

    fn run(job: *@This()) void {
        job.logger.info("SendFollowJob: start remote_actor_id={s}", .{job.remote_actor_id});
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

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        federation.sendFollowActivity(&thread_app, a, job.user_id, job.remote_actor_id, job.follow_activity_id) catch |err| {
            job.logger.err("SendFollowJob: deliver failed remote_actor_id={s} err={any}", .{ job.remote_actor_id, err });
            return;
        };
        job.logger.info("SendFollowJob: delivered remote_actor_id={s}", .{job.remote_actor_id});
    }
};

const SendUndoFollowJob = struct {
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

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        federation.sendUndoFollowActivity(&thread_app, a, job.user_id, job.remote_actor_id, job.follow_activity_id) catch |err| {
            job.logger.err("SendUndoFollowJob: deliver failed remote_actor_id={s} err={any}", .{ job.remote_actor_id, err });
            return;
        };
    }
};

const SendLikeJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    fn run(job: *@This()) void {
        defer {
            std.heap.page_allocator.free(job.remote_actor_id);
            std.heap.page_allocator.free(job.remote_status_uri);
            std.heap.page_allocator.destroy(job);
        }

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        federation.sendLikeActivity(&thread_app, a, job.user_id, job.remote_actor_id, job.remote_status_uri) catch |err| {
            job.logger.err("SendLikeJob: deliver failed remote_actor_id={s} err={any}", .{ job.remote_actor_id, err });
            return;
        };
    }
};

const SendUndoLikeJob = struct {
    cfg: config.Config,
    logger: *log.Logger,
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    fn run(job: *@This()) void {
        defer {
            std.heap.page_allocator.free(job.remote_actor_id);
            std.heap.page_allocator.free(job.remote_status_uri);
            std.heap.page_allocator.destroy(job);
        }

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var conn = db.Db.open(a, job.cfg.db_path) catch return;
        defer conn.close();

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        federation.sendUndoLikeActivity(&thread_app, a, job.user_id, job.remote_actor_id, job.remote_status_uri) catch |err| {
            job.logger.err("SendUndoLikeJob: deliver failed remote_actor_id={s} err={any}", .{ job.remote_actor_id, err });
            return;
        };
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

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

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

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

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

        var hub: streaming_hub.Hub = streaming_hub.Hub.init(std.heap.page_allocator);
        defer hub.deinit();

        var thread_app: app.App = .{
            .allocator = a,
            .cfg = job.cfg,
            .conn = conn,
            .logger = job.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .streaming = &hub,
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = transport.RealTransport.init(a, job.cfg) catch return,
        };
        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        const user = users.lookupUserById(&thread_app.conn, a, job.user_id) catch null;
        if (user == null) return;
        const st = statuses.lookupIncludingDeleted(&thread_app.conn, a, job.status_id) catch null;
        if (st == null) return;
        if (st.?.deleted_at == null) return;

        federation.deliverDeleteToFollowers(&thread_app, a, user.?, st.?) catch {};
    }
};

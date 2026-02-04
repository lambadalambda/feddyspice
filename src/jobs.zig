const std = @import("std");

pub const Mode = enum {
    /// Spawn background threads for deliveries.
    spawn,
    /// Run jobs synchronously (useful for CLI/debugging).
    sync,
    /// Queue jobs but do not execute automatically (default for unit tests).
    disabled,
};

pub fn modeFromString(s: []const u8) Mode {
    if (std.ascii.eqlIgnoreCase(s, "spawn")) return .spawn;
    if (std.ascii.eqlIgnoreCase(s, "inline")) return .sync;
    if (std.ascii.eqlIgnoreCase(s, "sync")) return .sync;
    if (std.ascii.eqlIgnoreCase(s, "disabled")) return .disabled;
    if (std.ascii.eqlIgnoreCase(s, "queue")) return .disabled;
    return .spawn;
}

pub const Job = union(enum) {
    send_follow: SendFollow,
    send_undo_follow: SendUndoFollow,
    send_like: SendLike,
    send_undo_like: SendUndoLike,
    send_announce: SendAnnounce,
    send_undo_announce: SendUndoAnnounce,
    accept_inbound_follow: AcceptInboundFollow,
    deliver_actor_update: DeliverActorUpdate,
    deliver_status: DeliverStatus,
    deliver_delete: DeliverDelete,

    pub fn deinit(job: *Job, allocator: std.mem.Allocator) void {
        switch (job.*) {
            .send_follow => |*j| j.deinit(allocator),
            .send_undo_follow => |*j| j.deinit(allocator),
            .send_like => |*j| j.deinit(allocator),
            .send_undo_like => |*j| j.deinit(allocator),
            .send_announce => |*j| j.deinit(allocator),
            .send_undo_announce => |*j| j.deinit(allocator),
            .accept_inbound_follow => |*j| j.deinit(allocator),
            .deliver_actor_update => {},
            .deliver_status => {},
            .deliver_delete => {},
        }
        job.* = undefined;
    }
};

pub const SendFollow = struct {
    user_id: i64,
    remote_actor_id: []u8,
    follow_activity_id: []u8,

    pub fn deinit(self: *SendFollow, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.follow_activity_id);
        self.* = undefined;
    }
};

pub const SendUndoFollow = struct {
    user_id: i64,
    remote_actor_id: []u8,
    follow_activity_id: []u8,

    pub fn deinit(self: *SendUndoFollow, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.follow_activity_id);
        self.* = undefined;
    }
};

pub const SendLike = struct {
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    pub fn deinit(self: *SendLike, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.remote_status_uri);
        self.* = undefined;
    }
};

pub const SendUndoLike = struct {
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    pub fn deinit(self: *SendUndoLike, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.remote_status_uri);
        self.* = undefined;
    }
};

pub const SendAnnounce = struct {
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    pub fn deinit(self: *SendAnnounce, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.remote_status_uri);
        self.* = undefined;
    }
};

pub const SendUndoAnnounce = struct {
    user_id: i64,
    remote_actor_id: []u8,
    remote_status_uri: []u8,

    pub fn deinit(self: *SendUndoAnnounce, allocator: std.mem.Allocator) void {
        allocator.free(self.remote_actor_id);
        allocator.free(self.remote_status_uri);
        self.* = undefined;
    }
};

pub const AcceptInboundFollow = struct {
    user_id: i64,
    username: []u8,
    remote_actor_id: []u8,
    remote_follow_activity_id: []u8,

    pub fn deinit(self: *AcceptInboundFollow, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.remote_actor_id);
        allocator.free(self.remote_follow_activity_id);
        self.* = undefined;
    }
};

pub const DeliverStatus = struct {
    user_id: i64,
    status_id: i64,
};

pub const DeliverActorUpdate = struct {
    user_id: i64,
};

pub const DeliverDelete = struct {
    user_id: i64,
    status_id: i64,
};

pub const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    items: std.ArrayListUnmanaged(Job) = .empty,

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        self.mutex.lock();
        var list = self.items;
        self.items = .empty;
        self.mutex.unlock();

        for (list.items) |*j| j.deinit(allocator);
        list.deinit(allocator);
        self.* = undefined;
    }

    pub fn push(self: *Queue, allocator: std.mem.Allocator, job: Job) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.items.append(allocator, job);
    }

    pub fn drain(self: *Queue) std.ArrayListUnmanaged(Job) {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = self.items;
        self.items = .empty;
        return out;
    }
};

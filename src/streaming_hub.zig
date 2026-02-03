const std = @import("std");

pub const Stream = enum {
    user,
    public,
};

pub const Hub = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    subscribers: std.ArrayListUnmanaged(*Subscriber) = .empty,

    pub fn init(allocator: std.mem.Allocator) Hub {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Hub) void {
        self.mutex.lock();
        var subs = self.subscribers;
        self.subscribers = .empty;
        self.mutex.unlock();

        for (subs.items) |sub| {
            sub.close();
            sub.deinit();
            self.allocator.destroy(sub);
        }
        subs.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn subscribe(self: *Hub, user_id: i64, streams: []const Stream) !*Subscriber {
        const sub = try self.allocator.create(Subscriber);
        errdefer self.allocator.destroy(sub);

        sub.* = Subscriber.init(self.allocator, user_id, streams);

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.subscribers.append(self.allocator, sub);
        return sub;
    }

    pub fn unsubscribe(self: *Hub, sub: *Subscriber) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.subscribers.items, 0..) |s, idx| {
            if (s != sub) continue;
            _ = self.subscribers.swapRemove(idx);
            sub.close();
            sub.deinit();
            self.allocator.destroy(sub);
            break;
        }
    }

    pub fn subscriberCount(self: *Hub) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.subscribers.items.len;
    }

    pub fn publishUpdate(self: *Hub, user_id: i64, status_json: []const u8) void {
        self.publish(user_id, .user, "update", status_json);
    }

    pub fn publishDelete(self: *Hub, user_id: i64, status_id: []const u8) void {
        self.publish(user_id, .user, "delete", status_id);
    }

    pub fn publishNotification(self: *Hub, user_id: i64, notification_json: []const u8) void {
        self.publish(user_id, .user, "notification", notification_json);
    }

    fn publish(self: *Hub, user_id: i64, stream: Stream, event: []const u8, payload: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.subscribers.items) |sub| {
            if (sub.user_id != user_id) continue;
            if (!sub.hasStream(stream)) continue;
            const message = makeEnvelopeAlloc(self.allocator, event, payload) catch continue;
            if (!sub.enqueue(message)) self.allocator.free(message);
        }
    }
};

pub const Subscriber = struct {
    allocator: std.mem.Allocator,
    user_id: i64,
    stream_user: bool,
    stream_public: bool,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    closed: bool = false,
    queue: Ring = .{},

    const max_queue_len: usize = 64;

    const Ring = struct {
        head: usize = 0,
        len: usize = 0,
        items: [max_queue_len]?[]u8 = [_]?[]u8{null} ** max_queue_len,

        fn push(self: *Ring, msg: []u8) bool {
            if (self.len >= max_queue_len) return false;
            const idx = (self.head + self.len) % max_queue_len;
            self.items[idx] = msg;
            self.len += 1;
            return true;
        }

        fn pop(self: *Ring) ?[]u8 {
            if (self.len == 0) return null;
            const msg = self.items[self.head] orelse return null;
            self.items[self.head] = null;
            self.head = (self.head + 1) % max_queue_len;
            self.len -= 1;
            return msg;
        }

        fn drainFree(self: *Ring, allocator: std.mem.Allocator) void {
            while (self.pop()) |msg| allocator.free(msg);
        }
    };

    pub fn init(allocator: std.mem.Allocator, user_id: i64, streams: []const Stream) Subscriber {
        var sub: Subscriber = .{
            .allocator = allocator,
            .user_id = user_id,
            .stream_user = false,
            .stream_public = false,
        };
        for (streams) |s| {
            switch (s) {
                .user => sub.stream_user = true,
                .public => sub.stream_public = true,
            }
        }
        return sub;
    }

    pub fn deinit(self: *Subscriber) void {
        self.mutex.lock();
        self.queue.drainFree(self.allocator);
        self.mutex.unlock();
        self.* = undefined;
    }

    pub fn close(self: *Subscriber) void {
        self.mutex.lock();
        self.closed = true;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    pub fn hasStream(self: *const Subscriber, stream: Stream) bool {
        return switch (stream) {
            .user => self.stream_user,
            .public => self.stream_public,
        };
    }

    /// Enqueue a message. The message must be heap-allocated by `self.allocator`.
    /// Returns whether it was enqueued. If the queue is full or the subscriber is closed,
    /// the message is not enqueued.
    pub fn enqueue(self: *Subscriber, msg: []u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return false;
        if (!self.queue.push(msg)) {
            self.closed = true;
            self.cond.broadcast();
            return false;
        }

        self.cond.signal();
        return true;
    }

    pub fn pop(self: *Subscriber) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.queue.pop();
    }

    pub fn waitPop(self: *Subscriber, timeout_ns: u64) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) return null;
        if (self.queue.len == 0) {
            self.cond.timedWait(&self.mutex, timeout_ns) catch {};
        }
        return self.queue.pop();
    }
};

fn makeEnvelopeAlloc(allocator: std.mem.Allocator, event: []const u8, payload: []const u8) ![]u8 {
    const Envelope = struct {
        event: []const u8,
        payload: []const u8,
    };
    return std.json.Stringify.valueAlloc(allocator, Envelope{ .event = event, .payload = payload }, .{});
}

test "Hub publishes update events to matching subscribers" {
    var hub = Hub.init(std.testing.allocator);
    defer hub.deinit();

    const sub_a = try hub.subscribe(1, &.{.user});
    defer hub.unsubscribe(sub_a);

    const sub_b = try hub.subscribe(2, &.{.user});
    defer hub.unsubscribe(sub_b);

    hub.publishUpdate(1, "{\"id\":\"1\"}");

    const msg_a = sub_a.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer std.testing.allocator.free(msg_a);

    try std.testing.expectEqualStrings("{\"event\":\"update\",\"payload\":\"{\\\"id\\\":\\\"1\\\"}\"}", msg_a);
    try std.testing.expect(sub_b.pop() == null);
}

test "Hub publishes notification events to matching subscribers" {
    var hub = Hub.init(std.testing.allocator);
    defer hub.deinit();

    const sub = try hub.subscribe(1, &.{.user});
    defer hub.unsubscribe(sub);

    hub.publishNotification(1, "{\"id\":\"n1\"}");

    const msg = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer std.testing.allocator.free(msg);

    try std.testing.expectEqualStrings("{\"event\":\"notification\",\"payload\":\"{\\\"id\\\":\\\"n1\\\"}\"}", msg);
}

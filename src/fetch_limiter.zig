const std = @import("std");

pub const AcquireError = std.mem.Allocator.Error || error{Throttled};

pub const Options = struct {
    max_inflight: u32 = 4,
    backoff_base_ms: i64 = 1000,
    backoff_max_ms: i64 = 60_000,
};

pub const Limiter = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct {
        in_flight: u32 = 0,
        failures: u32 = 0,
        next_allowed_ms: i64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, opts: Options) Limiter {
        return .{
            .allocator = allocator,
            .opts = opts,
        };
    }

    pub fn deinit(self: *Limiter) void {
        self.mutex.lock();
        var keys = self.map.keyIterator();
        while (keys.next()) |k| self.allocator.free(k.*);
        self.map.deinit(self.allocator);
        self.mutex.unlock();
        self.* = undefined;
    }

    pub const Ticket = struct {
        limiter: *Limiter,
        key: []const u8,
        active: bool = true,

        pub fn finish(self: *Ticket, now_ms: i64, ok: bool) void {
            if (!self.active) return;
            self.active = false;

            self.limiter.mutex.lock();
            defer self.limiter.mutex.unlock();

            const entry = self.limiter.map.getPtr(self.key) orelse return;
            if (entry.in_flight > 0) entry.in_flight -= 1;

            if (ok) {
                entry.failures = 0;
                entry.next_allowed_ms = 0;
                return;
            }

            entry.failures +|= 1;
            const backoff = computeBackoffMs(self.limiter.opts.backoff_base_ms, self.limiter.opts.backoff_max_ms, entry.failures);
            if (backoff > 0) entry.next_allowed_ms = now_ms + backoff;
        }
    };

    pub fn acquire(self: *Limiter, key: []const u8, now_ms: i64) AcquireError!Ticket {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = try self.getOrInsertEntry(key);

        if (now_ms < entry.next_allowed_ms) return error.Throttled;
        if (entry.in_flight >= self.opts.max_inflight) return error.Throttled;

        entry.in_flight += 1;
        return .{ .limiter = self, .key = key };
    }

    fn getOrInsertEntry(self: *Limiter, key: []const u8) std.mem.Allocator.Error!*Entry {
        if (self.map.getPtr(key)) |existing| return existing;

        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        try self.map.put(self.allocator, key_copy, .{});
        return self.map.getPtr(key_copy).?;
    }
};

fn computeBackoffMs(base_ms: i64, max_ms: i64, failures: u32) i64 {
    if (failures == 0) return 0;
    if (base_ms <= 0) return 0;
    if (max_ms <= 0) return 0;

    var backoff: i64 = base_ms;
    var i: u32 = 1;
    while (i < failures and backoff < max_ms) : (i += 1) {
        if (backoff > @divFloor(max_ms, 2)) {
            backoff = max_ms;
            break;
        }
        backoff *= 2;
    }

    return @min(backoff, max_ms);
}

test "Limiter enforces max inflight per key" {
    var limiter = Limiter.init(std.testing.allocator, .{
        .max_inflight = 1,
        .backoff_base_ms = 1000,
        .backoff_max_ms = 60_000,
    });
    defer limiter.deinit();

    var t1 = try limiter.acquire("example.test", 0);
    defer t1.finish(0, true);

    try std.testing.expectError(error.Throttled, limiter.acquire("example.test", 0));

    t1.finish(0, true);
    var t2 = try limiter.acquire("example.test", 0);
    t2.finish(0, true);
}

test "Limiter backs off after failures and resets on success" {
    var limiter = Limiter.init(std.testing.allocator, .{
        .max_inflight = 10,
        .backoff_base_ms = 1000,
        .backoff_max_ms = 8000,
    });
    defer limiter.deinit();

    var t1 = try limiter.acquire("example.test", 100);
    t1.finish(100, false);

    try std.testing.expectError(error.Throttled, limiter.acquire("example.test", 1099));
    var t2 = try limiter.acquire("example.test", 1100);
    t2.finish(1100, false);

    try std.testing.expectError(error.Throttled, limiter.acquire("example.test", 3099));
    var t3 = try limiter.acquire("example.test", 3100);
    t3.finish(3100, true);

    _ = try limiter.acquire("example.test", 4000);
}

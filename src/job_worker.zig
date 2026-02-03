const std = @import("std");

const app = @import("app.zig");
const background = @import("background.zig");
const config = @import("config.zig");
const db = @import("db.zig");
const jobs_db = @import("jobs_db.zig");
const log = @import("log.zig");
const migrations = @import("migrations.zig");
const transport = @import("transport.zig");

pub const Options = struct {
    poll_interval_ms: u64 = 250,
    lock_timeout_ms: i64 = 60_000,
};

pub fn startDetached(cfg: config.Config, logger: *log.Logger, opts: Options) void {
    const worker = std.heap.page_allocator.create(Worker) catch return;
    worker.* = .{ .cfg = cfg, .logger = logger, .opts = opts };

    var t = std.Thread.spawn(.{}, Worker.run, .{worker}) catch |err| {
        logger.err("JobsWorker: thread spawn failed err={any}", .{err});
        std.heap.page_allocator.destroy(worker);
        return;
    };
    t.detach();
}

const Worker = struct {
    cfg: config.Config,
    logger: *log.Logger,
    opts: Options,

    fn run(self: *@This()) void {
        defer std.heap.page_allocator.destroy(self);

        var conn = db.Db.open(std.heap.page_allocator, self.cfg.db_path) catch |err| {
            self.logger.err("JobsWorker: db open failed err={any}", .{err});
            return;
        };
        defer conn.close();

        migrations.migrate(&conn) catch |err| {
            self.logger.err("JobsWorker: migrate failed err={any}", .{err});
            return;
        };

        const real_transport = transport.RealTransport.init(std.heap.page_allocator, self.cfg) catch |err| {
            self.logger.err("JobsWorker: transport init failed err={any}", .{err});
            return;
        };
        const null_transport = transport.NullTransport.init();

        var thread_app: app.App = .{
            .allocator = std.heap.page_allocator,
            .cfg = self.cfg,
            .conn = conn,
            .logger = self.logger,
            .jobs_mode = .sync,
            .jobs_queue = .{},
            .transport = undefined,
            .null_transport = null_transport,
            .real_transport = real_transport,
        };

        thread_app.transport = thread_app.real_transport.transport();
        defer thread_app.transport.deinit();

        self.logger.info("JobsWorker: started", .{});

        while (true) {
            const now_ms: i64 = std.time.milliTimestamp();

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const a = arena.allocator();

            const claimed = jobs_db.claimNext(&thread_app.conn, a, .{
                .now_ms = now_ms,
                .lock_timeout_ms = self.opts.lock_timeout_ms,
            }) catch |err| {
                self.logger.err("JobsWorker: claim failed err={any}", .{err});
                std.Thread.sleep(self.opts.poll_interval_ms * std.time.ns_per_ms);
                continue;
            };

            if (claimed == null) {
                std.Thread.sleep(self.opts.poll_interval_ms * std.time.ns_per_ms);
                continue;
            }

            var job = claimed.?;
            defer job.deinit(a);

            if (background.runJob(&thread_app, a, job.job)) |_| {
                jobs_db.finishSuccess(&thread_app.conn, job.id) catch |err| {
                    self.logger.err("JobsWorker: finishSuccess failed job_id={d} err={any}", .{ job.id, err });
                };
            } else |err| {
                self.logger.err("JobsWorker: job failed job_id={d} type={s} err={any}", .{ job.id, @tagName(job.job), err });
                jobs_db.finishFailure(&thread_app.conn, job.id, job.attempts, job.max_attempts, err, now_ms) catch |e2| {
                    self.logger.err("JobsWorker: finishFailure failed job_id={d} err={any}", .{ job.id, e2 });
                };
            }
        }
    }
};

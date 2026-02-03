const std = @import("std");

const config = @import("config.zig");
const db = @import("db.zig");
const jobs = @import("jobs.zig");
const log = @import("log.zig");
const migrations = @import("migrations.zig");
const password = @import("password.zig");
const transport = @import("transport.zig");

pub const App = struct {
    allocator: std.mem.Allocator,
    cfg: config.Config,
    conn: db.Db,
    logger: *log.Logger,
    jobs_mode: jobs.Mode,
    jobs_queue: jobs.Queue = .{},
    transport: transport.Transport,
    null_transport: transport.NullTransport,
    real_transport: transport.RealTransport,

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config.Config) !*App {
        const app_state = try allocator.create(App);
        errdefer allocator.destroy(app_state);

        const logger = try allocator.create(log.Logger);
        errdefer allocator.destroy(logger);
        logger.* = if (cfg.log_file) |p|
            try log.Logger.initFile(p, .{ .to_stderr = true, .min_level = cfg.log_level })
        else
            .{ .opts = .{ .to_stderr = true, .min_level = cfg.log_level } };
        errdefer logger.deinit();

        var conn = try db.Db.open(allocator, cfg.db_path);
        errdefer conn.close();

        try migrations.migrate(&conn);

        var real_transport = try transport.RealTransport.init(allocator, cfg);
        errdefer real_transport.deinit();

        app_state.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .conn = conn,
            .logger = logger,
            .jobs_mode = cfg.jobs_mode,
            .jobs_queue = .{},
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = real_transport,
        };

        app_state.transport = app_state.real_transport.transport();
        return app_state;
    }

    pub fn initMemory(allocator: std.mem.Allocator, domain: []const u8) !App {
        const cfg: config.Config = .{
            .domain = try allocator.dupe(u8, domain),
            .scheme = .http,
            .listen_address = try std.net.Address.parseIp("127.0.0.1", 0),
            .db_path = try allocator.dupe(u8, ":memory:"),
            .ca_cert_file = null,
            .allow_private_networks = false,
            .log_file = null,
            .log_level = .err,
            .password_params = password.Params{ .t = 1, .m = 8, .p = 1 },
            .http_timeout_ms = 10_000,
            .jobs_mode = .disabled,
        };

        var conn = try db.Db.openZ(":memory:");
        errdefer conn.close();
        try migrations.migrate(&conn);

        const logger = try allocator.create(log.Logger);
        errdefer allocator.destroy(logger);
        logger.* = log.Logger.initNull();

        var app_state: App = .{
            .allocator = allocator,
            .cfg = cfg,
            .conn = conn,
            .logger = logger,
            .jobs_mode = cfg.jobs_mode,
            .jobs_queue = .{},
            .transport = undefined,
            .null_transport = transport.NullTransport.init(),
            .real_transport = undefined,
        };

        app_state.transport = app_state.null_transport.transport();
        return app_state;
    }

    pub fn deinit(app: *App) void {
        app.jobs_queue.deinit(app.allocator);
        app.transport.deinit();
        app.conn.close();
        app.cfg.deinit(app.allocator);
        app.logger.deinit();
        app.allocator.destroy(app.logger);
        app.* = undefined;
    }

    pub fn deinitAndDestroy(app: *App) void {
        const allocator = app.allocator;
        app.deinit();
        allocator.destroy(app);
    }
};

test "initFromConfig: transport ctx is stable" {
    const allocator = std.testing.allocator;

    const cfg: config.Config = .{
        .domain = try allocator.dupe(u8, "example.test"),
        .scheme = .http,
        .listen_address = try std.net.Address.parseIp("127.0.0.1", 0),
        .db_path = try allocator.dupe(u8, ":memory:"),
        .ca_cert_file = null,
        .allow_private_networks = false,
        .log_file = null,
        .log_level = .err,
        .password_params = password.Params{ .t = 1, .m = 8, .p = 1 },
        .http_timeout_ms = 1000,
        .jobs_mode = .disabled,
    };

    const app_state = try App.initFromConfig(allocator, cfg);
    defer app_state.deinitAndDestroy();

    try std.testing.expectEqual(@intFromPtr(&app_state.real_transport), @intFromPtr(app_state.transport.ctx));
}

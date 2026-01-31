const std = @import("std");

const config = @import("config.zig");
const db = @import("db.zig");
const migrations = @import("migrations.zig");
const password = @import("password.zig");

pub const App = struct {
    allocator: std.mem.Allocator,
    cfg: config.Config,
    conn: db.Db,

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config.Config) !App {
        var conn = try db.Db.open(allocator, cfg.db_path);
        errdefer conn.close();

        try migrations.migrate(&conn);

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .conn = conn,
        };
    }

    pub fn initMemory(allocator: std.mem.Allocator, domain: []const u8) !App {
        const cfg: config.Config = .{
            .domain = try allocator.dupe(u8, domain),
            .scheme = .http,
            .listen_address = try std.net.Address.parseIp("127.0.0.1", 0),
            .db_path = try allocator.dupe(u8, ":memory:"),
            .password_params = password.Params{ .t = 1, .m = 8, .p = 1 },
        };

        var conn = try db.Db.openZ(":memory:");
        errdefer conn.close();
        try migrations.migrate(&conn);

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .conn = conn,
        };
    }

    pub fn deinit(app: *App) void {
        app.conn.close();
        app.cfg.deinit(app.allocator);
        app.* = undefined;
    }
};


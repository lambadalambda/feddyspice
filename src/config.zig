const std = @import("std");

const password = @import("password.zig");

pub const Scheme = enum { http, https };

pub const Config = struct {
    domain: []const u8,
    scheme: Scheme,
    listen_address: std.net.Address,
    db_path: []const u8,
    ca_cert_file: ?[]const u8,
    password_params: password.Params,

    pub fn load(allocator: std.mem.Allocator) !Config {
        const domain_env = std.posix.getenv("FEDDYSPICE_DOMAIN") orelse "localhost";
        const scheme_env = std.posix.getenv("FEDDYSPICE_SCHEME") orelse "http";
        const listen_env = std.posix.getenv("FEDDYSPICE_LISTEN") orelse "0.0.0.0:8080";
        const db_path_env = std.posix.getenv("FEDDYSPICE_DB_PATH") orelse "feddyspice.sqlite3";
        const ca_cert_env = std.posix.getenv("FEDDYSPICE_CACERTFILE");

        const domain = try allocator.dupe(u8, domain_env);
        errdefer allocator.free(domain);

        const db_path = try allocator.dupe(u8, db_path_env);
        errdefer allocator.free(db_path);

        var ca_cert_file: ?[]const u8 = null;
        if (ca_cert_env) |p| {
            if (p.len > 0) {
                ca_cert_file = try allocator.dupe(u8, p);
                errdefer allocator.free(ca_cert_file.?);
            }
        }

        const scheme: Scheme = if (std.mem.eql(u8, scheme_env, "https")) .https else .http;
        const listen_address = try std.net.Address.parseIpAndPort(listen_env);

        return .{
            .domain = domain,
            .scheme = scheme,
            .listen_address = listen_address,
            .db_path = db_path,
            .ca_cert_file = ca_cert_file,
            .password_params = password.Params.owasp_2id,
        };
    }

    pub fn deinit(cfg: *Config, allocator: std.mem.Allocator) void {
        allocator.free(cfg.domain);
        allocator.free(cfg.db_path);
        if (cfg.ca_cert_file) |p| allocator.free(p);
        cfg.* = undefined;
    }
};

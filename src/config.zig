const std = @import("std");

const jobs = @import("jobs.zig");
const log = @import("log.zig");
const password = @import("password.zig");

pub const Scheme = enum { http, https };

pub const Config = struct {
    domain: []const u8,
    scheme: Scheme,
    listen_address: std.net.Address,
    db_path: []const u8,
    ca_cert_file: ?[]const u8,
    allow_private_networks: bool,
    log_file: ?[]const u8,
    log_level: log.Level,
    password_params: password.Params,
    http_timeout_ms: u32,
    http_max_body_bytes: usize = 1024 * 1024,
    http_allow_nonstandard_ports: bool = false,
    http_max_inflight_per_host: u32 = 4,
    http_failure_backoff_base_ms: i64 = 1000,
    http_failure_backoff_max_ms: i64 = 60_000,
    json_max_nesting_depth: usize = 64,
    json_max_tokens: usize = 4096,
    signature_max_clock_skew_sec: u32 = 15 * 60,
    jobs_mode: jobs.Mode,

    pub fn load(allocator: std.mem.Allocator) !Config {
        const domain_env_raw = std.posix.getenv("FEDDYSPICE_DOMAIN") orelse "localhost";
        const scheme_env_raw = std.posix.getenv("FEDDYSPICE_SCHEME") orelse "http";
        const listen_env_raw = std.posix.getenv("FEDDYSPICE_LISTEN") orelse "0.0.0.0:8080";
        const db_path_env_raw = std.posix.getenv("FEDDYSPICE_DB_PATH") orelse "feddyspice.sqlite3";

        const domain_env = blk: {
            const trimmed = std.mem.trim(u8, domain_env_raw, " \t\r\n");
            break :blk if (trimmed.len == 0) "localhost" else trimmed;
        };
        const scheme_env = blk: {
            const trimmed = std.mem.trim(u8, scheme_env_raw, " \t\r\n");
            break :blk if (trimmed.len == 0) "http" else trimmed;
        };
        const listen_env = blk: {
            const trimmed = std.mem.trim(u8, listen_env_raw, " \t\r\n");
            break :blk if (trimmed.len == 0) "0.0.0.0:8080" else trimmed;
        };
        const db_path_env = blk: {
            const trimmed = std.mem.trim(u8, db_path_env_raw, " \t\r\n");
            break :blk if (trimmed.len == 0) "feddyspice.sqlite3" else trimmed;
        };
        const ca_cert_env = std.posix.getenv("FEDDYSPICE_CACERTFILE");
        const allow_private_networks = envBool("FEDDYSPICE_ALLOW_PRIVATE_NETWORKS", false);
        const log_file_env = std.posix.getenv("FEDDYSPICE_LOG_FILE");
        const log_level_env = std.posix.getenv("FEDDYSPICE_LOG_LEVEL") orelse "info";
        const timeout_env = std.posix.getenv("FEDDYSPICE_HTTP_TIMEOUT_MS") orelse "10000";
        const max_body_env = std.posix.getenv("FEDDYSPICE_HTTP_MAX_BODY_BYTES") orelse "1048576";
        const allow_nonstandard_ports = envBool("FEDDYSPICE_HTTP_ALLOW_NONSTANDARD_PORTS", false);
        const max_inflight_env = std.posix.getenv("FEDDYSPICE_HTTP_MAX_INFLIGHT_PER_HOST") orelse "4";
        const backoff_base_env = std.posix.getenv("FEDDYSPICE_HTTP_FAILURE_BACKOFF_BASE_MS") orelse "1000";
        const backoff_max_env = std.posix.getenv("FEDDYSPICE_HTTP_FAILURE_BACKOFF_MAX_MS") orelse "60000";
        const json_depth_env = std.posix.getenv("FEDDYSPICE_JSON_MAX_NESTING_DEPTH") orelse "64";
        const json_tokens_env = std.posix.getenv("FEDDYSPICE_JSON_MAX_TOKENS") orelse "4096";
        const skew_env = std.posix.getenv("FEDDYSPICE_SIGNATURE_MAX_CLOCK_SKEW_SEC") orelse "900";
        const jobs_mode_env = std.posix.getenv("FEDDYSPICE_JOBS_MODE") orelse "spawn";

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

        var log_file: ?[]const u8 = null;
        if (log_file_env) |p| {
            if (p.len > 0) {
                log_file = try allocator.dupe(u8, p);
                errdefer allocator.free(log_file.?);
            }
        }

        const log_level = log.levelFromString(log_level_env);

        const http_timeout_ms: u32 = blk: {
            const parsed = std.fmt.parseInt(u32, timeout_env, 10) catch break :blk 10_000;
            break :blk @max(parsed, 1);
        };

        const http_max_body_bytes: usize = blk: {
            const parsed = std.fmt.parseInt(usize, max_body_env, 10) catch break :blk 1024 * 1024;
            break :blk parsed;
        };

        const http_max_inflight_per_host: u32 = blk: {
            const parsed = std.fmt.parseInt(u32, max_inflight_env, 10) catch break :blk 4;
            break :blk @max(parsed, 1);
        };

        const http_failure_backoff_base_ms: i64 = blk: {
            const parsed = std.fmt.parseInt(i64, backoff_base_env, 10) catch break :blk 1000;
            break :blk @max(parsed, 0);
        };

        const http_failure_backoff_max_ms: i64 = blk: {
            const parsed = std.fmt.parseInt(i64, backoff_max_env, 10) catch break :blk 60_000;
            break :blk @max(parsed, 0);
        };

        const json_max_nesting_depth: usize = blk: {
            const parsed = std.fmt.parseInt(usize, json_depth_env, 10) catch break :blk 64;
            break :blk @max(parsed, 1);
        };

        const json_max_tokens: usize = blk: {
            const parsed = std.fmt.parseInt(usize, json_tokens_env, 10) catch break :blk 4096;
            break :blk @max(parsed, 1);
        };

        const signature_max_clock_skew_sec: u32 = blk: {
            const parsed = std.fmt.parseInt(u32, skew_env, 10) catch break :blk 15 * 60;
            break :blk parsed;
        };

        const jobs_mode = jobs.modeFromString(jobs_mode_env);

        const scheme: Scheme = if (std.ascii.eqlIgnoreCase(scheme_env, "https")) .https else .http;
        const listen_address = try std.net.Address.parseIpAndPort(listen_env);

        return .{
            .domain = domain,
            .scheme = scheme,
            .listen_address = listen_address,
            .db_path = db_path,
            .ca_cert_file = ca_cert_file,
            .allow_private_networks = allow_private_networks,
            .log_file = log_file,
            .log_level = log_level,
            .password_params = password.Params.owasp_2id,
            .http_timeout_ms = http_timeout_ms,
            .http_max_body_bytes = http_max_body_bytes,
            .http_allow_nonstandard_ports = allow_nonstandard_ports,
            .http_max_inflight_per_host = http_max_inflight_per_host,
            .http_failure_backoff_base_ms = http_failure_backoff_base_ms,
            .http_failure_backoff_max_ms = http_failure_backoff_max_ms,
            .json_max_nesting_depth = json_max_nesting_depth,
            .json_max_tokens = json_max_tokens,
            .signature_max_clock_skew_sec = signature_max_clock_skew_sec,
            .jobs_mode = jobs_mode,
        };
    }

    pub fn deinit(cfg: *Config, allocator: std.mem.Allocator) void {
        allocator.free(cfg.domain);
        allocator.free(cfg.db_path);
        if (cfg.ca_cert_file) |p| allocator.free(p);
        if (cfg.log_file) |p| allocator.free(p);
        cfg.* = undefined;
    }
};

fn envBool(name: []const u8, default: bool) bool {
    const raw = std.posix.getenv(name) orelse return default;
    if (raw.len == 0) return default;
    if (std.ascii.eqlIgnoreCase(raw, "1")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "0")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "false")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "no")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "off")) return false;
    return default;
}

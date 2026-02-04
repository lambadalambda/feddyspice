const std = @import("std");
const builtin = @import("builtin");

const config = @import("config.zig");
const ssrf = @import("ssrf.zig");

pub const Error =
    std.mem.Allocator.Error ||
    std.http.Client.RequestError ||
    std.Io.Writer.Error ||
    std.http.Client.Request.ReceiveHeadError ||
    std.http.Reader.BodyError ||
    std.Uri.ParseError ||
    std.crypto.Certificate.Bundle.AddCertsFromFilePathError ||
    std.posix.GetSockNameError ||
    std.posix.SetSockOptError ||
    error{
        TimeoutUnsupported,
        NetworkDisabled,
        UnexpectedRequest,
        OutboundUrlInvalid,
        ResolveFailed,
        SsrfBlocked,
        ResponseTooLarge,
    };

pub const FetchOptions = struct {
    url: []const u8,
    method: std.http.Method,
    headers: std.http.Client.Request.Headers = .{},
    extra_headers: []const std.http.Header = &.{},
    payload: ?[]const u8 = null,
    keep_alive: bool = false,
    redirect_behavior: std.http.Client.Request.RedirectBehavior = .unhandled,
    max_body_bytes: ?usize = null,
};

pub const Response = struct {
    status: std.http.Status,
    body: []u8,
};

pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        fetch: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, opts: FetchOptions) Error!Response,
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn fetch(t: Transport, allocator: std.mem.Allocator, opts: FetchOptions) Error!Response {
        return t.vtable.fetch(t.ctx, allocator, opts);
    }

    pub fn deinit(t: Transport) void {
        t.vtable.deinit(t.ctx);
    }
};

pub const NullTransport = struct {
    pub fn init() NullTransport {
        return .{};
    }

    pub fn transport(self: *NullTransport) Transport {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    const vtable: Transport.VTable = .{
        .fetch = fetch,
        .deinit = deinit,
    };

    fn fetch(_: *anyopaque, _: std.mem.Allocator, _: FetchOptions) Error!Response {
        return error.NetworkDisabled;
    }

    fn deinit(_: *anyopaque) void {}
};

pub const RealTransport = struct {
    client: std.http.Client,
    timeout_ms: u32,
    allow_private_networks: bool,
    max_body_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, cfg: config.Config) !RealTransport {
        var client: std.http.Client = .{ .allocator = allocator };
        errdefer client.deinit();

        if (cfg.ca_cert_file) |p| {
            client.next_https_rescan_certs = false;
            try client.ca_bundle.addCertsFromFilePathAbsolute(allocator, p);
        }

        return .{
            .client = client,
            .timeout_ms = cfg.http_timeout_ms,
            .allow_private_networks = cfg.allow_private_networks,
            .max_body_bytes = cfg.http_max_body_bytes,
        };
    }

    pub fn deinit(self: *RealTransport) void {
        self.client.deinit();
        self.* = undefined;
    }

    pub fn transport(self: *RealTransport) Transport {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    const vtable: Transport.VTable = .{
        .fetch = fetch,
        .deinit = deinitVtable,
    };

    fn deinitVtable(ctx: *anyopaque) void {
        const self: *RealTransport = @ptrCast(@alignCast(ctx));
        self.deinit();
    }

    fn fetch(ctx: *anyopaque, allocator: std.mem.Allocator, opts: FetchOptions) Error!Response {
        const self: *RealTransport = @ptrCast(@alignCast(ctx));
        const max_body_bytes = opts.max_body_bytes orelse self.max_body_bytes;

        const uri = try std.Uri.parse(opts.url);
        try validateOutboundUri(allocator, uri, self.allow_private_networks);

        var req = try self.client.request(opts.method, uri, .{
            .headers = opts.headers,
            .extra_headers = opts.extra_headers,
            .redirect_behavior = opts.redirect_behavior,
            .keep_alive = opts.keep_alive,
        });
        defer req.deinit();

        try applySocketTimeouts(req.connection, self.timeout_ms);
        if (req.connection) |conn| {
            try validateConnectedPeerAddress(conn, self.allow_private_networks);
        }

        if (opts.payload) |payload| {
            req.transfer_encoding = .{ .content_length = payload.len };
            var body_buf: [4 * 1024]u8 = undefined;
            var body = try req.sendBodyUnflushed(&body_buf);
            try body.writer.writeAll(payload);
            try body.end();
            try req.connection.?.flush();
        } else {
            try req.sendBodiless();
        }

        var redirect_buf: [8 * 1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        var transfer_buf: [64]u8 = undefined;
        var reader = response.reader(&transfer_buf);
        const limit: std.Io.Limit = if (max_body_bytes == 0) .unlimited else .limited(max_body_bytes);
        const body_bytes = reader.allocRemaining(allocator, limit) catch |err| switch (err) {
            error.StreamTooLong => return error.ResponseTooLarge,
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };

        return .{
            .status = response.head.status,
            .body = body_bytes,
        };
    }
};

fn validateOutboundUri(allocator: std.mem.Allocator, uri: std.Uri, allow_private_networks: bool) Error!void {
    if (!schemeIsHttp(uri.scheme)) return error.OutboundUrlInvalid;
    if (uri.user != null or uri.password != null) return error.OutboundUrlInvalid;

    var host_buf: [std.Uri.host_name_max]u8 = undefined;
    const host = uri.getHost(&host_buf) catch return error.OutboundUrlInvalid;
    if (host.len == 0) return error.OutboundUrlInvalid;

    const port: u16 = uri.port orelse defaultPortForScheme(uri.scheme);

    const direct_ip = std.net.Address.parseIp(host, port) catch null;
    if (direct_ip) |addr| {
        if (!ssrf.isAllowedAddress(addr, allow_private_networks)) return error.SsrfBlocked;
        return;
    }

    const list = std.net.getAddressList(allocator, host, port) catch return error.ResolveFailed;
    defer list.deinit();

    for (list.addrs) |addr| {
        if (!ssrf.isAllowedAddress(addr, allow_private_networks)) return error.SsrfBlocked;
    }
}

fn validateConnectedPeerAddress(conn: *std.http.Client.Connection, allow_private_networks: bool) Error!void {
    if (builtin.os.tag == .windows) return;
    const stream = conn.stream_reader.getStream();

    var peer: std.net.Address = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.net.Address);
    try std.posix.getpeername(stream.handle, &peer.any, &len);

    const addr = std.net.Address.initPosix(@alignCast(&peer.any));
    if (!ssrf.isAllowedAddress(addr, allow_private_networks)) return error.SsrfBlocked;
}

fn schemeIsHttp(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
}

fn defaultPortForScheme(scheme: []const u8) u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    return 443;
}

pub const MockTransport = struct {
    pub const Expected = struct {
        method: std.http.Method,
        url: []const u8,
        response_status: std.http.Status = .ok,
        response_body: []const u8 = "",
    };

    pub const Recorded = struct {
        method: std.http.Method,
        url: []u8,
        headers: std.http.Client.Request.Headers,
        extra_headers: []std.http.Header,
        payload: ?[]u8,
    };

    allocator: std.mem.Allocator,
    strict: bool = true,
    expected: std.ArrayListUnmanaged(Expected) = .empty,
    requests: std.ArrayListUnmanaged(Recorded) = .empty,

    pub fn init(allocator: std.mem.Allocator) MockTransport {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MockTransport) void {
        for (self.requests.items) |r| {
            self.allocator.free(r.url);
            for (r.extra_headers) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            self.allocator.free(r.extra_headers);
            if (r.payload) |p| self.allocator.free(p);
        }
        self.requests.deinit(self.allocator);
        self.expected.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn pushExpected(self: *MockTransport, e: Expected) !void {
        try self.expected.append(self.allocator, e);
    }

    pub fn transport(self: *MockTransport) Transport {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    const vtable: Transport.VTable = .{
        .fetch = fetch,
        .deinit = deinitVtable,
    };

    fn deinitVtable(ctx: *anyopaque) void {
        const self: *MockTransport = @ptrCast(@alignCast(ctx));
        self.deinit();
    }

    fn fetch(ctx: *anyopaque, allocator: std.mem.Allocator, opts: FetchOptions) Error!Response {
        const self: *MockTransport = @ptrCast(@alignCast(ctx));

        var copied_extra = try self.allocator.alloc(std.http.Header, opts.extra_headers.len);
        for (opts.extra_headers, 0..) |h, i| {
            copied_extra[i] = .{
                .name = try self.allocator.dupe(u8, h.name),
                .value = try self.allocator.dupe(u8, h.value),
            };
        }

        const copied_url = try self.allocator.dupe(u8, opts.url);
        const copied_payload = if (opts.payload) |p| try self.allocator.dupe(u8, p) else null;

        try self.requests.append(self.allocator, .{
            .method = opts.method,
            .url = copied_url,
            .headers = opts.headers,
            .extra_headers = copied_extra,
            .payload = copied_payload,
        });

        var match_i: ?usize = null;
        for (self.expected.items, 0..) |e, i| {
            if (e.method == opts.method and std.mem.eql(u8, e.url, opts.url)) {
                match_i = i;
                break;
            }
        }

        if (match_i == null) {
            if (self.strict) return error.UnexpectedRequest;
            return .{ .status = .ok, .body = try allocator.dupe(u8, "") };
        }

        const e = self.expected.swapRemove(match_i.?);
        const out_body = try allocator.dupe(u8, e.response_body);
        return .{ .status = e.response_status, .body = out_body };
    }
};

fn applySocketTimeouts(conn: ?*std.http.Client.Connection, timeout_ms: u32) Error!void {
    if (timeout_ms == 0) return;
    if (conn == null) return;

    if (builtin.os.tag == .windows) return error.TimeoutUnsupported;

    const stream = conn.?.stream_reader.getStream();
    const fd = stream.handle;

    const sec: u64 = timeout_ms / 1000;
    const usec: u64 = @as(u64, timeout_ms % 1000) * 1000;

    var tv: std.posix.timeval = .{
        .sec = @intCast(sec),
        .usec = @intCast(usec),
    };

    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
}

test "RealTransport blocks outbound loopback by default" {
    const allocator = std.testing.allocator;
    const jobs = @import("jobs.zig");
    const password = @import("password.zig");

    var cfg: config.Config = .{
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
        .jobs_mode = jobs.Mode.disabled,
    };
    defer cfg.deinit(allocator);

    var real = try RealTransport.init(allocator, cfg);
    var t = real.transport();
    defer t.deinit();

    try std.testing.expectError(error.SsrfBlocked, t.fetch(allocator, .{
        .url = "http://127.0.0.1:1",
        .method = .GET,
    }));
}

test "RealTransport enforces max_body_bytes" {
    const allocator = std.testing.allocator;
    const jobs = @import("jobs.zig");
    const password = @import("password.zig");

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.deinit();
    const port = server.listen_address.getPort();

    const body_len: usize = 2048;
    const t = try std.Thread.spawn(.{}, struct {
        fn run(listener: *std.net.Server, len: usize) void {
            var conn = listener.accept() catch return;
            defer conn.stream.close();

            var req_buf: [1024]u8 = undefined;
            _ = conn.stream.read(&req_buf) catch {};

            var write_buf: [4096]u8 = undefined;
            var w = std.net.Stream.Writer.init(conn.stream, &write_buf);
            w.interface.print(
                "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
                .{len},
            ) catch return;

            var chunk: [1024]u8 = undefined;
            @memset(chunk[0..], 'a');

            var remaining: usize = len;
            while (remaining > 0) {
                const n = @min(remaining, chunk.len);
                w.interface.writeAll(chunk[0..n]) catch return;
                remaining -= n;
            }
            w.interface.flush() catch {};
        }
    }.run, .{ &server, body_len });
    defer t.join();

    var cfg: config.Config = .{
        .domain = try allocator.dupe(u8, "example.test"),
        .scheme = .http,
        .listen_address = try std.net.Address.parseIp("127.0.0.1", 0),
        .db_path = try allocator.dupe(u8, ":memory:"),
        .ca_cert_file = null,
        .allow_private_networks = true,
        .log_file = null,
        .log_level = .err,
        .password_params = password.Params{ .t = 1, .m = 8, .p = 1 },
        .http_timeout_ms = 1000,
        .jobs_mode = jobs.Mode.disabled,
    };
    defer cfg.deinit(allocator);

    var real = try RealTransport.init(allocator, cfg);
    var tr = real.transport();
    defer tr.deinit();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{port});
    defer allocator.free(url);

    try std.testing.expectError(error.ResponseTooLarge, tr.fetch(allocator, .{
        .url = url,
        .method = .GET,
        .max_body_bytes = 1024,
    }));
}

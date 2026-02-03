const std = @import("std");

const http = std.http;
const net = std.net;

const routes = @import("http.zig");
const app = @import("app.zig");
const form = @import("form.zig");
const log = @import("log.zig");
const oauth = @import("oauth.zig");
const streaming_hub = @import("streaming_hub.zig");
const websocket = @import("websocket.zig");

pub fn serve(app_state: *app.App, listen_address: net.Address) !void {
    var listener = try listen_address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    while (true) {
        try serveOnce(app_state, &listener);
    }
}

pub fn serveOnce(app_state: *app.App, listener: *net.Server) !void {
    var conn = try listener.accept();
    var close_conn = true;
    defer if (close_conn) conn.stream.close();

    var read_buffer: [16 * 1024]u8 = undefined;
    var write_buffer: [16 * 1024]u8 = undefined;
    var body_read_buffer: [16 * 1024]u8 = undefined;

    const start_ms: i64 = std.time.milliTimestamp();

    var reader = net.Stream.Reader.init(conn.stream, &read_buffer);
    var writer = net.Stream.Writer.init(conn.stream, &write_buffer);

    var server = http.Server.init(reader.interface(), &writer.interface);
    var request = try server.receiveHead();

    const method = request.head.method;
    const target = request.head.target;
    const path = targetPath(target);
    const content_type = request.head.content_type;

    var cookie: ?[]const u8 = null;
    var authorization: ?[]const u8 = null;
    var connection_hdr: ?[]const u8 = null;
    var upgrade_hdr: ?[]const u8 = null;
    var sec_ws_key: ?[]const u8 = null;
    var sec_ws_version: ?[]const u8 = null;
    var sec_ws_protocol: ?[]const u8 = null;

    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "cookie")) cookie = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) authorization = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) connection_hdr = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "upgrade")) upgrade_hdr = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-key")) sec_ws_key = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-version")) sec_ws_version = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-protocol")) sec_ws_protocol = h.value;
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    if (isStreamingWebSocketRequest(method, path, upgrade_hdr, connection_hdr, sec_ws_key, sec_ws_version)) {
        const q = targetQuery(target);
        var params = form.parse(alloc, q) catch form.Form{ .map = .empty };
        const stream_raw = params.get("stream") orelse "user";

        const token_q = params.get("access_token") orelse params.get("token");
        const token = token_q orelse bearerToken(authorization) orelse "";
        if (token.len == 0) {
            const resp: routes.Response = .{ .status = .unauthorized, .body = "unauthorized\n" };
            try writeResponse(&request, resp);
            logAccess(app_state, conn.address, method, target, resp.status, start_ms);
            return;
        }

        const info = oauth.verifyAccessToken(&app_state.conn, alloc, token) catch null;
        if (info == null) {
            const resp: routes.Response = .{ .status = .unauthorized, .body = "unauthorized\n" };
            try writeResponse(&request, resp);
            logAccess(app_state, conn.address, method, target, resp.status, start_ms);
            return;
        }

        const streams: []const streaming_hub.Stream = blk: {
            if (std.mem.eql(u8, stream_raw, "user")) break :blk &.{.user};
            if (std.mem.eql(u8, stream_raw, "public")) break :blk &.{.public};
            if (std.mem.eql(u8, stream_raw, "public:local")) break :blk &.{.public};
            // Minimal: ignore unknown streams but keep the connection.
            break :blk &.{.user};
        };

        const sub = app_state.streaming.subscribe(info.?.user_id, streams) catch {
            const resp: routes.Response = .{ .status = .internal_server_error, .body = "internal server error\n" };
            try writeResponse(&request, resp);
            logAccess(app_state, conn.address, method, target, resp.status, start_ms);
            return;
        };
        errdefer app_state.streaming.unsubscribe(sub);

        try writeWebSocketHandshake(conn.stream.handle, sec_ws_key.?, sec_ws_protocol);
        logAccess(app_state, conn.address, method, target, .switching_protocols, start_ms);

        const handler = try std.heap.page_allocator.create(StreamingHandler);
        handler.* = .{
            .logger = app_state.logger,
            .hub = app_state.streaming,
            .sub = sub,
            .stream = conn.stream,
        };

        close_conn = false;

        var t = std.Thread.spawn(.{}, StreamingHandler.run, .{handler}) catch |err| {
            app_state.logger.err("streaming: thread spawn failed err={any}", .{err});
            app_state.streaming.unsubscribe(sub);
            close_conn = true;
            std.heap.page_allocator.destroy(handler);
            return;
        };
        t.detach();
        return;
    }

    var body: []const u8 = "";
    if (request.head.method.requestHasBody()) {
        const default_max_len: usize = 1024 * 1024;
        const media_max_len: usize = 10 * 1024 * 1024;
        const max_len: usize = if (std.mem.eql(u8, path, "/api/v1/media")) media_max_len else default_max_len;
        const content_length: usize = @intCast(request.head.content_length orelse 0);
        if (content_length > max_len) {
            const resp: routes.Response = .{
                .status = .payload_too_large,
                .body = "payload too large\n",
            };
            try writeResponse(&request, resp);
            logAccess(app_state, conn.address, method, target, resp.status, start_ms);
            return;
        }

        request.head.expect = null;
        const body_reader = request.readerExpectNone(&body_read_buffer);
        body = body_reader.readAlloc(alloc, content_length) catch "";
    }

    const resp = routes.handle(app_state, alloc, .{
        .method = method,
        .target = target,
        .content_type = content_type,
        .body = body,
        .cookie = cookie,
        .authorization = authorization,
    });

    try writeResponse(&request, resp);
    logAccess(app_state, conn.address, method, target, resp.status, start_ms);
}

fn targetPath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| return target[0..idx];
    return target;
}

fn targetQuery(target: []const u8) []const u8 {
    const idx = std.mem.indexOfScalar(u8, target, '?') orelse return "";
    return target[idx + 1 ..];
}

fn bearerToken(authorization: ?[]const u8) ?[]const u8 {
    const hdr = authorization orelse return null;
    if (!std.mem.startsWith(u8, hdr, "Bearer ")) return null;
    return hdr["Bearer ".len..];
}

fn isStreamingWebSocketRequest(
    method: http.Method,
    path: []const u8,
    upgrade_hdr: ?[]const u8,
    connection_hdr: ?[]const u8,
    sec_ws_key: ?[]const u8,
    sec_ws_version: ?[]const u8,
) bool {
    if (method != .GET) return false;
    if (!std.mem.startsWith(u8, path, "/api/v1/streaming")) return false;

    const upgrade = upgrade_hdr orelse return false;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return false;

    const connection = connection_hdr orelse return false;
    if (!headerHasToken(connection, "upgrade")) return false;

    if (sec_ws_key == null) return false;

    const ver = sec_ws_version orelse return false;
    return std.mem.eql(u8, ver, "13");
}

fn headerHasToken(hdr_value: []const u8, token: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, hdr_value, ", \t");
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(part, token)) return true;
    }
    return false;
}

fn firstProtocolToken(hdr_value: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, hdr_value, ',');
    const raw = it.next() orelse return null;
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return null;
    if (std.mem.indexOfAny(u8, trimmed, "\r\n") != null) return null;
    return trimmed;
}

fn writeWebSocketHandshake(fd: std.posix.fd_t, sec_ws_key: []const u8, sec_ws_protocol: ?[]const u8) !void {
    const accept = websocket.computeAcceptKey(sec_ws_key);
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    try w.print("HTTP/1.1 101 Switching Protocols\r\n", .{});
    try w.print("Upgrade: websocket\r\n", .{});
    try w.print("Connection: Upgrade\r\n", .{});
    try w.print("Sec-WebSocket-Accept: {s}\r\n", .{accept[0..]});
    if (sec_ws_protocol) |hdr| {
        if (firstProtocolToken(hdr)) |proto| {
            try w.print("Sec-WebSocket-Protocol: {s}\r\n", .{proto});
        }
    }
    try w.print("\r\n", .{});

    try writeAll(fd, fbs.getWritten());
}

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        written += try std.posix.write(fd, data[written..]);
    }
}

const StreamingHandler = struct {
    logger: *log.Logger,
    hub: *streaming_hub.Hub,
    sub: *streaming_hub.Subscriber,
    stream: net.Stream,

    fn run(self: *@This()) void {
        defer {
            self.hub.unsubscribe(self.sub);
            self.stream.close();
            std.heap.page_allocator.destroy(self);
        }

        // Best-effort: enable non-blocking reads so we can respond to pings while waiting for messages.
        const flags = std.posix.fcntl(self.stream.handle, std.posix.F.GETFL, 0) catch 0;
        var oflags: std.posix.O = @bitCast(@as(u32, @intCast(flags)));
        oflags.NONBLOCK = true;
        const oflags_u32: u32 = @bitCast(oflags);
        _ = std.posix.fcntl(self.stream.handle, std.posix.F.SETFL, @intCast(oflags_u32)) catch {};

        var recv_buf: [16 * 1024]u8 = undefined;
        var recv_used: usize = 0;

        var write_buf: [16 * 1024]u8 = undefined;
        var writer = self.stream.writer(&write_buf);

        while (true) {
            if (self.sub.waitPop(250 * std.time.ns_per_ms)) |msg| {
                defer self.hub.allocator.free(msg);
                websocket.writeText(&writer.interface, msg) catch |err| {
                    self.logger.info("streaming: write failed err={any}", .{err});
                    return;
                };
                writer.interface.flush() catch {};
            }

            if (drainIncoming(&self.stream, &writer.interface, &recv_buf, &recv_used)) |stop| {
                if (stop) return;
            } else |_| {
                return;
            }
        }
    }
};

fn drainIncoming(stream: *net.Stream, writer: anytype, buf: []u8, used: *usize) !bool {
    while (true) {
        if (websocket.tryParseFrame(buf[0..used.*])) |maybe| {
            if (maybe == null) break;
            const res = maybe.?;
            const frame = res.frame;

            switch (frame.opcode) {
                .ping => {
                    websocket.writePong(writer, frame.payload) catch {};
                    writer.flush() catch {};
                },
                .close => {
                    websocket.writeClose(writer, "") catch {};
                    writer.flush() catch {};
                    return true;
                },
                else => {},
            }

            const remaining = used.* - res.consumed;
            if (remaining > 0) {
                std.mem.copyForwards(u8, buf[0..remaining], buf[res.consumed..used.*]);
            }
            used.* = remaining;
            continue;
        } else |err| {
            return err;
        }

        if (used.* >= buf.len) return error.FrameTooLarge;

        const n = std.posix.read(stream.handle, buf[used.*..]) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => return err,
        };
        if (n == 0) return true;
        used.* += n;
    }

    const n = std.posix.read(stream.handle, buf[used.*..]) catch |err| switch (err) {
        error.WouldBlock => return false,
        else => return err,
    };
    if (n == 0) return true;
    used.* += n;
    return false;
}

fn writeResponse(request: *http.Server.Request, resp: routes.Response) !void {
    const cors_headers = [_]http.Header{
        .{ .name = "access-control-allow-origin", .value = "*" },
        .{ .name = "access-control-allow-methods", .value = "GET, POST, PUT, PATCH, DELETE, OPTIONS" },
        .{ .name = "access-control-allow-headers", .value = "authorization, content-type, idempotency-key" },
        .{ .name = "access-control-expose-headers", .value = "link, location, mastodon-async-refresh" },
        .{ .name = "access-control-max-age", .value = "86400" },
    };

    const header_count: usize = 1 + cors_headers.len + resp.headers.len;
    var headers = try std.heap.page_allocator.alloc(http.Header, header_count);
    defer std.heap.page_allocator.free(headers);

    headers[0] = .{ .name = "content-type", .value = resp.content_type };
    for (cors_headers, 0..) |h, i| headers[i + 1] = h;
    for (resp.headers, 0..) |h, i| headers[1 + cors_headers.len + i] = h;

    try request.respond(resp.body, .{
        .status = resp.status,
        .keep_alive = false,
        .extra_headers = headers,
    });
}

fn logAccess(
    app_state: *app.App,
    remote_addr: net.Address,
    method: http.Method,
    target: []const u8,
    status: http.Status,
    start_ms: i64,
) void {
    const elapsed_ms: i64 = std.time.milliTimestamp() - start_ms;
    var addr_buf: [128]u8 = undefined;
    const addr_str = std.fmt.bufPrint(&addr_buf, "{any}", .{remote_addr}) catch "unknown";
    app_state.logger.info(
        "access remote={s} method={s} target={s} status={d} dur_ms={d}",
        .{ addr_str, @tagName(method), target, @intFromEnum(status), elapsed_ms },
    );
}

test "serveOnce: GET /healthz -> 200" {
    const listen_address = try net.Address.parseIp("127.0.0.1", 0);
    var listener = try listen_address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    const addr = listener.listen_address;

    var ctx: struct {
        addr: net.Address,
        ok: bool = false,
    } = .{ .addr = addr };

    const Client = struct {
        fn run(c: *@TypeOf(ctx)) !void {
            var stream = try net.tcpConnectToAddress(c.addr);
            defer stream.close();

            const req = "GET /healthz HTTP/1.1\r\n" ++
                "Host: localhost\r\n" ++
                "Connection: close\r\n" ++
                "\r\n";

            var written: usize = 0;
            while (written < req.len) {
                written += try std.posix.write(stream.handle, req[written..]);
            }

            var buf: [4096]u8 = undefined;
            var used: usize = 0;

            while (used < buf.len) {
                const n = try std.posix.read(stream.handle, buf[used..]);
                if (n == 0) break;
                used += n;
            }

            const resp = buf[0..used];

            c.ok = std.mem.startsWith(u8, resp, "HTTP/1.1 200") and
                (std.mem.indexOf(u8, resp, "\r\n\r\nok\n") != null);
        }
    };

    var t = try std.Thread.spawn(.{}, Client.run, .{&ctx});

    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    try serveOnce(&app_state, &listener);
    t.join();

    try std.testing.expect(ctx.ok);
}

test "serveOnce: WebSocket /api/v1/streaming upgrade receives update" {
    const listen_address = try net.Address.parseIp("127.0.0.1", 0);
    var listener = try listen_address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    const addr = listener.listen_address;

    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params: @import("password.zig").Params = .{ .t = 1, .m = 8, .p = 1 };
    const user_id = try @import("users.zig").create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const creds = try oauth.createApp(&app_state.conn, a, "pl-fe", "urn:ietf:wg:oauth:2.0:oob", "read write follow", "");
    const token = try oauth.createAccessToken(&app_state.conn, a, creds.id, user_id, "read write follow");

    var ctx: struct {
        addr: net.Address,
        token: []const u8,
        got_101: bool = false,
        got_protocol: bool = false,
        got_update: bool = false,
    } = .{ .addr = addr, .token = token };

    const Client = struct {
        fn run(c: *@TypeOf(ctx)) !void {
            var stream = try net.tcpConnectToAddress(c.addr);
            defer stream.close();

            const req = try std.fmt.allocPrint(
                std.testing.allocator,
                "GET /api/v1/streaming/?stream=user&access_token={s} HTTP/1.1\r\n" ++
                    "Host: example.test\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                    "Sec-WebSocket-Version: 13\r\n" ++
                    "Sec-WebSocket-Protocol: {s}\r\n" ++
                    "\r\n",
                .{ c.token, c.token },
            );
            defer std.testing.allocator.free(req);

            try writeAll(stream.handle, req);

            var buf: [4096]u8 = undefined;
            var used: usize = 0;
            while (used < buf.len) {
                const n = try std.posix.read(stream.handle, buf[used..]);
                if (n == 0) break;
                used += n;
                if (std.mem.indexOf(u8, buf[0..used], "\r\n\r\n") != null) break;
            }

            const head = buf[0..used];
            c.got_101 = std.mem.startsWith(u8, head, "HTTP/1.1 101");
            const expected_proto = try std.fmt.allocPrint(std.testing.allocator, "Sec-WebSocket-Protocol: {s}\r\n", .{c.token});
            defer std.testing.allocator.free(expected_proto);
            c.got_protocol = (std.mem.indexOf(u8, head, expected_proto) != null);

            // Read a single text frame.
            used = 0;
            while (used < buf.len) {
                const n = try std.posix.read(stream.handle, buf[used..]);
                if (n == 0) break;
                used += n;
                const res = try websocket.tryParseFrame(buf[0..used]);
                if (res) |r| {
                    c.got_update = (r.frame.opcode == .text) and (std.mem.indexOf(u8, r.frame.payload, "\"event\":\"update\"") != null);
                    break;
                }
            }
        }
    };

    var t = try std.Thread.spawn(.{}, Client.run, .{&ctx});

    try serveOnce(&app_state, &listener);
    // Publish after the subscriber has been registered (during handshake handling).
    app_state.streaming.publishUpdate(user_id, "{\"id\":\"1\"}");

    t.join();

    try std.testing.expect(ctx.got_101);
    try std.testing.expect(ctx.got_protocol);
    try std.testing.expect(ctx.got_update);

    // The streaming handler thread is detached; wait for it to notice the client disconnect and unsubscribe.
    var attempts: usize = 0;
    while (attempts < 50 and app_state.streaming.subscriberCount() != 0) : (attempts += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 0), app_state.streaming.subscriberCount());
}

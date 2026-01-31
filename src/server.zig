const std = @import("std");

const http = std.http;
const net = std.net;

const routes = @import("http.zig");
const app = @import("app.zig");

pub fn serve(app_state: *app.App, listen_address: net.Address) !void {
    var listener = try listen_address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    while (true) {
        try serveOnce(app_state, &listener);
    }
}

pub fn serveOnce(app_state: *app.App, listener: *net.Server) !void {
    var conn = try listener.accept();
    defer conn.stream.close();

    var read_buffer: [16 * 1024]u8 = undefined;
    var write_buffer: [16 * 1024]u8 = undefined;
    var body_read_buffer: [16 * 1024]u8 = undefined;

    var reader = net.Stream.Reader.init(conn.stream, &read_buffer);
    var writer = net.Stream.Writer.init(conn.stream, &write_buffer);

    var server = http.Server.init(reader.interface(), &writer.interface);
    var request = try server.receiveHead();

    const method = request.head.method;
    const target = request.head.target;
    const content_type = request.head.content_type;

    var cookie: ?[]const u8 = null;
    var authorization: ?[]const u8 = null;

    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "cookie")) cookie = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) authorization = h.value;
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var body: []const u8 = "";
    if (request.head.method.requestHasBody()) {
        const max_len: usize = 1024 * 1024;
        const content_length: usize = @intCast(request.head.content_length orelse 0);
        if (content_length > max_len) {
            const resp: routes.Response = .{
                .status = .payload_too_large,
                .body = "payload too large\n",
            };
            try writeResponse(&request, resp);
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
}

fn writeResponse(request: *http.Server.Request, resp: routes.Response) !void {
    const header_count: usize = 1 + resp.headers.len;
    var headers = try std.heap.page_allocator.alloc(http.Header, header_count);
    defer std.heap.page_allocator.free(headers);

    headers[0] = .{ .name = "content-type", .value = resp.content_type };
    for (resp.headers, 0..) |h, i| headers[i + 1] = h;

    try request.respond(resp.body, .{
        .status = resp.status,
        .keep_alive = false,
        .extra_headers = headers,
    });
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

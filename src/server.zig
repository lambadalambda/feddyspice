const std = @import("std");

const http = std.http;
const net = std.net;

const routes = @import("http.zig");

pub fn serve(listen_address: net.Address) !void {
    var listener = try listen_address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    while (true) {
        try serveOnce(&listener);
    }
}

pub fn serveOnce(listener: *net.Server) !void {
    var conn = try listener.accept();
    defer conn.stream.close();

    var read_buffer: [16 * 1024]u8 = undefined;
    var write_buffer: [16 * 1024]u8 = undefined;

    var reader = net.Stream.Reader.init(conn.stream, &read_buffer);
    var writer = net.Stream.Writer.init(conn.stream, &write_buffer);

    var server = http.Server.init(reader.interface(), &writer.interface);
    var request = try server.receiveHead();

    const resp = routes.route(request.head.method, request.head.target);
    const headers: [1]http.Header = .{
        .{ .name = "content-type", .value = resp.content_type },
    };

    try request.respond(resp.body, .{
        .status = resp.status,
        .keep_alive = false,
        .extra_headers = headers[0..],
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

    try serveOnce(&listener);
    t.join();

    try std.testing.expect(ctx.ok);
}

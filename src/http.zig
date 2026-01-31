const std = @import("std");

const app = @import("app.zig");
const form = @import("form.zig");
const sessions = @import("sessions.zig");
const users = @import("users.zig");
const version = @import("version.zig");

pub const Request = struct {
    method: std.http.Method,
    target: []const u8,
    content_type: ?[]const u8 = null,
    body: []const u8 = "",
    cookie: ?[]const u8 = null,
    authorization: ?[]const u8 = null,
};

pub const Response = struct {
    status: std.http.Status = .ok,
    content_type: []const u8 = "text/plain; charset=utf-8",
    body: []const u8,
    headers: []const std.http.Header = &.{},
};

pub fn handle(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const path = targetPath(req.target);

    if (req.method == .GET and std.mem.eql(u8, path, "/healthz")) {
        return .{ .body = "ok\n" };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/")) {
        const body =
            \\<!doctype html>
            \\<html>
            \\  <head><meta charset="utf-8"><title>feddyspice</title></head>
            \\  <body>
            \\    <h1>feddyspice</h1>
            \\    <p>This server is intended to be used with <a href="https://github.com/mkljczk/pl-fe">pl-fe</a>.</p>
            \\    <ul>
            \\      <li><a href="/signup">Sign up</a></li>
            \\      <li><a href="/login">Log in</a></li>
            \\    </ul>
            \\  </body>
            \\</html>
        ;

        return .{
            .content_type = "text/html; charset=utf-8",
            .body = body,
        };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/instance")) {
        const payload = .{
            .uri = app_state.cfg.domain,
            .title = "feddyspice",
            .short_description = "single-user server",
            .version = version.version,
            .registrations = true,
        };

        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return .{
            .content_type = "application/json; charset=utf-8",
            .body = body,
        };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/signup")) {
        const existing = users.count(&app_state.conn) catch 0;
        if (existing > 0) {
            return htmlPage(
                allocator,
                "Already set up",
                "<p>This instance already has a user. <a href=\"/login\">Log in</a>.</p>",
            );
        }

        const body =
            \\<form method="POST" action="/signup">
            \\  <label>Username <input name="username" autocomplete="username"></label><br>
            \\  <label>Password <input type="password" name="password" autocomplete="new-password"></label><br>
            \\  <button type="submit">Create account</button>
            \\</form>
        ;

        return htmlPage(allocator, "Sign up", body);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/signup")) {
        if (!isForm(req.content_type)) {
            return .{ .status = .bad_request, .body = "invalid content-type\n" };
        }

        var parsed = form.parse(allocator, req.body) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };

        const username = parsed.get("username") orelse
            return .{ .status = .bad_request, .body = "missing username\n" };
        const password_plain = parsed.get("password") orelse
            return .{ .status = .bad_request, .body = "missing password\n" };

        const user_id = users.create(
            &app_state.conn,
            allocator,
            username,
            password_plain,
            app_state.cfg.password_params,
        ) catch |err| switch (err) {
            error.SingleUserOnly => return htmlPage(allocator, "Already set up", "<p>User already exists.</p>"),
            else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
        };

        const token = sessions.create(&app_state.conn, allocator, user_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return redirectWithSession(allocator, app_state.cfg.scheme == .https, token, "/");
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/login")) {
        const body =
            \\<form method="POST" action="/login">
            \\  <label>Username <input name="username" autocomplete="username"></label><br>
            \\  <label>Password <input type="password" name="password" autocomplete="current-password"></label><br>
            \\  <button type="submit">Log in</button>
            \\</form>
        ;
        return htmlPage(allocator, "Log in", body);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/login")) {
        if (!isForm(req.content_type)) {
            return .{ .status = .bad_request, .body = "invalid content-type\n" };
        }

        var parsed = form.parse(allocator, req.body) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };

        const username = parsed.get("username") orelse
            return .{ .status = .bad_request, .body = "missing username\n" };
        const password_plain = parsed.get("password") orelse
            return .{ .status = .bad_request, .body = "missing password\n" };

        const user_id = users.authenticate(
            &app_state.conn,
            allocator,
            username,
            password_plain,
            app_state.cfg.password_params,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (user_id == null) {
            return htmlPage(allocator, "Log in", "<p>Invalid username or password.</p>");
        }

        const token = sessions.create(&app_state.conn, allocator, user_id.?) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return redirectWithSession(allocator, app_state.cfg.scheme == .https, token, "/");
    }

    return .{ .status = .not_found, .body = "not found\n" };
}

fn isForm(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "application/x-www-form-urlencoded");
}

fn htmlPage(allocator: std.mem.Allocator, title: []const u8, inner_html: []const u8) Response {
    const body = std.fmt.allocPrint(
        allocator,
        \\<!doctype html>
        \\<html>
        \\  <head><meta charset="utf-8"><title>{s}</title></head>
        \\  <body>
        \\    <h1>{s}</h1>
        \\    {s}
        \\  </body>
        \\</html>
    ,
        .{ title, title, inner_html },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "text/html; charset=utf-8",
        .body = body,
    };
}

fn redirectWithSession(
    allocator: std.mem.Allocator,
    secure_cookie: bool,
    token: []const u8,
    location: []const u8,
) Response {
    const cookie = cookieValue(allocator, secure_cookie, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const headers = allocator.alloc(std.http.Header, 2) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    headers[0] = .{ .name = "location", .value = location };
    headers[1] = .{ .name = "set-cookie", .value = cookie };

    return .{
        .status = .see_other,
        .body = "redirecting\n",
        .headers = headers,
    };
}

fn cookieValue(allocator: std.mem.Allocator, secure_cookie: bool, token: []const u8) ![]u8 {
    if (secure_cookie) {
        return std.fmt.allocPrint(
            allocator,
            "{s}={s}; HttpOnly; SameSite=Lax; Path=/; Secure",
            .{ sessions.CookieName, token },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{s}={s}; HttpOnly; SameSite=Lax; Path=/",
        .{ sessions.CookieName, token },
    );
}

fn targetPath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |idx| {
        return target[0..idx];
    }
    return target;
}

test "GET /healthz -> 200" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{ .method = .GET, .target = "/healthz" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
}

test "unknown route -> 404" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{ .method = .GET, .target = "/nope" });
    try std.testing.expectEqual(std.http.Status.not_found, resp.status);
}

test "GET /api/v1/instance -> 200 with uri" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{ .method = .GET, .target = "/api/v1/instance" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("example.test", parsed.value.object.get("uri").?.string);
}

test "POST /signup creates user and session cookie" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .POST,
        .target = "/signup",
        .content_type = "application/x-www-form-urlencoded",
        .body = "username=alice&password=password",
    });

    try std.testing.expectEqual(std.http.Status.see_other, resp.status);

    var set_cookie: ?[]const u8 = null;
    for (resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) set_cookie = h.value;
    }
    const cookie_value = set_cookie orelse return error.TestUnexpectedResult;

    const token = sessions.parseCookie(cookie_value) orelse return error.TestUnexpectedResult;
    const user_id = try sessions.lookupUserId(&app_state.conn, token);
    try std.testing.expect(user_id != null);
}

test "POST /login returns session cookie" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .POST,
        .target = "/login",
        .content_type = "application/x-www-form-urlencoded",
        .body = "username=alice&password=password",
    });

    try std.testing.expectEqual(std.http.Status.see_other, resp.status);

    var set_cookie: ?[]const u8 = null;
    for (resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) set_cookie = h.value;
    }
    try std.testing.expect(set_cookie != null);
}

const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const log = @import("../log.zig");
const rate_limit = @import("../rate_limit.zig");
const sessions = @import("../sessions.zig");
const session = @import("session.zig");
const users = @import("../users.zig");

pub fn signupGet(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const existing = users.count(&app_state.conn) catch 0;
    if (existing > 0) {
        return common.htmlPage(
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

    return common.htmlPage(allocator, "Sign up", body);
}

pub fn signupPost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    if (!common.isForm(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid content-type\n" };
    }
    if (!common.isSameOrigin(req, @tagName(app_state.cfg.scheme), app_state.cfg.domain)) {
        const path = common.targetPath(req.target);
        app_state.logger.warn(
            "sameOrigin: reject path={f} expected={s}://{f} host={f} origin={f} referer={f}",
            .{
                log.safe(path),
                @tagName(app_state.cfg.scheme),
                log.safe(app_state.cfg.domain),
                log.safe(req.host orelse ""),
                log.safe(req.origin orelse ""),
                log.safe(req.referer orelse ""),
            },
        );
        return .{ .status = .forbidden, .body = "forbidden\n" };
    }
    const ok = rate_limit.allowNow(&app_state.conn, "signup_post", 60_000, 10) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .too_many_requests, .body = "too many requests\n" };

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
        error.SingleUserOnly => return common.htmlPage(allocator, "Already set up", "<p>User already exists.</p>"),
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    const token = sessions.create(&app_state.conn, allocator, user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return session.redirectWithSession(allocator, app_state.cfg.scheme == .https, token, "/");
}

pub fn loginGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    _ = app_state;
    const q = common.queryString(req.target);
    const return_to = common.parseQueryParam(allocator, q, "return_to") catch null;

    const extra = if (return_to) |rt| blk: {
        const escaped = common.htmlEscapeAlloc(allocator, rt) catch break :blk "";
        break :blk std.fmt.allocPrint(
            allocator,
            "<input type=\"hidden\" name=\"return_to\" value=\"{s}\">",
            .{escaped},
        ) catch "";
    } else "";

    const full = std.fmt.allocPrint(
        allocator,
        \\<form method="POST" action="/login">
        \\  <label>Username <input name="username" autocomplete="username"></label><br>
        \\  <label>Password <input type="password" name="password" autocomplete="current-password"></label><br>
        \\  {s}
        \\  <button type="submit">Log in</button>
        \\</form>
    ,
        .{extra},
    ) catch
        \\<form method="POST" action="/login">
        \\  <label>Username <input name="username" autocomplete="username"></label><br>
        \\  <label>Password <input type="password" name="password" autocomplete="current-password"></label><br>
        \\  <button type="submit">Log in</button>
        \\</form>
    ;

    return common.htmlPage(allocator, "Log in", full);
}

pub fn loginPost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    if (!common.isForm(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid content-type\n" };
    }
    if (!common.isSameOrigin(req, @tagName(app_state.cfg.scheme), app_state.cfg.domain)) {
        const path = common.targetPath(req.target);
        app_state.logger.warn(
            "sameOrigin: reject path={f} expected={s}://{f} host={f} origin={f} referer={f}",
            .{
                log.safe(path),
                @tagName(app_state.cfg.scheme),
                log.safe(app_state.cfg.domain),
                log.safe(req.host orelse ""),
                log.safe(req.origin orelse ""),
                log.safe(req.referer orelse ""),
            },
        );
        return .{ .status = .forbidden, .body = "forbidden\n" };
    }
    const ok = rate_limit.allowNow(&app_state.conn, "login_post", 60_000, 20) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .too_many_requests, .body = "too many requests\n" };

    var parsed = form.parse(allocator, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const username = parsed.get("username") orelse
        return .{ .status = .bad_request, .body = "missing username\n" };
    const password_plain = parsed.get("password") orelse
        return .{ .status = .bad_request, .body = "missing password\n" };
    const return_to = parsed.get("return_to");

    const user_id = users.authenticate(
        &app_state.conn,
        allocator,
        username,
        password_plain,
        app_state.cfg.password_params,
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (user_id == null) {
        return common.htmlPage(allocator, "Log in", "<p>Invalid username or password.</p>");
    }

    const token = sessions.create(&app_state.conn, allocator, user_id.?) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const location = common.safeReturnTo(return_to) orelse "/";
    return session.redirectWithSession(allocator, app_state.cfg.scheme == .https, token, location);
}

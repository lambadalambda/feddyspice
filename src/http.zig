const std = @import("std");

const app = @import("app.zig");
const form = @import("form.zig");
const oauth = @import("oauth.zig");
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

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/apps")) {
        if (!isForm(req.content_type)) {
            return .{ .status = .bad_request, .body = "invalid content-type\n" };
        }

        var parsed = form.parse(allocator, req.body) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };

        const client_name = parsed.get("client_name") orelse
            return .{ .status = .bad_request, .body = "missing client_name\n" };
        const redirect_uris = parsed.get("redirect_uris") orelse
            return .{ .status = .bad_request, .body = "missing redirect_uris\n" };
        const scopes = parsed.get("scopes") orelse "";
        const website = parsed.get("website") orelse "";

        const creds = oauth.createApp(&app_state.conn, allocator, client_name, redirect_uris, scopes, website) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const id_str = std.fmt.allocPrint(allocator, "{d}", .{creds.id}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const payload = .{
            .id = id_str,
            .name = client_name,
            .website = website,
            .redirect_uri = redirect_uris,
            .client_id = creds.client_id,
            .client_secret = creds.client_secret,
            .vapid_key = "",
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
        const q = queryString(req.target);
        const return_to = parseQueryParam(allocator, q, "return_to") catch null;

        const extra = if (return_to) |rt| blk: {
            const escaped = htmlEscapeAlloc(allocator, rt) catch break :blk "";
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

        return htmlPage(allocator, "Log in", full);
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
        const return_to = parsed.get("return_to");

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

        const location = safeReturnTo(return_to) orelse "/";
        return redirectWithSession(allocator, app_state.cfg.scheme == .https, token, location);
    }

    if (std.mem.eql(u8, path, "/oauth/authorize")) {
        if (req.method == .GET) return oauthAuthorizeGet(app_state, allocator, req);
        if (req.method == .POST) return oauthAuthorizePost(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/oauth/token")) {
        return oauthToken(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/verify_credentials")) {
        return verifyCredentials(app_state, allocator, req);
    }

    return .{ .status = .not_found, .body = "not found\n" };
}

fn verifyCredentials(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    const id_str = std.fmt.allocPrint(allocator, "{d}", .{user.?.id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .id = id_str,
        .username = user.?.username,
        .acct = user.?.username,
        .display_name = "",
        .note = "",
        .url = "",
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.?.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = "",
        .avatar_static = "",
        .header = "",
        .header_static = "",
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn bearerToken(authorization: ?[]const u8) ?[]const u8 {
    const h = authorization orelse return null;
    const prefix = "Bearer ";
    if (h.len < prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(h[0..prefix.len], prefix)) return null;
    return std.mem.trim(u8, h[prefix.len..], " \t");
}

fn unauthorized(allocator: std.mem.Allocator) Response {
    const body = std.json.Stringify.valueAlloc(allocator, .{ .@"error" = "unauthorized" }, .{}) catch
        return .{ .status = .unauthorized, .body = "unauthorized\n" };
    return .{
        .status = .unauthorized,
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn oauthAuthorizeGet(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const q = queryString(req.target);
    var query = form.parse(allocator, q) catch
        return .{ .status = .bad_request, .body = "invalid query\n" };

    const response_type = query.get("response_type") orelse "";
    if (!std.mem.eql(u8, response_type, "code")) {
        return .{ .status = .bad_request, .body = "unsupported response_type\n" };
    }

    const client_id = query.get("client_id") orelse
        return .{ .status = .bad_request, .body = "missing client_id\n" };
    const redirect_uri = query.get("redirect_uri") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uri\n" };
    const scope = query.get("scope") orelse "";
    const state = query.get("state") orelse "";

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (app_row == null) return .{ .status = .bad_request, .body = "unknown client_id\n" };
    if (!oauth.redirectUriAllowed(app_row.?.redirect_uris, redirect_uri)) {
        return .{ .status = .bad_request, .body = "invalid redirect_uri\n" };
    }

    const user_id = currentUserId(app_state, req) catch null;
    if (user_id == null) {
        const encoded = percentEncodeAlloc(allocator, req.target) catch "";
        const location = std.fmt.allocPrint(allocator, "/login?return_to={s}", .{encoded}) catch "/login";
        return redirect(allocator, location);
    }

    const app_name = htmlEscapeAlloc(allocator, app_row.?.name) catch app_row.?.name;

    const page = std.fmt.allocPrint(
        allocator,
        \\<p>Authorize <strong>{s}</strong>?</p>
        \\<form method="POST" action="/oauth/authorize">
        \\  <input type="hidden" name="response_type" value="code">
        \\  <input type="hidden" name="client_id" value="{s}">
        \\  <input type="hidden" name="redirect_uri" value="{s}">
        \\  <input type="hidden" name="scope" value="{s}">
        \\  <input type="hidden" name="state" value="{s}">
        \\  <button type="submit" name="approve" value="1">Authorize</button>
        \\  <button type="submit" name="deny" value="1">Deny</button>
        \\</form>
    ,
        .{ app_name, client_id, redirect_uri, scope, state },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return htmlPage(allocator, "Authorize", page);
}

fn oauthAuthorizePost(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    if (!isForm(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid content-type\n" };
    }

    const user_id = currentUserId(app_state, req) catch null;
    if (user_id == null) return redirect(allocator, "/login");

    var parsed = form.parse(allocator, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const response_type = parsed.get("response_type") orelse "";
    if (!std.mem.eql(u8, response_type, "code")) {
        return .{ .status = .bad_request, .body = "unsupported response_type\n" };
    }

    const client_id = parsed.get("client_id") orelse
        return .{ .status = .bad_request, .body = "missing client_id\n" };
    const redirect_uri = parsed.get("redirect_uri") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uri\n" };
    const scope = parsed.get("scope") orelse "";
    const state = parsed.get("state") orelse "";
    const deny = parsed.get("deny");

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (app_row == null) return .{ .status = .bad_request, .body = "unknown client_id\n" };
    if (!oauth.redirectUriAllowed(app_row.?.redirect_uris, redirect_uri)) {
        return .{ .status = .bad_request, .body = "invalid redirect_uri\n" };
    }

    if (deny != null) {
        const loc = oauthErrorRedirect(allocator, redirect_uri, "access_denied", state) catch redirect_uri;
        return redirect(allocator, loc);
    }

    const code = oauth.createAuthCode(&app_state.conn, allocator, app_row.?.id, user_id.?, redirect_uri, scope) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (std.mem.eql(u8, redirect_uri, "urn:ietf:wg:oauth:2.0:oob")) {
        const page = std.fmt.allocPrint(allocator, "<p>Authorization code:</p><pre id=\"code\">{s}</pre>", .{code}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        return htmlPage(allocator, "Authorization code", page);
    }

    const loc = oauthCodeRedirect(allocator, redirect_uri, code, state) catch redirect_uri;
    return redirect(allocator, loc);
}

fn oauthToken(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    if (!isForm(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid content-type\n" };
    }

    var parsed = form.parse(allocator, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const grant_type = parsed.get("grant_type") orelse "";
    if (!std.mem.eql(u8, grant_type, "authorization_code")) {
        return .{ .status = .bad_request, .body = "unsupported grant_type\n" };
    }

    const code = parsed.get("code") orelse
        return .{ .status = .bad_request, .body = "missing code\n" };
    const client_id = parsed.get("client_id") orelse
        return .{ .status = .bad_request, .body = "missing client_id\n" };
    const client_secret = parsed.get("client_secret") orelse
        return .{ .status = .bad_request, .body = "missing client_secret\n" };
    const redirect_uri = parsed.get("redirect_uri") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uri\n" };

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (app_row == null) return .{ .status = .bad_request, .body = "unknown client_id\n" };
    if (!std.mem.eql(u8, app_row.?.client_secret, client_secret)) {
        return .{ .status = .unauthorized, .body = "invalid client_secret\n" };
    }

    const consumed = oauth.consumeAuthCode(&app_state.conn, allocator, code) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (consumed == null) return .{ .status = .bad_request, .body = "invalid code\n" };
    if (consumed.?.app_id != app_row.?.id) return .{ .status = .bad_request, .body = "invalid code\n" };
    if (!std.mem.eql(u8, consumed.?.redirect_uri, redirect_uri)) return .{ .status = .bad_request, .body = "invalid code\n" };

    const token = oauth.createAccessToken(&app_state.conn, allocator, app_row.?.id, consumed.?.user_id, consumed.?.scopes) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .access_token = token,
        .token_type = "Bearer",
        .scope = consumed.?.scopes,
        .created_at = std.time.timestamp(),
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn oauthCodeRedirect(allocator: std.mem.Allocator, redirect_uri: []const u8, code: []const u8, state: []const u8) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, redirect_uri, '?') == null) "?" else "&";
    if (state.len > 0) {
        return std.fmt.allocPrint(allocator, "{s}{s}code={s}&state={s}", .{ redirect_uri, sep, code, state });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}code={s}", .{ redirect_uri, sep, code });
}

fn oauthErrorRedirect(allocator: std.mem.Allocator, redirect_uri: []const u8, err: []const u8, state: []const u8) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, redirect_uri, '?') == null) "?" else "&";
    if (state.len > 0) {
        return std.fmt.allocPrint(allocator, "{s}{s}error={s}&state={s}", .{ redirect_uri, sep, err, state });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}error={s}", .{ redirect_uri, sep, err });
}

fn currentUserId(app_state: *app.App, req: Request) !?i64 {
    const cookie_header = req.cookie orelse return null;
    const token = sessions.parseCookie(cookie_header) orelse return null;
    return try sessions.lookupUserId(&app_state.conn, token);
}

fn redirect(allocator: std.mem.Allocator, location: []const u8) Response {
    const headers = allocator.alloc(std.http.Header, 1) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    headers[0] = .{ .name = "location", .value = location };

    return .{
        .status = .see_other,
        .body = "redirecting\n",
        .headers = headers,
    };
}

fn safeReturnTo(return_to: ?[]const u8) ?[]const u8 {
    const rt = return_to orelse return null;
    if (!std.mem.startsWith(u8, rt, "/")) return null;
    if (std.mem.indexOf(u8, rt, "://") != null) return null;
    return rt;
}

fn queryString(target: []const u8) []const u8 {
    const idx = std.mem.indexOfScalar(u8, target, '?') orelse return "";
    return target[idx + 1 ..];
}

fn parseQueryParam(allocator: std.mem.Allocator, query: []const u8, name: []const u8) !?[]const u8 {
    if (query.len == 0) return null;
    var parsed = try form.parse(allocator, query);
    return parsed.get(name);
}

fn percentEncodeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    for (raw) |c| {
        if (isUnreserved(c)) {
            try aw.writer.writeByte(c);
        } else {
            try aw.writer.print("%{X:0>2}", .{c});
        }
    }

    const out = try aw.toOwnedSlice();
    aw.deinit();
    return out;
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn htmlEscapeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var needed: usize = 0;
    for (raw) |c| {
        needed += switch (c) {
            '&' => 5, // &amp;
            '<', '>' => 4, // &lt; &gt;
            '"' => 6, // &quot;
            '\'' => 5, // &#39;
            else => 1,
        };
    }

    var out = try allocator.alloc(u8, needed);
    var i: usize = 0;

    for (raw) |c| {
        const repl = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            else => null,
        };

        if (repl) |s| {
            @memcpy(out[i..][0..s.len], s);
            i += s.len;
        } else {
            out[i] = c;
            i += 1;
        }
    }

    return out;
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

test "POST /api/v1/apps registers app" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .POST,
        .target = "/api/v1/apps",
        .content_type = "application/x-www-form-urlencoded",
        .body = "client_name=pl-fe&redirect_uris=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scopes=read+write&website=",
    });

    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(obj.get("client_id") != null);
    try std.testing.expect(obj.get("client_secret") != null);
    try std.testing.expectEqualStrings("urn:ietf:wg:oauth:2.0:oob", obj.get("redirect_uri").?.string);
}

test "oauth: authorization code flow (oob)" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/apps",
        .content_type = "application/x-www-form-urlencoded",
        .body = "client_name=pl-fe&redirect_uris=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scopes=read+write+follow&website=",
    });
    try std.testing.expectEqual(std.http.Status.ok, app_resp.status);

    var app_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, app_resp.body, .{});
    defer app_json.deinit();

    const client_id = app_json.value.object.get("client_id").?.string;
    const client_secret = app_json.value.object.get("client_secret").?.string;

    const signup_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/signup",
        .content_type = "application/x-www-form-urlencoded",
        .body = "username=alice&password=password",
    });
    try std.testing.expectEqual(std.http.Status.see_other, signup_resp.status);

    var set_cookie: ?[]const u8 = null;
    for (signup_resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) set_cookie = h.value;
    }
    const token = sessions.parseCookie(set_cookie orelse return error.TestUnexpectedResult) orelse
        return error.TestUnexpectedResult;

    const cookie_header = std.fmt.allocPrint(a, "{s}={s}", .{ sessions.CookieName, token }) catch
        return error.OutOfMemory;

    const auth_target = std.fmt.allocPrint(
        a,
        "/oauth/authorize?response_type=code&client_id={s}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scope=read+write&state=xyz",
        .{client_id},
    ) catch return error.OutOfMemory;

    const auth_get = handle(&app_state, a, .{
        .method = .GET,
        .target = auth_target,
        .cookie = cookie_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, auth_get.status);

    const auth_post_body = std.fmt.allocPrint(
        a,
        "response_type=code&client_id={s}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scope=read+write&state=xyz&approve=1",
        .{client_id},
    ) catch return error.OutOfMemory;

    const auth_post = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/authorize",
        .content_type = "application/x-www-form-urlencoded",
        .body = auth_post_body,
        .cookie = cookie_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, auth_post.status);

    const code = extractBetween(auth_post.body, "<pre id=\"code\">", "</pre>") orelse
        return error.TestUnexpectedResult;

    const token_body = std.fmt.allocPrint(
        a,
        "grant_type=authorization_code&code={s}&client_id={s}&client_secret={s}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob",
        .{ code, client_id, client_secret },
    ) catch return error.OutOfMemory;

    const token_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/token",
        .content_type = "application/x-www-form-urlencoded",
        .body = token_body,
    });
    try std.testing.expectEqual(std.http.Status.ok, token_resp.status);

    var token_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, token_resp.body, .{});
    defer token_json.deinit();

    try std.testing.expect(token_json.value.object.get("access_token") != null);
    try std.testing.expectEqualStrings("Bearer", token_json.value.object.get("token_type").?.string);
}

test "GET /api/v1/accounts/verify_credentials works with bearer token" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/apps",
        .content_type = "application/x-www-form-urlencoded",
        .body = "client_name=pl-fe&redirect_uris=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scopes=read+write&website=",
    });
    var app_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, app_resp.body, .{});
    defer app_json.deinit();

    const client_id = app_json.value.object.get("client_id").?.string;
    const client_secret = app_json.value.object.get("client_secret").?.string;

    const signup_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/signup",
        .content_type = "application/x-www-form-urlencoded",
        .body = "username=alice&password=password",
    });
    var set_cookie: ?[]const u8 = null;
    for (signup_resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) set_cookie = h.value;
    }
    const session_token = sessions.parseCookie(set_cookie orelse return error.TestUnexpectedResult) orelse
        return error.TestUnexpectedResult;

    const cookie_header = std.fmt.allocPrint(a, "{s}={s}", .{ sessions.CookieName, session_token }) catch
        return error.OutOfMemory;

    const auth_post_body = std.fmt.allocPrint(
        a,
        "response_type=code&client_id={s}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scope=read+write&state=&approve=1",
        .{client_id},
    ) catch return error.OutOfMemory;

    const auth_post = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/authorize",
        .content_type = "application/x-www-form-urlencoded",
        .body = auth_post_body,
        .cookie = cookie_header,
    });

    const code = extractBetween(auth_post.body, "<pre id=\"code\">", "</pre>") orelse
        return error.TestUnexpectedResult;

    const token_body = std.fmt.allocPrint(
        a,
        "grant_type=authorization_code&code={s}&client_id={s}&client_secret={s}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob",
        .{ code, client_id, client_secret },
    ) catch return error.OutOfMemory;

    const token_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/token",
        .content_type = "application/x-www-form-urlencoded",
        .body = token_body,
    });

    var token_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, token_resp.body, .{});
    defer token_json.deinit();

    const access_token = token_json.value.object.get("access_token").?.string;
    const auth_header = std.fmt.allocPrint(a, "Bearer {s}", .{access_token}) catch return error.OutOfMemory;

    const resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/accounts/verify_credentials",
        .authorization = auth_header,
    });

    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("alice", parsed.value.object.get("username").?.string);
}

fn extractBetween(haystack: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, haystack, start) orelse return null;
    const j = std.mem.indexOfPos(u8, haystack, i + start.len, end) orelse return null;
    return haystack[i + start.len .. j];
}

const std = @import("std");

const app = @import("app.zig");
const actor_keys = @import("actor_keys.zig");
const db = @import("db.zig");
const federation = @import("federation.zig");
const background = @import("background.zig");
const form = @import("form.zig");
const follows = @import("follows.zig");
const followers = @import("followers.zig");
const inbox_dedupe = @import("inbox_dedupe.zig");
const media = @import("media.zig");
const notifications = @import("notifications.zig");
const oauth = @import("oauth.zig");
const remote_actors = @import("remote_actors.zig");
const remote_statuses = @import("remote_statuses.zig");
const sessions = @import("sessions.zig");
const statuses = @import("statuses.zig");
const transport = @import("transport.zig");
const users = @import("users.zig");
const version = @import("version.zig");

const transparent_png = [_]u8{
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0xb5, 0x1c, 0x0c,
    0x02, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xff, 0x1f, 0x00,
    0x03, 0x03, 0x02, 0x00, 0xef, 0xa4, 0xbe, 0x95, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82,
};

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

    if (req.method == .OPTIONS) {
        return .{ .status = .no_content, .body = "" };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/healthz")) {
        return .{ .body = "ok\n" };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/metrics")) {
        return metrics(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/static/avatar.png")) {
        return .{
            .content_type = "image/png",
            .body = transparent_png[0..],
        };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/static/header.png")) {
        return .{
            .content_type = "image/png",
            .body = transparent_png[0..],
        };
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/media/")) {
        return mediaFileGet(app_state, allocator, req, path);
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

    if (req.method == .GET and std.mem.eql(u8, path, "/.well-known/webfinger")) {
        return webfinger(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/.well-known/host-meta")) {
        return hostMeta(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/.well-known/nodeinfo")) {
        return nodeinfoDiscovery(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/nodeinfo/2.0")) {
        return nodeinfoDocument(app_state, allocator);
    }

    if (std.mem.startsWith(u8, path, "/users/")) {
        if (req.method == .POST and std.mem.endsWith(u8, path, "/inbox")) {
            return inboxPost(app_state, allocator, req, path);
        }

        if (req.method == .GET) {
            if (std.mem.endsWith(u8, path, "/followers")) return followersGet(app_state, allocator, path);
            if (std.mem.endsWith(u8, path, "/following")) return followingGet(app_state, allocator, path);
            if (std.mem.endsWith(u8, path, "/outbox")) return outboxGet(app_state, allocator, req, path);
            if (std.mem.indexOf(u8, path, "/statuses/") != null) return userStatusGet(app_state, allocator, path);
            return actorGet(app_state, allocator, path);
        }
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

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/instance")) {
        const streaming_url = streamingBaseUrlAlloc(app_state, allocator) catch "";
        const payload = .{
            .domain = app_state.cfg.domain,
            .title = "feddyspice",
            .version = version.version,
            .source_url = "",
            .description = "single-user server",
            .registrations = .{
                .enabled = true,
                .approval_required = false,
            },
            .thumbnail = .{ .url = "" },
            .languages = [_][]const u8{"en"},
            .configuration = .{
                .urls = .{ .streaming = streaming_url },
                .polls = .{
                    .max_characters_per_option = 25,
                    .max_expiration = 2629746,
                    .max_options = 4,
                    .min_expiration = 300,
                },
                .statuses = .{
                    .max_characters = 500,
                    .max_media_attachments = 4,
                },
                .vapid = .{ .public_key = "" },
            },
            .usage = .{ .users = .{ .active_month = 1 } },
            .rules = [_]struct { id: []const u8, text: []const u8 }{},
        };

        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return .{
            .content_type = "application/json; charset=utf-8",
            .body = body,
        };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/streaming/health")) {
        return .{
            .content_type = "application/json; charset=utf-8",
            .body = "\"OK\"",
        };
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/streaming")) {
        return .{ .status = .not_implemented, .body = "streaming not implemented\n" };
    }

    // --- Client-compat placeholders (Elk/pl-fe) ---
    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/custom_emojis")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/notifications")) {
        return notificationsGet(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/notifications/clear")) {
        return notificationsClear(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/notifications/") and std.mem.endsWith(u8, path, "/dismiss")) {
        return notificationsDismiss(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/follow_requests")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/scheduled_statuses")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/lists")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/announcements")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/trends/tags")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/filters")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/suggestions")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/followed_tags")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/preferences")) {
        const payload: struct {} = .{};
        return jsonOk(allocator, payload);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/push/subscription")) {
        const payload: struct {} = .{};
        return jsonOk(allocator, payload);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/search")) {
        return apiV2Search(app_state, allocator, req);
    }

    if (std.mem.eql(u8, path, "/api/v1/markers")) {
        if (req.method == .GET or req.method == .POST) {
            const updated_at = "1970-01-01T00:00:00.000Z";
            return jsonOk(allocator, .{
                .home = .{ .last_read_id = "0", .version = 0, .updated_at = updated_at },
                .notifications = .{ .last_read_id = "0", .version = 0, .updated_at = updated_at },
            });
        }
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/apps")) {
        var parsed = parseBodyParams(allocator, req) catch
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

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/lookup")) {
        return accountLookup(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/relationships")) {
        return accountRelationships(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/statuses")) {
        return accountStatuses(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/followers")) {
        return accountFollowers(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/following")) {
        return accountFollowing(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/follow")) {
        return accountFollow(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/unfollow")) {
        return accountUnfollow(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/")) {
        const rest = path["/api/v1/accounts/".len..];
        if (std.mem.indexOfScalar(u8, rest, '/') == null) {
            return accountGet(app_state, allocator, path);
        }
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/follows")) {
        return apiFollow(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/media")) {
        return createMedia(app_state, allocator, req);
    }

    if (req.method == .PUT and std.mem.startsWith(u8, path, "/api/v1/media/")) {
        return updateMedia(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/statuses")) {
        return createStatus(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/favourite")) {
        return statusActionNoop(app_state, allocator, req, path, "/favourite");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unfavourite")) {
        return statusActionNoop(app_state, allocator, req, path, "/unfavourite");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/reblog")) {
        return statusActionNoop(app_state, allocator, req, path, "/reblog");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unreblog")) {
        return statusActionNoop(app_state, allocator, req, path, "/unreblog");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/bookmark")) {
        return statusActionNoop(app_state, allocator, req, path, "/bookmark");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unbookmark")) {
        return statusActionNoop(app_state, allocator, req, path, "/unbookmark");
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/timelines/tag/")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/timelines/list/")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/link")) {
        return jsonOk(allocator, [_]i32{});
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/public")) {
        return publicTimeline(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/home")) {
        return homeTimeline(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/context")) {
        return statusContext(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/statuses/")) {
        return getStatus(app_state, allocator, req, path);
    }

    if (req.method == .DELETE and std.mem.startsWith(u8, path, "/api/v1/statuses/")) {
        return deleteStatus(app_state, allocator, req, path);
    }

    return .{ .status = .not_found, .body = "not found\n" };
}

fn metrics(app_state: *app.App, allocator: std.mem.Allocator) Response {
    const CountError = db.Error || std.mem.Allocator.Error;
    const count: *const fn (conn: *db.Db, sql: [:0]const u8) CountError!i64 = struct {
        fn f(conn: *db.Db, sql: [:0]const u8) CountError!i64 {
            var stmt = try conn.prepareZ(sql);
            defer stmt.finalize();
            switch (try stmt.step()) {
                .row => return stmt.columnInt64(0),
                .done => return 0,
            }
        }
    }.f;

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    const jobs_queued = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='queued';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const jobs_running = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='running';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const jobs_dead = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='dead';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const inbox_dedupe_total = count(&app_state.conn, "SELECT COUNT(*) FROM inbox_dedupe;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const statuses_local = count(&app_state.conn, "SELECT COUNT(*) FROM statuses WHERE deleted_at IS NULL;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const statuses_remote = count(&app_state.conn, "SELECT COUNT(*) FROM remote_statuses WHERE deleted_at IS NULL;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    aw.writer.print("# HELP feddyspice_build_info Build info.\n", .{}) catch {};
    aw.writer.print("# TYPE feddyspice_build_info gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_build_info{{version=\"{s}\"}} 1\n", .{version.version}) catch {};

    aw.writer.print("# TYPE feddyspice_jobs_queued gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_queued {d}\n", .{jobs_queued}) catch {};
    aw.writer.print("# TYPE feddyspice_jobs_running gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_running {d}\n", .{jobs_running}) catch {};
    aw.writer.print("# TYPE feddyspice_jobs_dead gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_dead {d}\n", .{jobs_dead}) catch {};

    aw.writer.print("# TYPE feddyspice_inbox_dedupe_total gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_inbox_dedupe_total {d}\n", .{inbox_dedupe_total}) catch {};

    aw.writer.print("# TYPE feddyspice_statuses_local gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_statuses_local {d}\n", .{statuses_local}) catch {};
    aw.writer.print("# TYPE feddyspice_statuses_remote gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_statuses_remote {d}\n", .{statuses_remote}) catch {};

    const body = aw.toOwnedSlice() catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    aw.deinit();

    return .{
        .content_type = "text/plain; version=0.0.4; charset=utf-8",
        .body = body,
    };
}

fn baseUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

fn streamingBaseUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    const scheme: []const u8 = switch (app_state.cfg.scheme) {
        .https => "wss",
        .http => "ws",
    };
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme, app_state.cfg.domain });
}

fn hostMeta(app_state: *app.App, allocator: std.mem.Allocator) Response {
    const scheme = @tagName(app_state.cfg.scheme);
    const domain = app_state.cfg.domain;

    const body = std.fmt.allocPrint(
        allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
        \\  <Link rel="lrdd" type="application/jrd+json" template="{s}://{s}/.well-known/webfinger?resource={{uri}}" />
        \\</XRD>
        \\
    ,
        .{ scheme, domain },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/xrd+xml; charset=utf-8",
        .body = body,
    };
}

fn defaultAvatarUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/static/avatar.png", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

fn defaultHeaderUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/static/header.png", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
    });
}

fn userUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}", .{
        @tagName(app_state.cfg.scheme),
        app_state.cfg.domain,
        username,
    });
}

fn webfinger(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const q = queryString(req.target);
    const resource = parseQueryParam(allocator, q, "resource") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    if (resource == null) return .{ .status = .bad_request, .body = "missing resource\n" };

    const prefix = "acct:";
    if (!std.mem.startsWith(u8, resource.?, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const acct = resource.?[prefix.len..];
    const at = std.mem.indexOfScalar(u8, acct, '@') orelse return .{ .status = .not_found, .body = "not found\n" };
    const username = acct[0..at];
    const domain = acct[at + 1 ..];
    if (!std.mem.eql(u8, domain, app_state.cfg.domain)) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const href = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const Link = struct {
        rel: []const u8,
        type: []const u8,
        href: []const u8,
    };

    const payload = .{
        .subject = resource.?,
        .links = [_]Link{
            .{ .rel = "self", .type = "application/activity+json", .href = href },
        },
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/jrd+json; charset=utf-8",
        .body = body,
    };
}

fn nodeinfoDiscovery(app_state: *app.App, allocator: std.mem.Allocator) Response {
    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const href = std.fmt.allocPrint(allocator, "{s}/nodeinfo/2.0", .{base}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .links = [_]struct { rel: []const u8, href: []const u8 }{
            .{
                .rel = "http://nodeinfo.diaspora.software/ns/schema/2.0",
                .href = href,
            },
        },
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn nodeinfoDocument(app_state: *app.App, allocator: std.mem.Allocator) Response {
    const user_count = users.count(&app_state.conn) catch 0;
    const open_registrations = (user_count == 0);

    const payload = .{
        .version = "2.0",
        .software = .{
            .name = "feddyspice",
            .version = version.version,
        },
        .protocols = [_][]const u8{"activitypub"},
        .services = .{
            .inbound = [_][]const u8{},
            .outbound = [_][]const u8{},
        },
        .openRegistrations = open_registrations,
        .usage = .{
            .users = .{
                .total = user_count,
            },
            .localPosts = @as(i64, 0),
        },
        .metadata = .{},
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn actorGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) Response {
    const username = path["/users/".len..];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const keys = actor_keys.ensureForUser(&app_state.conn, allocator, user.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const actor_id = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const inbox = std.fmt.allocPrint(allocator, "{s}/users/{s}/inbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const outbox = std.fmt.allocPrint(allocator, "{s}/users/{s}/outbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const followers_url = std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const following = std.fmt.allocPrint(allocator, "{s}/users/{s}/following", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const key_id = std.fmt.allocPrint(allocator, "{s}#main-key", .{actor_id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .@"@context" = [_][]const u8{
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        },
        .id = actor_id,
        .type = "Person",
        .preferredUsername = user.?.username,
        .inbox = inbox,
        .outbox = outbox,
        .followers = followers_url,
        .following = following,
        .publicKey = .{
            .id = key_id,
            .owner = actor_id,
            .publicKeyPem = keys.public_key_pem,
        },
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/activity+json; charset=utf-8",
        .body = body,
    };
}

fn followersGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) Response {
    const prefix = "/users/";
    const suffix = "/followers";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const username = path[prefix.len .. path.len - suffix.len];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const id = std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const total = followers.countAccepted(&app_state.conn, user.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const items = followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.?.id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = id,
        .type = "OrderedCollection",
        .totalItems = total,
        .orderedItems = items,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/activity+json; charset=utf-8",
        .body = body,
    };
}

fn followingGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) Response {
    const prefix = "/users/";
    const suffix = "/following";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const username = path[prefix.len .. path.len - suffix.len];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const id = std.fmt.allocPrint(allocator, "{s}/users/{s}/following", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const total = follows.countAccepted(&app_state.conn, user.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const items = follows.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.?.id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = id,
        .type = "OrderedCollection",
        .totalItems = total,
        .orderedItems = items,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/activity+json; charset=utf-8",
        .body = body,
    };
}

fn outboxGet(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const prefix = "/users/";
    const suffix = "/outbox";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const username = path[prefix.len .. path.len - suffix.len];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const outbox_id = std.fmt.allocPrint(allocator, "{s}/users/{s}/outbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };
    const is_page = params.get("page") != null;

    if (!is_page) {
        var count_stmt = app_state.conn.prepareZ(
            "SELECT COUNT(*) FROM statuses WHERE user_id = ?1 AND deleted_at IS NULL AND (visibility = 'public' OR visibility = 'unlisted');\x00",
        ) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        defer count_stmt.finalize();
        count_stmt.bindInt64(1, user.?.id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const total: i64 = switch (count_stmt.step() catch db.Stmt.Step.done) {
            .row => count_stmt.columnInt64(0),
            .done => 0,
        };

        const first = std.fmt.allocPrint(allocator, "{s}?page=true", .{outbox_id}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const payload = .{
            .@"@context" = "https://www.w3.org/ns/activitystreams",
            .id = outbox_id,
            .type = "OrderedCollection",
            .totalItems = total,
            .first = first,
        };

        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return .{
            .content_type = "application/activity+json; charset=utf-8",
            .body = body,
        };
    }

    const limit: usize = 20;
    const list = statuses.listByUser(&app_state.conn, allocator, user.?.id, limit, null) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const actor_id = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const followers_url = std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const ApNote = struct {
        id: []const u8,
        type: []const u8 = "Note",
        attributedTo: []const u8,
        content: []const u8,
        published: []const u8,
        to: []const []const u8,
        cc: []const []const u8,
    };

    const ApCreate = struct {
        id: []const u8,
        type: []const u8 = "Create",
        actor: []const u8,
        published: []const u8,
        to: []const []const u8,
        cc: []const []const u8,
        object: ApNote,
    };

    var items = std.ArrayListUnmanaged(ApCreate).empty;
    defer items.deinit(allocator);

    for (list) |st| {
        if (!isPubliclyVisibleVisibility(st.visibility)) continue;

        const status_id_str = std.fmt.allocPrint(allocator, "{d}", .{st.id}) catch "0";
        const status_url = std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{s}", .{ base, username, status_id_str }) catch "";
        const activity_id = std.fmt.allocPrint(allocator, "{s}#create", .{status_url}) catch "";

        const html_content = textToHtmlAlloc(allocator, st.text) catch st.text;

        const public_iri = "https://www.w3.org/ns/activitystreams#Public";
        const to = allocator.alloc([]const u8, 1) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const cc = allocator.alloc([]const u8, 1) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (std.mem.eql(u8, st.visibility, "unlisted")) {
            to[0] = followers_url;
            cc[0] = public_iri;
        } else {
            to[0] = public_iri;
            cc[0] = followers_url;
        }

        items.append(allocator, .{
            .id = activity_id,
            .actor = actor_id,
            .published = st.created_at,
            .to = to,
            .cc = cc,
            .object = .{
                .id = status_url,
                .attributedTo = actor_id,
                .content = html_content,
                .published = st.created_at,
                .to = to,
                .cc = cc,
            },
        }) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const page_id = std.fmt.allocPrint(allocator, "{s}?page=true", .{outbox_id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = page_id,
        .type = "OrderedCollectionPage",
        .partOf = outbox_id,
        .orderedItems = items.items,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/activity+json; charset=utf-8",
        .body = body,
    };
}

fn userStatusGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) Response {
    const prefix = "/users/";
    const sep = "/statuses/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const sep_i = std.mem.indexOf(u8, path, sep) orelse return .{ .status = .not_found, .body = "not found\n" };
    const username = path[prefix.len..sep_i];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[sep_i + sep.len ..];
    if (id_str.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_str, '/') != null) return .{ .status = .not_found, .body = "not found\n" };
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const st = statuses.lookupIncludingDeleted(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != user.?.id) return .{ .status = .not_found, .body = "not found\n" };

    if (!isPubliclyVisibleVisibility(st.?.visibility)) return .{ .status = .not_found, .body = "not found\n" };

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const actor_id = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const followers_url = std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const note_id = std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, username, st.?.id }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (st.?.deleted_at) |deleted_at| {
        const payload = .{
            .@"@context" = "https://www.w3.org/ns/activitystreams",
            .id = note_id,
            .type = "Tombstone",
            .formerType = "Note",
            .deleted = deleted_at,
        };

        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return .{
            .content_type = "application/activity+json; charset=utf-8",
            .body = body,
        };
    }

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    var to_buf: [1][]const u8 = undefined;
    var cc_buf: [1][]const u8 = undefined;
    if (std.mem.eql(u8, st.?.visibility, "unlisted")) {
        to_buf[0] = followers_url;
        cc_buf[0] = public_iri;
    } else {
        to_buf[0] = public_iri;
        cc_buf[0] = followers_url;
    }
    const to = to_buf[0..];
    const cc = cc_buf[0..];

    const html_content = textToHtmlAlloc(allocator, st.?.text) catch st.?.text;

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = note_id,
        .type = "Note",
        .attributedTo = actor_id,
        .content = html_content,
        .published = st.?.created_at,
        .to = to[0..],
        .cc = cc[0..],
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/activity+json; charset=utf-8",
        .body = body,
    };
}

fn jsonContainsIri(v: ?std.json.Value, needle: []const u8) bool {
    const val = v orelse return false;
    const want = trimTrailingSlash(needle);

    switch (val) {
        .string => |s| return std.mem.eql(u8, trimTrailingSlash(s), want),
        .object => |o| {
            const id_val = o.get("id") orelse return false;
            if (id_val != .string) return false;
            return std.mem.eql(u8, trimTrailingSlash(id_val.string), want);
        },
        .array => |arr| {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| if (std.mem.eql(u8, trimTrailingSlash(s), want)) return true,
                    .object => |o| {
                        const id_val = o.get("id") orelse continue;
                        if (id_val != .string) continue;
                        if (std.mem.eql(u8, trimTrailingSlash(id_val.string), want)) return true;
                    },
                    else => continue,
                }
            }
            return false;
        },
        else => return false,
    }
}

fn inboxPost(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const prefix = "/users/";
    const suffix = "/inbox";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const username = path[prefix.len .. path.len - suffix.len];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, req.body, .{}) catch
        return .{ .status = .bad_request, .body = "invalid json\n" };
    defer parsed.deinit();

    if (parsed.value != .object) return .{ .status = .bad_request, .body = "invalid json\n" };

    const typ = parsed.value.object.get("type") orelse
        return .{ .status = .bad_request, .body = "missing type\n" };
    if (typ != .string) return .{ .status = .bad_request, .body = "invalid type\n" };

    if (std.mem.eql(u8, typ.string, "Create")) {
        const actor_val = parsed.value.object.get("actor") orelse
            return .{ .status = .bad_request, .body = "missing actor\n" };
        if (actor_val != .string) return .{ .status = .bad_request, .body = "invalid actor\n" };

        const obj = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };
        if (obj != .object) return .{ .status = .bad_request, .body = "invalid object\n" };

        const note_id_val = obj.object.get("id") orelse return .{ .status = .bad_request, .body = "missing id\n" };
        const content_val = obj.object.get("content") orelse
            return .{ .status = .bad_request, .body = "missing content\n" };

        if (note_id_val != .string) return .{ .status = .bad_request, .body = "invalid id\n" };
        if (content_val != .string) return .{ .status = .bad_request, .body = "invalid content\n" };

        const created_at = blk: {
            const p = obj.object.get("published") orelse break :blk "1970-01-01T00:00:00.000Z";
            if (p != .string) break :blk "1970-01-01T00:00:00.000Z";
            if (p.string.len == 0) break :blk "1970-01-01T00:00:00.000Z";
            break :blk p.string;
        };

        const received_at_ms: i64 = std.time.milliTimestamp();
        var dedupe_activity_id: ?[]const u8 = null;
        var dedupe_keep: bool = false;
        defer {
            if (dedupe_activity_id) |id| {
                if (!dedupe_keep) inbox_dedupe.clear(&app_state.conn, id) catch {};
            }
        }

        const activity_id = blk: {
            const id_val = parsed.value.object.get("id") orelse break :blk null;
            if (id_val != .string) break :blk null;
            if (id_val.string.len == 0) break :blk null;
            break :blk trimTrailingSlash(id_val.string);
        };

        if (activity_id) |id| {
            const inserted = inbox_dedupe.begin(&app_state.conn, id, user.?.id, actor_val.string, received_at_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
            dedupe_activity_id = id;
        }

        var remote_actor = blk: {
            if (remote_actors.lookupById(&app_state.conn, allocator, actor_val.string) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
            {
                break :blk found;
            }

            const trimmed = trimTrailingSlash(actor_val.string);
            if (!std.mem.eql(u8, trimmed, actor_val.string)) {
                if (remote_actors.lookupById(&app_state.conn, allocator, trimmed) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            } else {
                const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{actor_val.string}) catch
                    break :blk null;
                if (remote_actors.lookupById(&app_state.conn, allocator, with_slash) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            }

            break :blk null;
        };

        if (remote_actor == null) {
            remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch null;
            if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };
        }

        const visibility: []const u8 = blk: {
            const has_recipients =
                (parsed.value.object.get("to") != null) or
                (parsed.value.object.get("cc") != null) or
                (obj.object.get("to") != null) or
                (obj.object.get("cc") != null);
            if (!has_recipients) break :blk "public";

            const public_iri = "https://www.w3.org/ns/activitystreams#Public";

            const public_in_to =
                jsonContainsIri(parsed.value.object.get("to"), public_iri) or
                jsonContainsIri(obj.object.get("to"), public_iri);
            if (public_in_to) break :blk "public";

            const public_in_cc =
                jsonContainsIri(parsed.value.object.get("cc"), public_iri) or
                jsonContainsIri(obj.object.get("cc"), public_iri);
            if (public_in_cc) break :blk "unlisted";

            break :blk "direct";
        };

        const created = remote_statuses.createIfNotExists(
            &app_state.conn,
            allocator,
            note_id_val.string,
            remote_actor.?.id,
            content_val.string,
            visibility,
            created_at,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const st_resp = remoteStatusResponse(app_state, allocator, remote_actor.?, created);
        app_state.streaming.publishUpdate(user.?.id, st_resp.body);

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    if (std.mem.eql(u8, typ.string, "Delete")) {
        const actor_val = parsed.value.object.get("actor") orelse
            return .{ .status = .bad_request, .body = "missing actor\n" };
        if (actor_val != .string) return .{ .status = .bad_request, .body = "invalid actor\n" };

        const received_at_ms: i64 = std.time.milliTimestamp();
        var dedupe_activity_id: ?[]const u8 = null;
        var dedupe_keep: bool = false;
        defer {
            if (dedupe_activity_id) |id| {
                if (!dedupe_keep) inbox_dedupe.clear(&app_state.conn, id) catch {};
            }
        }

        const activity_id = blk: {
            const id_val = parsed.value.object.get("id") orelse break :blk null;
            if (id_val != .string) break :blk null;
            if (id_val.string.len == 0) break :blk null;
            break :blk trimTrailingSlash(id_val.string);
        };

        if (activity_id) |id| {
            const inserted = inbox_dedupe.begin(&app_state.conn, id, user.?.id, actor_val.string, received_at_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
            dedupe_activity_id = id;
        }

        const remote_actor = blk: {
            if (remote_actors.lookupById(&app_state.conn, allocator, actor_val.string) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
            {
                break :blk found;
            }

            const trimmed = trimTrailingSlash(actor_val.string);
            if (!std.mem.eql(u8, trimmed, actor_val.string)) {
                if (remote_actors.lookupById(&app_state.conn, allocator, trimmed) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            } else {
                const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{actor_val.string}) catch
                    break :blk null;
                if (remote_actors.lookupById(&app_state.conn, allocator, with_slash) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            }

            break :blk null;
        };
        if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };

        const obj = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };

        var object_id: []const u8 = undefined;
        var deleted_at: ?[]const u8 = null;
        switch (obj) {
            .string => |s| object_id = s,
            .object => |o| {
                const id_val = o.get("id") orelse return .{ .status = .bad_request, .body = "missing id\n" };
                if (id_val != .string) return .{ .status = .bad_request, .body = "invalid id\n" };
                object_id = id_val.string;

                if (o.get("deleted")) |deleted_val| {
                    if (deleted_val == .string and deleted_val.string.len > 0) {
                        deleted_at = deleted_val.string;
                    }
                }
            },
            else => return .{ .status = .bad_request, .body = "invalid object\n" },
        }

        const remote_status = blk: {
            if (remote_statuses.lookupByUriIncludingDeleted(&app_state.conn, allocator, object_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
            {
                break :blk found;
            }

            const trimmed = trimTrailingSlash(object_id);
            if (!std.mem.eql(u8, trimmed, object_id)) {
                if (remote_statuses.lookupByUriIncludingDeleted(&app_state.conn, allocator, trimmed) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            } else {
                const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{object_id}) catch
                    break :blk null;
                if (remote_statuses.lookupByUriIncludingDeleted(&app_state.conn, allocator, with_slash) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }
            }

            break :blk null;
        };
        if (remote_status == null) return .{ .status = .accepted, .body = "ignored\n" };
        if (!std.mem.eql(u8, remote_status.?.remote_actor_id, remote_actor.?.id)) {
            return .{ .status = .accepted, .body = "ignored\n" };
        }

        const deleted = remote_statuses.markDeletedByUri(&app_state.conn, remote_status.?.remote_uri, deleted_at) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (deleted) {
            const id_str = std.fmt.allocPrint(allocator, "{d}", .{remote_status.?.id}) catch "0";
            app_state.streaming.publishDelete(user.?.id, id_str);
        }

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    if (std.mem.eql(u8, typ.string, "Follow")) {
        const id_val = parsed.value.object.get("id") orelse
            return .{ .status = .bad_request, .body = "missing id\n" };
        if (id_val != .string) return .{ .status = .bad_request, .body = "invalid id\n" };

        const actor_val = parsed.value.object.get("actor") orelse
            return .{ .status = .bad_request, .body = "missing actor\n" };
        if (actor_val != .string) return .{ .status = .bad_request, .body = "invalid actor\n" };

        const received_at_ms: i64 = std.time.milliTimestamp();
        var dedupe_activity_id: ?[]const u8 = null;
        var dedupe_keep: bool = false;
        defer {
            if (dedupe_activity_id) |id| {
                if (!dedupe_keep) inbox_dedupe.clear(&app_state.conn, id) catch {};
            }
        }

        const follow_activity_id = trimTrailingSlash(id_val.string);
        const inserted = inbox_dedupe.begin(&app_state.conn, follow_activity_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = follow_activity_id;

        const obj = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };

        var object_actor_id: []const u8 = undefined;
        switch (obj) {
            .string => |s| object_actor_id = s,
            .object => |o| {
                const oid = o.get("id") orelse return .{ .status = .bad_request, .body = "missing id\n" };
                if (oid != .string) return .{ .status = .bad_request, .body = "invalid id\n" };
                object_actor_id = oid.string;
            },
            else => return .{ .status = .bad_request, .body = "invalid object\n" },
        }

        const base = baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const expected = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const trimSlash = struct {
            fn f(s: []const u8) []const u8 {
                if (s.len == 0) return s;
                if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
                return s;
            }
        }.f;

        if (!std.mem.eql(u8, trimSlash(object_actor_id), trimSlash(expected))) {
            return .{ .status = .accepted, .body = "ignored\n" };
        }

        background.acceptInboundFollow(app_state, allocator, user.?.id, username, actor_val.string, follow_activity_id);

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    if (std.mem.eql(u8, typ.string, "Accept")) {
        const received_at_ms: i64 = std.time.milliTimestamp();
        var dedupe_activity_id: ?[]const u8 = null;
        var dedupe_keep: bool = false;
        defer {
            if (dedupe_activity_id) |id| {
                if (!dedupe_keep) inbox_dedupe.clear(&app_state.conn, id) catch {};
            }
        }

        const activity_id = blk: {
            const id_val = parsed.value.object.get("id") orelse break :blk null;
            if (id_val != .string) break :blk null;
            if (id_val.string.len == 0) break :blk null;
            break :blk trimTrailingSlash(id_val.string);
        };
        const actor_id = blk: {
            const actor_val = parsed.value.object.get("actor") orelse break :blk null;
            if (actor_val != .string) break :blk null;
            if (actor_val.string.len == 0) break :blk null;
            break :blk actor_val.string;
        };

        if (activity_id != null and actor_id != null) {
            const inserted = inbox_dedupe.begin(&app_state.conn, activity_id.?, user.?.id, actor_id.?, received_at_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
            dedupe_activity_id = activity_id.?;
        }

        const obj = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };

        var follow_activity_id: []const u8 = undefined;
        switch (obj) {
            .string => |s| follow_activity_id = s,
            .object => |o| {
                const id_val = o.get("id") orelse
                    return .{ .status = .bad_request, .body = "missing id\n" };
                if (id_val != .string) return .{ .status = .bad_request, .body = "invalid id\n" };
                follow_activity_id = id_val.string;
            },
            else => return .{ .status = .bad_request, .body = "invalid object\n" },
        }

        const trimSlash = struct {
            fn f(s: []const u8) []const u8 {
                if (s.len == 0) return s;
                if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
                return s;
            }
        }.f;

        const changed = follows.markAcceptedByActivityId(&app_state.conn, follow_activity_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!changed) {
            const trimmed = trimSlash(follow_activity_id);
            if (!std.mem.eql(u8, trimmed, follow_activity_id)) {
                _ = follows.markAcceptedByActivityId(&app_state.conn, trimmed) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" };
            } else {
                const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{follow_activity_id}) catch null;
                if (with_slash) |alt_id| {
                    _ = follows.markAcceptedByActivityId(&app_state.conn, alt_id) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" };
                }
            }
        }

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    return .{ .status = .accepted, .body = "ignored\n" };
}

fn createStatus(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    var parsed = parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const text = parsed.get("status") orelse return .{ .status = .bad_request, .body = "missing status\n" };
    const visibility = parsed.get("visibility") orelse "public";
    const media_ids_raw = parsed.get("media_ids[]") orelse parsed.get("media_ids");

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const st = statuses.create(&app_state.conn, allocator, info.?.user_id, text, visibility) catch |err| switch (err) {
        error.InvalidText => return .{ .status = .unprocessable_entity, .body = "invalid status\n" },
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    if (media_ids_raw) |raw| {
        var pos: i64 = 0;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |id_str| {
            if (id_str.len == 0) continue;
            const media_id = std.fmt.parseInt(i64, id_str, 10) catch
                return .{ .status = .unprocessable_entity, .body = "invalid media\n" };

            const meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (meta == null or meta.?.user_id != info.?.user_id) {
                return .{ .status = .unprocessable_entity, .body = "invalid media\n" };
            }

            const attached = media.attachToStatus(&app_state.conn, st.id, media_id, pos) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (!attached) return .{ .status = .unprocessable_entity, .body = "invalid media\n" };
            pos += 1;
        }
    }

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    background.deliverStatusToFollowers(app_state, allocator, info.?.user_id, st.id);

    const resp = statusResponse(app_state, allocator, user.?, st);
    app_state.streaming.publishUpdate(info.?.user_id, resp.body);
    return resp;
}

fn createMedia(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    if (!isMultipart(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid form\n" };
    }

    var parsed = form.parseMultipartWithFile(allocator, req.content_type.?, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const file = parsed.file orelse return .{ .status = .bad_request, .body = "missing file\n" };
    if (!std.mem.eql(u8, file.name, "file")) return .{ .status = .bad_request, .body = "missing file\n" };

    const description = parsed.form.get("description");
    const content_type = file.content_type orelse "application/octet-stream";

    const now_ms: i64 = std.time.milliTimestamp();
    var meta = media.create(
        &app_state.conn,
        allocator,
        info.?.user_id,
        content_type,
        file.data,
        description,
        now_ms,
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    defer meta.deinit(allocator);

    const one_day_ms: i64 = 24 * 60 * 60 * 1000;
    _ = media.pruneOrphansOlderThan(&app_state.conn, now_ms - one_day_ms) catch 0;

    const payload = makeMediaAttachmentPayload(app_state, allocator, meta);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn updateMedia(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const id_str = path["/api/v1/media/".len..];
    const media_id = std.fmt.parseInt(i64, id_str, 10) catch
        return .{ .status = .bad_request, .body = "invalid media id\n" };

    var parsed = parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const description = parsed.get("description");
    const now_ms: i64 = std.time.milliTimestamp();
    const updated = media.updateDescription(&app_state.conn, media_id, info.?.user_id, description, now_ms) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!updated) return .{ .status = .not_found, .body = "not found\n" };

    var meta = media.lookupMeta(&app_state.conn, allocator, media_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (meta == null) return .{ .status = .not_found, .body = "not found\n" };
    defer meta.?.deinit(allocator);

    const payload = makeMediaAttachmentPayload(app_state, allocator, meta.?);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn mediaFileGet(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    _ = req;

    const token = path["/media/".len..];
    if (token.len == 0) return .{ .status = .not_found, .body = "not found\n" };

    const m = media.lookupByPublicToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (m == null) return .{ .status = .not_found, .body = "not found\n" };

    return .{
        .content_type = m.?.content_type,
        .body = m.?.data,
    };
}

fn mediaAttachmentType(content_type: []const u8) []const u8 {
    if (std.mem.startsWith(u8, content_type, "image/")) return "image";
    if (std.mem.startsWith(u8, content_type, "video/")) return "video";
    if (std.mem.startsWith(u8, content_type, "audio/")) return "audio";
    return "unknown";
}

fn makeMediaAttachmentPayload(app_state: *app.App, allocator: std.mem.Allocator, meta: media.MediaMeta) MediaAttachmentPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{meta.id}) catch "0";
    const base = baseUrlAlloc(app_state, allocator) catch "";
    const url = std.fmt.allocPrint(allocator, "{s}/media/{s}", .{ base, meta.public_token }) catch "";
    return .{
        .id = id_str,
        .type = mediaAttachmentType(meta.content_type),
        .url = url,
        .preview_url = url,
        .description = meta.description,
    };
}

fn isPublicTimelineVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public");
}

fn isPubliclyVisibleVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}

const TimelineCursor = struct {
    created_at: []const u8,
    id: i64,
};

fn lookupTimelineCursor(app_state: *app.App, allocator: std.mem.Allocator, id: i64) ?TimelineCursor {
    if (id < 0) {
        const st = remote_statuses.lookupIncludingDeleted(&app_state.conn, allocator, id) catch return null;
        if (st == null) return null;
        return .{ .created_at = st.?.created_at, .id = id };
    }

    const st = statuses.lookupIncludingDeleted(&app_state.conn, allocator, id) catch return null;
    if (st == null) return null;
    return .{ .created_at = st.?.created_at, .id = id };
}

fn retainStatusesNewerThan(payloads: *std.ArrayListUnmanaged(StatusPayload), cursor: TimelineCursor) void {
    var out_len: usize = 0;
    for (payloads.items) |p| {
        const keep = switch (std.mem.order(u8, p.created_at, cursor.created_at)) {
            .gt => true,
            .lt => false,
            .eq => statusPayloadIdInt(p) > cursor.id,
        };

        if (keep) {
            payloads.items[out_len] = p;
            out_len += 1;
        }
    }
    payloads.items = payloads.items[0..out_len];
}

fn publicTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };

    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 20;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 20;
        break :blk @min(parsed, 200);
    };

    const max_id: ?i64 = blk: {
        const s = params.get("max_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const since_id: ?i64 = blk: {
        const s = params.get("since_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const min_id: ?i64 = blk: {
        const s = params.get("min_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const local_only: bool = blk: {
        const s = params.get("local") orelse break :blk false;
        if (std.ascii.eqlIgnoreCase(s, "true")) break :blk true;
        if (std.mem.eql(u8, s, "1")) break :blk true;
        break :blk false;
    };

    const cursor = if (max_id) |id| lookupTimelineCursor(app_state, allocator, id) else null;
    const before_created_at = if (cursor) |c| c.created_at else null;
    const before_id = if (cursor) |c| c.id else null;

    const user = users.lookupFirstUser(&app_state.conn, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads = std.ArrayListUnmanaged(StatusPayload).empty;
    defer payloads.deinit(allocator);

    if (user) |u| {
        const local_list = statuses.listByUserBeforeCreatedAt(&app_state.conn, allocator, u.id, limit, before_created_at, before_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        for (local_list) |st| {
            if (!isPublicTimelineVisibility(st.visibility)) continue;
            payloads.append(allocator, makeStatusPayload(app_state, allocator, u, st)) catch return .{
                .status = .internal_server_error,
                .body = "internal server error\n",
            };
        }
    }

    if (!local_only) {
        const remote_list = remote_statuses.listLatestBeforeCreatedAt(&app_state.conn, allocator, limit, before_created_at, before_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        for (remote_list) |st| {
            if (!isPublicTimelineVisibility(st.visibility)) continue;
            const actor = remote_actors.lookupById(&app_state.conn, allocator, st.remote_actor_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (actor == null) continue;

            payloads.append(allocator, makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
                .status = .internal_server_error,
                .body = "internal server error\n",
            };
        }
    }

    std.sort.block(StatusPayload, payloads.items, {}, statusPayloadNewerFirst);

    if (since_id) |id| {
        if (lookupTimelineCursor(app_state, allocator, id)) |c| {
            retainStatusesNewerThan(&payloads, c);
        }
    }
    if (min_id) |id| {
        if (lookupTimelineCursor(app_state, allocator, id)) |c| {
            retainStatusesNewerThan(&payloads, c);
        }
    }

    const slice = payloads.items[0..@min(limit, payloads.items.len)];
    const body = std.json.Stringify.valueAlloc(allocator, slice, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var headers: []const std.http.Header = &.{};
    if (slice.len > 0) {
        const base = baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const newest_id = statusPayloadIdInt(slice[0]);
        const oldest_id = statusPayloadIdInt(slice[slice.len - 1]);

        const local_param: []const u8 = if (local_only) "&local=true" else "";
        const next_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/public?limit={d}{s}&max_id={d}",
            .{ base, limit, local_param, oldest_id },
        ) catch "";
        const prev_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/public?limit={d}{s}&since_id={d}",
            .{ base, limit, local_param, newest_id },
        ) catch "";
        const link = std.fmt.allocPrint(
            allocator,
            "<{s}>; rel=\"next\", <{s}>; rel=\"prev\"",
            .{ next_url, prev_url },
        ) catch "";

        var header_slice = allocator.alloc(std.http.Header, 1) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        header_slice[0] = .{ .name = "link", .value = link };
        headers = header_slice;
    }

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
        .headers = headers,
    };
}

fn homeTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };

    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 20;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 20;
        break :blk @min(parsed, 200);
    };

    const max_id: ?i64 = blk: {
        const s = params.get("max_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const since_id: ?i64 = blk: {
        const s = params.get("since_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const min_id: ?i64 = blk: {
        const s = params.get("min_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const cursor = if (max_id) |id| lookupTimelineCursor(app_state, allocator, id) else null;
    const before_created_at = if (cursor) |c| c.created_at else null;
    const before_id = if (cursor) |c| c.id else null;

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    const local_list = statuses.listByUserBeforeCreatedAt(&app_state.conn, allocator, info.?.user_id, limit, before_created_at, before_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads = std.ArrayListUnmanaged(StatusPayload).empty;
    defer payloads.deinit(allocator);

    for (local_list) |st| {
        payloads.append(allocator, makeStatusPayload(app_state, allocator, user.?, st)) catch return .{
            .status = .internal_server_error,
            .body = "internal server error\n",
        };
    }

    const remote_list = remote_statuses.listLatestBeforeCreatedAt(&app_state.conn, allocator, limit, before_created_at, before_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    for (remote_list) |st| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        payloads.append(allocator, makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
            .status = .internal_server_error,
            .body = "internal server error\n",
        };
    }

    std.sort.block(StatusPayload, payloads.items, {}, statusPayloadNewerFirst);

    if (since_id) |id| {
        if (lookupTimelineCursor(app_state, allocator, id)) |c| {
            retainStatusesNewerThan(&payloads, c);
        }
    }
    if (min_id) |id| {
        if (lookupTimelineCursor(app_state, allocator, id)) |c| {
            retainStatusesNewerThan(&payloads, c);
        }
    }

    const slice = payloads.items[0..@min(limit, payloads.items.len)];
    const body = std.json.Stringify.valueAlloc(allocator, slice, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var headers: []const std.http.Header = &.{};
    if (slice.len > 0) {
        const base = baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const newest_id = statusPayloadIdInt(slice[0]);
        const oldest_id = statusPayloadIdInt(slice[slice.len - 1]);

        const next_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/home?limit={d}&max_id={d}",
            .{ base, limit, oldest_id },
        ) catch "";
        const prev_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/home?limit={d}&since_id={d}",
            .{ base, limit, newest_id },
        ) catch "";
        const link = std.fmt.allocPrint(
            allocator,
            "<{s}>; rel=\"next\", <{s}>; rel=\"prev\"",
            .{ next_url, prev_url },
        ) catch "";

        var header_slice = allocator.alloc(std.http.Header, 1) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        header_slice[0] = .{ .name = "link", .value = link };
        headers = header_slice;
    }

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
        .headers = headers,
    };
}

fn getStatus(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        return remoteStatusResponse(app_state, allocator, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    return statusResponse(app_state, allocator, user.?, st.?);
}

fn statusContext(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    const suffix = "/context";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    } else {
        const st = statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    }

    return jsonOk(allocator, .{
        .ancestors = [_]StatusPayload{},
        .descendants = [_]StatusPayload{},
    });
}

fn statusActionNoop(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    req: Request,
    path: []const u8,
    suffix: []const u8,
) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        return remoteStatusResponse(app_state, allocator, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    return statusResponse(app_state, allocator, user.?, st.?);
}

fn deleteStatus(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };
    if (id < 0) return .{ .status = .not_found, .body = "not found\n" };

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return unauthorized(allocator);

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const ok = statuses.markDeleted(&app_state.conn, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    media.deleteForStatus(&app_state.conn, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    background.deliverDeleteToFollowers(app_state, allocator, info.?.user_id, id);

    const resp = statusResponse(app_state, allocator, user.?, st.?);
    app_state.streaming.publishDelete(info.?.user_id, id_str);
    return resp;
}

fn statusResponse(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Response {
    const payload = makeStatusPayload(app_state, allocator, user, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

const AccountPayload = struct {
    id: []const u8,
    username: []const u8,
    acct: []const u8,
    display_name: []const u8,
    note: []const u8,
    url: []const u8,
    locked: bool,
    bot: bool,
    group: bool,
    discoverable: bool,
    created_at: []const u8,
    followers_count: i64,
    following_count: i64,
    statuses_count: i64,
    avatar: []const u8,
    avatar_static: []const u8,
    header: []const u8,
    header_static: []const u8,
};

const remote_actor_id_base: i64 = 1_000_000_000;

fn remoteAccountApiIdAlloc(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) []const u8 {
    const rowid = remote_actors.lookupRowIdById(&app_state.conn, actor_id) catch return actor_id;
    if (rowid == null) return actor_id;
    return std.fmt.allocPrint(allocator, "{d}", .{remote_actor_id_base + rowid.?}) catch actor_id;
}

fn makeRemoteAccountPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    api_id: []const u8,
    actor: remote_actors.RemoteActor,
) AccountPayload {
    const acct = std.fmt.allocPrint(allocator, "{s}@{s}", .{ actor.preferred_username, actor.domain }) catch
        actor.preferred_username;
    const avatar_url = if (actor.avatar_url) |u| u else defaultAvatarUrlAlloc(app_state, allocator) catch actor.id;
    const header_url = if (actor.header_url) |u| u else defaultHeaderUrlAlloc(app_state, allocator) catch actor.id;

    return .{
        .id = api_id,
        .username = actor.preferred_username,
        .acct = acct,
        .display_name = "",
        .note = "",
        .url = actor.id,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = "1970-01-01T00:00:00.000Z",
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };
}

const MediaAttachmentPayload = struct {
    id: []const u8,
    type: []const u8,
    url: []const u8,
    preview_url: []const u8,
    remote_url: ?[]const u8 = null,
    text_url: ?[]const u8 = null,
    meta: struct {} = .{},
    description: ?[]const u8,
    blurhash: ?[]const u8 = null,
};

const StatusPayload = struct {
    id: []const u8,
    created_at: []const u8,
    content: []const u8,
    visibility: []const u8,
    sensitive: bool,
    uri: []const u8,
    url: []const u8,
    account: AccountPayload,
    media_attachments: []const MediaAttachmentPayload,
};

fn statusPayloadIdInt(p: StatusPayload) i64 {
    return std.fmt.parseInt(i64, p.id, 10) catch 0;
}

fn statusPayloadNewerFirst(_: void, a: StatusPayload, b: StatusPayload) bool {
    return switch (std.mem.order(u8, a.created_at, b.created_at)) {
        .gt => true,
        .lt => false,
        .eq => statusPayloadIdInt(a) > statusPayloadIdInt(b),
    };
}

fn makeStatusPayload(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) StatusPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{st.id}) catch "0";
    const user_id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch "0";

    const html_content = textToHtmlAlloc(allocator, st.text) catch st.text;

    const user_url = userUrlAlloc(app_state, allocator, user.username) catch "";
    const avatar_url = defaultAvatarUrlAlloc(app_state, allocator) catch "";
    const header_url = defaultHeaderUrlAlloc(app_state, allocator) catch "";

    const acct: AccountPayload = .{
        .id = user_id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = "",
        .note = "",
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const base = baseUrlAlloc(app_state, allocator) catch "";

    const uri = std.fmt.allocPrint(allocator, "{s}/api/v1/statuses/{s}", .{ base, id_str }) catch "";

    const metas: []const media.MediaMeta = media.listForStatus(&app_state.conn, allocator, st.id) catch &.{};
    const attachments = blk: {
        if (metas.len == 0) break :blk &.{};
        const out = allocator.alloc(MediaAttachmentPayload, metas.len) catch break :blk &.{};
        for (metas, 0..) |m, i| {
            out[i] = makeMediaAttachmentPayload(app_state, allocator, m);
        }
        break :blk out;
    };

    return .{
        .id = id_str,
        .created_at = st.created_at,
        .content = html_content,
        .visibility = st.visibility,
        .sensitive = false,
        .uri = uri,
        .url = uri,
        .account = acct,
        .media_attachments = attachments,
    };
}

fn makeRemoteStatusPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) StatusPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{st.id}) catch "0";

    const acct_str = std.fmt.allocPrint(allocator, "{s}@{s}", .{ actor.preferred_username, actor.domain }) catch
        actor.preferred_username;

    const avatar_url = if (actor.avatar_url) |u| u else defaultAvatarUrlAlloc(app_state, allocator) catch actor.id;
    const header_url = if (actor.header_url) |u| u else defaultHeaderUrlAlloc(app_state, allocator) catch actor.id;

    const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);

    const acct: AccountPayload = .{
        .id = api_id,
        .username = actor.preferred_username,
        .acct = acct_str,
        .display_name = "",
        .note = "",
        .url = actor.id,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = "1970-01-01T00:00:00.000Z",
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    return .{
        .id = id_str,
        .created_at = st.created_at,
        .content = st.content_html,
        .visibility = st.visibility,
        .sensitive = false,
        .uri = st.remote_uri,
        .url = st.remote_uri,
        .account = acct,
        .media_attachments = &.{},
    };
}

fn remoteStatusResponse(app_state: *app.App, allocator: std.mem.Allocator, actor: remote_actors.RemoteActor, st: remote_statuses.RemoteStatus) Response {
    const payload = makeRemoteStatusPayload(app_state, allocator, actor, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn textToHtmlAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const escaped = try htmlEscapeAlloc(allocator, text);
    return std.fmt.allocPrint(allocator, "<p>{s}</p>", .{escaped});
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

    const user_url = userUrlAlloc(app_state, allocator, user.?.username) catch "";
    const avatar_url = defaultAvatarUrlAlloc(app_state, allocator) catch "";
    const header_url = defaultHeaderUrlAlloc(app_state, allocator) catch "";

    const payload = .{
        .id = id_str,
        .username = user.?.username,
        .acct = user.?.username,
        .display_name = "",
        .note = "",
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.?.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn accountLookup(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const q = queryString(req.target);
    const acct_param = parseQueryParam(allocator, q, "acct") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    if (acct_param == null) return .{ .status = .bad_request, .body = "missing acct\n" };

    var username = acct_param.?;
    if (std.mem.indexOfScalar(u8, username, '@')) |at| {
        const domain = username[at + 1 ..];
        if (domain.len == 0) return .{ .status = .not_found, .body = "not found\n" };
        if (!std.mem.eql(u8, domain, app_state.cfg.domain)) return .{ .status = .not_found, .body = "not found\n" };
        username = username[0..at];
    }
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    return accountByUser(app_state, allocator, user.?);
}

fn apiV2Search(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const q = queryString(req.target);
    const q_param = parseQueryParam(allocator, q, "q") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };

    const query_raw = q_param orelse return jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    const query_trimmed = std.mem.trim(u8, query_raw, " \t\r\n");
    if (query_trimmed.len == 0) return jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    var accounts: std.ArrayListUnmanaged(AccountPayload) = .empty;
    defer accounts.deinit(allocator);

    // Minimal: resolve acct handles like `@user@domain` / `user@domain`.
    if (!std.mem.startsWith(u8, query_trimmed, "http://") and
        !std.mem.startsWith(u8, query_trimmed, "https://") and
        std.mem.indexOfScalar(u8, query_trimmed, '@') != null)
    {
        const actor = federation.resolveRemoteActorByHandle(app_state, allocator, query_trimmed) catch null;
        if (actor) |a| {
            const api_id = remoteAccountApiIdAlloc(app_state, allocator, a.id);
            accounts.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, a)) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    return jsonOk(allocator, .{
        .accounts = accounts.items,
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });
}

fn accountGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) Response {
    const prefix = "/api/v1/accounts/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (id >= remote_actor_id_base) {
        const rowid = id - remote_actor_id_base;
        if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        return jsonOk(allocator, makeRemoteAccountPayload(app_state, allocator, id_str, actor.?));
    }

    const user = users.lookupUserById(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    return accountByUser(app_state, allocator, user.?);
}

fn accountRelationships(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const q = queryString(req.target);

    var ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ids.deinit(allocator);

    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |pair_raw| {
        if (pair_raw.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair_raw, '=') orelse continue;

        const key = pair_raw[0..eq];
        const value = pair_raw[eq + 1 ..];
        if (value.len == 0) continue;

        if (std.mem.eql(u8, key, "id") or std.mem.eql(u8, key, "id[]") or std.mem.eql(u8, key, "id%5B%5D")) {
            ids.append(allocator, value) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    const Rel = struct {
        id: []const u8,
        following: bool = false,
        followed_by: bool = false,
        requested: bool = false,
    };
    var rels: std.ArrayListUnmanaged(Rel) = .empty;
    defer rels.deinit(allocator);

    for (ids.items) |id_str| {
        var following = false;
        var requested = false;

        const id_num = std.fmt.parseInt(i64, id_str, 10) catch null;
        if (id_num != null and id_num.? >= remote_actor_id_base) {
            const rowid = id_num.? - remote_actor_id_base;
            if (rowid > 0) {
                const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch null;
                if (actor) |a| {
                    const f = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, a.id) catch null;
                    if (f) |follow| {
                        following = follow.state == .accepted;
                        requested = follow.state == .pending;
                    }
                }
            }
        }

        rels.append(allocator, .{ .id = id_str, .following = following, .requested = requested }) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const body = std.json.Stringify.valueAlloc(allocator, rels.items, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

const RelationshipPayload = struct {
    id: []const u8,
    following: bool,
    followed_by: bool = false,
    requested: bool,
};

fn relationshipPayload(id: []const u8, state: ?follows.FollowState) RelationshipPayload {
    const following = state != null and state.? == .accepted;
    const requested = state != null and state.? == .pending;
    return .{ .id = id, .following = following, .requested = requested };
}

fn accountFollow(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const prefix = "/api/v1/accounts/";
    const suffix = "/follow";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (account_id < remote_actor_id_base) {
        return jsonOk(allocator, relationshipPayload(id_part, null));
    }

    const rowid = account_id - remote_actor_id_base;
    if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

    const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

    const existing = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (existing) |f| {
        return jsonOk(allocator, relationshipPayload(id_part, f.state));
    }

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const follow_activity_id = std.fmt.allocPrint(allocator, "{s}/follows/{s}", .{ base, id_hex[0..] }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    _ = follows.createPending(&app_state.conn, info.?.user_id, actor.?.id, follow_activity_id) catch |err| switch (err) {
        error.Sqlite => {
            const f = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.?.id) catch null;
            if (f) |existing_follow| {
                return jsonOk(allocator, relationshipPayload(id_part, existing_follow.state));
            }
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        },
    };

    background.sendFollow(app_state, allocator, info.?.user_id, actor.?.id, follow_activity_id);

    return jsonOk(allocator, relationshipPayload(id_part, .pending));
}

fn accountUnfollow(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const prefix = "/api/v1/accounts/";
    const suffix = "/unfollow";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (account_id < remote_actor_id_base) {
        return jsonOk(allocator, relationshipPayload(id_part, null));
    }

    const rowid = account_id - remote_actor_id_base;
    if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

    const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

    _ = follows.deleteByUserAndRemoteActorId(&app_state.conn, info.?.user_id, actor.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return jsonOk(allocator, relationshipPayload(id_part, null));
}

fn accountStatuses(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const prefix = "/api/v1/accounts/";
    const suffix = "/statuses";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (account_id >= remote_actor_id_base) {
        return jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };

    const pinned: bool = blk: {
        const s = params.get("pinned") orelse break :blk false;
        if (std.ascii.eqlIgnoreCase(s, "true")) break :blk true;
        if (std.mem.eql(u8, s, "1")) break :blk true;
        break :blk false;
    };

    const only_media: bool = blk: {
        const s = params.get("only_media") orelse break :blk false;
        if (std.ascii.eqlIgnoreCase(s, "true")) break :blk true;
        if (std.mem.eql(u8, s, "1")) break :blk true;
        break :blk false;
    };

    if (pinned or only_media) {
        return jsonOk(allocator, [_]i32{});
    }

    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 20;
        break :blk std.fmt.parseInt(usize, lim_str, 10) catch 20;
    };

    const max_id: ?i64 = blk: {
        const s = params.get("max_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const include_all: bool = blk: {
        const token = bearerToken(req.authorization) orelse break :blk false;
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch break :blk false;
        if (info == null) break :blk false;
        break :blk info.?.user_id == user.?.id;
    };

    const list = statuses.listByUser(&app_state.conn, allocator, user.?.id, limit, max_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads: std.ArrayListUnmanaged(StatusPayload) = .empty;
    defer payloads.deinit(allocator);

    for (list) |st| {
        if (!include_all and !isPubliclyVisibleVisibility(st.visibility)) continue;
        payloads.append(allocator, makeStatusPayload(app_state, allocator, user.?, st)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const body = std.json.Stringify.valueAlloc(allocator, payloads.items, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn accountFollowers(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const prefix = "/api/v1/accounts/";
    const suffix = "/followers";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (account_id >= remote_actor_id_base) {
        return jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };
    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 40;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 40;
        break :blk @min(parsed, 200);
    };

    const ids = followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.?.id, limit) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var accounts: std.ArrayListUnmanaged(AccountPayload) = .empty;
    defer accounts.deinit(allocator);

    for (ids) |actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
        accounts.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, actor.?)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return jsonOk(allocator, accounts.items);
}

fn accountFollowing(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const prefix = "/api/v1/accounts/";
    const suffix = "/following";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (account_id >= remote_actor_id_base) {
        return jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };
    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 40;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 40;
        break :blk @min(parsed, 200);
    };

    const ids = follows.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.?.id, limit) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var accounts: std.ArrayListUnmanaged(AccountPayload) = .empty;
    defer accounts.deinit(allocator);

    for (ids) |actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
        accounts.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, actor.?)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return jsonOk(allocator, accounts.items);
}

fn accountByUser(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) Response {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const user_url = userUrlAlloc(app_state, allocator, user.username) catch "";
    const avatar_url = defaultAvatarUrlAlloc(app_state, allocator) catch "";
    const header_url = defaultHeaderUrlAlloc(app_state, allocator) catch "";

    const payload: AccountPayload = .{
        .id = id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = "",
        .note = "",
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn apiFollow(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    var parsed = parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const uri = parsed.get("uri") orelse return .{ .status = .bad_request, .body = "missing uri\n" };

    const actor = federation.resolveRemoteActorByHandle(app_state, allocator, uri) catch |err| switch (err) {
        error.InvalidHandle, error.WebfingerNoSelfLink, error.ActorDocMissingFields => return .{
            .status = .bad_request,
            .body = "invalid uri\n",
        },
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    // Idempotent behavior: if the follow already exists, just return the account.
    const existing = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (existing != null) {
        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);
        const payload = makeRemoteAccountPayload(app_state, allocator, api_id, actor);
        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        return .{
            .content_type = "application/json; charset=utf-8",
            .body = body,
        };
    }

    const base = baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const follow_activity_id = std.fmt.allocPrint(allocator, "{s}/follows/{s}", .{ base, id_hex[0..] }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    _ = follows.createPending(&app_state.conn, info.?.user_id, actor.id, follow_activity_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    background.sendFollow(app_state, allocator, info.?.user_id, actor.id, follow_activity_id);

    const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);

    const payload = makeRemoteAccountPayload(app_state, allocator, api_id, actor);

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

const NotificationPayload = struct {
    id: []const u8,
    type: []const u8,
    created_at: []const u8,
    account: AccountPayload,
    status: ?StatusPayload = null,
};

fn notificationsGet(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const q = queryString(req.target);
    var params = form.parse(allocator, q) catch form.Form{ .map = .empty };

    const limit: usize = blk: {
        const lim_str = params.get("limit") orelse break :blk 20;
        const parsed = std.fmt.parseInt(usize, lim_str, 10) catch 20;
        break :blk @min(parsed, 200);
    };

    const max_id: ?i64 = blk: {
        const s = params.get("max_id") orelse break :blk null;
        break :blk std.fmt.parseInt(i64, s, 10) catch null;
    };

    const rows = notifications.list(&app_state.conn, allocator, info.?.user_id, limit, max_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var out: std.ArrayListUnmanaged(NotificationPayload) = .empty;
    defer out.deinit(allocator);

    for (rows) |n| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, n.actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
        const acct = makeRemoteAccountPayload(app_state, allocator, api_id, actor.?);

        out.append(allocator, .{
            .id = std.fmt.allocPrint(allocator, "{d}", .{n.id}) catch "0",
            .type = n.kind,
            .created_at = n.created_at,
            .account = acct,
            .status = null,
        }) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return jsonOk(allocator, out.items);
}

fn notificationsClear(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    notifications.clear(&app_state.conn, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return jsonOk(allocator, .{});
}

fn notificationsDismiss(app_state: *app.App, allocator: std.mem.Allocator, req: Request, path: []const u8) Response {
    const token = bearerToken(req.authorization) orelse return unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return unauthorized(allocator);

    const prefix = "/api/v1/notifications/";
    const suffix = "/dismiss";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = notifications.dismiss(&app_state.conn, info.?.user_id, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    return jsonOk(allocator, .{});
}

fn jsonOk(allocator: std.mem.Allocator, payload: anytype) Response {
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
    const client_id_html = htmlEscapeAlloc(allocator, client_id) catch client_id;
    const redirect_uri_html = htmlEscapeAlloc(allocator, redirect_uri) catch redirect_uri;
    const scope_html = htmlEscapeAlloc(allocator, scope) catch scope;
    const state_html = htmlEscapeAlloc(allocator, state) catch state;

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
        .{ app_name, client_id_html, redirect_uri_html, scope_html, state_html },
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
    var parsed = parseBodyParams(allocator, req) catch
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "invalid form");

    const grant_type = parsed.get("grant_type") orelse "";
    if (!std.mem.eql(u8, std.mem.trim(u8, grant_type, " \t\r\n"), "authorization_code")) {
        return oauthErrorResponse(allocator, .bad_request, "unsupported_grant_type", "unsupported grant_type");
    }

    const code = std.mem.trim(u8, parsed.get("code") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing code"), " \t\r\n");
    const client_id = std.mem.trim(u8, parsed.get("client_id") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing client_id"), " \t\r\n");
    const client_secret = std.mem.trim(u8, parsed.get("client_secret") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing client_secret"), " \t\r\n");
    const redirect_uri = std.mem.trim(u8, parsed.get("redirect_uri") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing redirect_uri"), " \t\r\n");

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (app_row == null) return oauthErrorResponse(allocator, .bad_request, "invalid_client", "unknown client_id");
    if (!std.mem.eql(u8, app_row.?.client_secret, client_secret)) {
        return oauthErrorResponse(allocator, .unauthorized, "invalid_client", "invalid client_secret");
    }

    const consumed = oauth.consumeAuthCode(&app_state.conn, allocator, code) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (consumed == null) {
        app_state.logger.warn(
            "oauth token invalid_code reason=not_found client_id={s} redirect_uri={s} code_prefix={s}",
            .{ client_id, redirect_uri, code[0..@min(code.len, 8)] },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }
    if (consumed.?.app_id != app_row.?.id) {
        app_state.logger.warn(
            "oauth token invalid_code reason=app_mismatch client_id={s} redirect_uri={s} code_prefix={s} consumed_app_id={d}",
            .{ client_id, redirect_uri, code[0..@min(code.len, 8)], consumed.?.app_id },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }
    if (!std.mem.eql(u8, consumed.?.redirect_uri, redirect_uri)) {
        app_state.logger.warn(
            "oauth token invalid_code reason=redirect_mismatch client_id={s} code_prefix={s} expected_redirect_uri={s} got_redirect_uri={s}",
            .{ client_id, code[0..@min(code.len, 8)], consumed.?.redirect_uri, redirect_uri },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }

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
    const code_enc = try percentEncodeAlloc(allocator, code);
    if (state.len > 0) {
        const state_enc = try percentEncodeAlloc(allocator, state);
        return std.fmt.allocPrint(allocator, "{s}{s}code={s}&state={s}", .{ redirect_uri, sep, code_enc, state_enc });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}code={s}", .{ redirect_uri, sep, code_enc });
}

fn oauthErrorRedirect(allocator: std.mem.Allocator, redirect_uri: []const u8, err: []const u8, state: []const u8) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, redirect_uri, '?') == null) "?" else "&";
    const err_enc = try percentEncodeAlloc(allocator, err);
    if (state.len > 0) {
        const state_enc = try percentEncodeAlloc(allocator, state);
        return std.fmt.allocPrint(allocator, "{s}{s}error={s}&state={s}", .{ redirect_uri, sep, err_enc, state_enc });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}error={s}", .{ redirect_uri, sep, err_enc });
}

fn oauthErrorResponse(
    allocator: std.mem.Allocator,
    status: std.http.Status,
    err_code: []const u8,
    description: []const u8,
) Response {
    const body = std.json.Stringify.valueAlloc(
        allocator,
        .{ .@"error" = err_code, .error_description = description },
        .{},
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .status = status,
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
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

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
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

fn isJson(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "application/json");
}

fn isMultipart(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    return std.mem.startsWith(u8, ct, "multipart/form-data");
}

fn parseBodyParams(allocator: std.mem.Allocator, req: Request) !form.Form {
    if (isForm(req.content_type)) return try form.parse(allocator, req.body);
    if (isJson(req.content_type)) return try form.parseJson(allocator, req.body);
    if (isMultipart(req.content_type)) return try form.parseMultipart(allocator, req.content_type.?, req.body);
    return error.UnsupportedContentType;
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

test "GET /metrics -> 200 and includes build info" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{ .method = .GET, .target = "/metrics" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "feddyspice_build_info") != null);
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

test "GET /api/v2/instance -> 200 with domain" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{ .method = .GET, .target = "/api/v2/instance" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("example.test", parsed.value.object.get("domain").?.string);

    const cfg = parsed.value.object.get("configuration").?.object;
    try std.testing.expect(cfg.get("urls") != null);
    try std.testing.expect(cfg.get("polls") != null);
    try std.testing.expect(cfg.get("statuses") != null);

    const urls = cfg.get("urls").?.object;
    try std.testing.expectEqualStrings("ws://example.test", urls.get("streaming").?.string);

    const polls = cfg.get("polls").?.object;
    switch (polls.get("max_options").?) {
        .integer => |i| try std.testing.expectEqual(@as(i64, 4), i),
        .float => |f| try std.testing.expectEqual(@as(f64, 4), f),
        else => return error.TestUnexpectedResult,
    }
}

test "GET /api/v1/streaming -> 501" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{
        .method = .GET,
        .target = "/api/v1/streaming/?stream=user",
    });
    try std.testing.expectEqual(std.http.Status.not_implemented, resp.status);
}

test "GET /api/v1/streaming/health -> 200 OK" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{
        .method = .GET,
        .target = "/api/v1/streaming/health",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expectEqualStrings("\"OK\"", resp.body);
}

test "client compat: placeholder endpoints return JSON" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const Kind = enum { array, object };
    const Case = struct {
        method: std.http.Method,
        target: []const u8,
        kind: Kind,
        require_key: ?[]const u8 = null,
    };

    const cases = [_]Case{
        .{ .method = .GET, .target = "/api/v1/custom_emojis", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/follow_requests", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/scheduled_statuses", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/lists", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/announcements", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/trends/tags", .kind = .array },
        .{ .method = .GET, .target = "/api/v2/filters", .kind = .array },
        .{ .method = .GET, .target = "/api/v2/suggestions?", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/followed_tags", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/preferences", .kind = .object },
        .{ .method = .GET, .target = "/api/v1/push/subscription", .kind = .object },
        .{ .method = .GET, .target = "/api/v2/search?q=https%3A%2F%2Fexample.test%2F&resolve=true&limit=1", .kind = .object, .require_key = "accounts" },
        .{ .method = .GET, .target = "/api/v1/markers?timeline[]=notifications", .kind = .object, .require_key = "notifications" },
        .{ .method = .POST, .target = "/api/v1/markers", .kind = .object, .require_key = "notifications" },
    };

    for (cases) |tc| {
        const resp = handle(&app_state, a, .{
            .method = tc.method,
            .target = tc.target,
            .content_type = if (tc.method == .POST) "application/json" else null,
            .body = if (tc.method == .POST) "{}" else "",
        });

        try std.testing.expectEqual(std.http.Status.ok, resp.status);
        try std.testing.expect(std.mem.startsWith(u8, resp.content_type, "application/json"));

        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
        defer parsed.deinit();

        const tag = std.meta.activeTag(parsed.value);
        switch (tc.kind) {
            .array => {
                try std.testing.expect(tag == .array);
            },
            .object => {
                try std.testing.expect(tag == .object);
            },
        }

        if (tc.require_key) |k| {
            try std.testing.expect(parsed.value.object.get(k) != null);
        }

        if (std.mem.eql(u8, tc.target, "/api/v1/markers?timeline[]=notifications") or std.mem.eql(u8, tc.target, "/api/v1/markers")) {
            const notif = parsed.value.object.get("notifications").?.object;
            try std.testing.expect(notif.get("last_read_id") != null);
            try std.testing.expect(notif.get("version") != null);
            try std.testing.expect(notif.get("updated_at") != null);
        }
    }
}

test "notifications: GET/clear/dismiss" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read");

    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const n_id = try notifications.create(&app_state.conn, user_id, "follow", "https://remote.test/users/bob", null);

    const list_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/notifications?limit=20",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, list_resp.status);

    var list_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list_resp.body, .{});
    defer list_json.deinit();

    try std.testing.expect(list_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), list_json.value.array.items.len);
    try std.testing.expectEqualStrings("follow", list_json.value.array.items[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("bob", list_json.value.array.items[0].object.get("account").?.object.get("username").?.string);

    const dismiss_target = try std.fmt.allocPrint(a, "/api/v1/notifications/{d}/dismiss", .{n_id});
    const dismiss_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = dismiss_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, dismiss_resp.status);

    const clear_id = try notifications.create(&app_state.conn, user_id, "follow", "https://remote.test/users/bob", null);
    try std.testing.expect(clear_id > 0);

    const clear_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/notifications/clear",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, clear_resp.status);

    const list2 = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/notifications",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, list2.status);

    var list2_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list2.body, .{});
    defer list2_json.deinit();
    try std.testing.expect(list2_json.value == .array);
    try std.testing.expectEqual(@as(usize, 0), list2_json.value.array.items.len);
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

test "POST /api/v1/apps accepts json" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .POST,
        .target = "/api/v1/apps",
        .content_type = "application/json",
        .body =
        \\{"client_name":"pl-fe","redirect_uris":"urn:ietf:wg:oauth:2.0:oob","scopes":"read write","website":""}
        ,
    });

    try std.testing.expectEqual(std.http.Status.ok, resp.status);
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

test "oauth: authorization code flow (redirect uri)" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const redirect_uri_enc = "https%3A%2F%2Fpl.mkljczk.pl%2Flogin%2Fexternal";
    const app_body = std.fmt.allocPrint(
        a,
        "client_name=pl-fe&redirect_uris={s}&scopes=read+write+follow&website=",
        .{redirect_uri_enc},
    ) catch return error.OutOfMemory;

    const app_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/apps",
        .content_type = "application/x-www-form-urlencoded",
        .body = app_body,
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

    const auth_post_body = std.fmt.allocPrint(
        a,
        "response_type=code&client_id={s}&redirect_uri={s}&scope=read+write&state=xyz&approve=1",
        .{ client_id, redirect_uri_enc },
    ) catch return error.OutOfMemory;

    const auth_post = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/authorize",
        .content_type = "application/x-www-form-urlencoded",
        .body = auth_post_body,
        .cookie = cookie_header,
    });
    try std.testing.expectEqual(std.http.Status.see_other, auth_post.status);

    var location: ?[]const u8 = null;
    for (auth_post.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "location")) location = h.value;
    }
    const loc = location orelse return error.TestUnexpectedResult;

    const qs_idx = std.mem.indexOfScalar(u8, loc, '?') orelse return error.TestUnexpectedResult;
    var qp = try form.parse(a, loc[qs_idx + 1 ..]);
    const code = qp.get("code") orelse return error.TestUnexpectedResult;

    const boundary = "----webkitboundary";
    const token_body = std.fmt.allocPrint(
        a,
        "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"grant_type\"\r\n" ++
            "\r\n" ++
            "authorization_code\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"code\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"client_id\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"client_secret\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"redirect_uri\"\r\n" ++
            "\r\n" ++
            "https://pl.mkljczk.pl/login/external\r\n" ++
            "--{s}--\r\n",
        .{
            boundary,
            boundary,
            code,
            boundary,
            client_id,
            boundary,
            client_secret,
            boundary,
            boundary,
        },
    ) catch return error.OutOfMemory;

    const token_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/token",
        .content_type = "multipart/form-data; boundary=----webkitboundary",
        .body = token_body,
    });
    try std.testing.expectEqual(std.http.Status.ok, token_resp.status);
}

test "oauth: token endpoint accepts json" {
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

    const token_json_body = std.fmt.allocPrint(
        a,
        \\{{"grant_type":"authorization_code","code":"{s}","client_id":"{s}","client_secret":"{s}","redirect_uri":"urn:ietf:wg:oauth:2.0:oob","scope":"read write"}}
    ,
        .{ code, client_id, client_secret },
    ) catch return error.OutOfMemory;

    const token_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/token",
        .content_type = "application/json",
        .body = token_json_body,
    });
    try std.testing.expectEqual(std.http.Status.ok, token_resp.status);
}

test "oauth: token endpoint accepts multipart form-data" {
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

    const boundary = "----feddyspiceboundary";
    const token_body = std.fmt.allocPrint(
        a,
        "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"grant_type\"\r\n" ++
            "\r\n" ++
            "authorization_code\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"code\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"client_id\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"client_secret\"\r\n" ++
            "\r\n" ++
            "{s}\r\n" ++
            "--{s}\r\n" ++
            "Content-Disposition: form-data; name=\"redirect_uri\"\r\n" ++
            "\r\n" ++
            "urn:ietf:wg:oauth:2.0:oob\r\n" ++
            "--{s}--\r\n",
        .{
            boundary,
            boundary,
            code,
            boundary,
            client_id,
            boundary,
            client_secret,
            boundary,
            boundary,
        },
    ) catch return error.OutOfMemory;

    const token_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/oauth/token",
        .content_type = "multipart/form-data; boundary=----feddyspiceboundary",
        .body = token_body,
    });
    try std.testing.expectEqual(std.http.Status.ok, token_resp.status);
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
    try std.testing.expectEqualStrings("http://example.test/users/alice", parsed.value.object.get("url").?.string);
    try std.testing.expectEqualStrings("http://example.test/static/avatar.png", parsed.value.object.get("avatar_static").?.string);
    try std.testing.expectEqualStrings("http://example.test/static/header.png", parsed.value.object.get("header").?.string);
    try std.testing.expectEqualStrings("http://example.test/static/header.png", parsed.value.object.get("header_static").?.string);
}

test "accounts: lookup + get account" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const id_str = try std.fmt.allocPrint(a, "{d}", .{user_id});

    const lookup_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/accounts/lookup?acct=alice",
    });
    try std.testing.expectEqual(std.http.Status.ok, lookup_resp.status);

    var lookup_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, lookup_resp.body, .{});
    defer lookup_json.deinit();

    try std.testing.expectEqualStrings(id_str, lookup_json.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("alice", lookup_json.value.object.get("username").?.string);
    try std.testing.expectEqualStrings("alice", lookup_json.value.object.get("acct").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", lookup_json.value.object.get("url").?.string);

    const get_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}", .{id_str});
    const get_resp = handle(&app_state, a, .{ .method = .GET, .target = get_target });
    try std.testing.expectEqual(std.http.Status.ok, get_resp.status);

    var get_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, get_resp.body, .{});
    defer get_json.deinit();

    try std.testing.expectEqualStrings(id_str, get_json.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("alice", get_json.value.object.get("username").?.string);
    try std.testing.expectEqualStrings("alice", get_json.value.object.get("acct").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", get_json.value.object.get("url").?.string);
}

test "accounts: relationships" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const id_str = try std.fmt.allocPrint(a, "{d}", .{user_id});

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const target = try std.fmt.allocPrint(a, "/api/v1/accounts/relationships?id[]={s}&id[]=999", .{id_str});

    const resp = handle(&app_state, a, .{
        .method = .GET,
        .target = target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value == .array);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.array.items.len);
    try std.testing.expectEqualStrings(id_str, parsed.value.array.items[0].object.get("id").?.string);
    try std.testing.expectEqualStrings("999", parsed.value.array.items[1].object.get("id").?.string);
}

test "accounts: statuses list (public vs authed)" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const id_str = try std.fmt.allocPrint(a, "{d}", .{user_id});

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    _ = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=pub&visibility=public",
        .authorization = auth_header,
    });

    _ = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=secret&visibility=private",
        .authorization = auth_header,
    });

    const statuses_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/statuses?exclude_replies=true", .{id_str});

    const public_resp = handle(&app_state, a, .{ .method = .GET, .target = statuses_target });
    try std.testing.expectEqual(std.http.Status.ok, public_resp.status);

    var public_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, public_resp.body, .{});
    defer public_json.deinit();

    try std.testing.expect(public_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), public_json.value.array.items.len);
    try std.testing.expectEqualStrings("<p>pub</p>", public_json.value.array.items[0].object.get("content").?.string);

    const authed_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = statuses_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, authed_resp.status);

    var authed_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, authed_resp.body, .{});
    defer authed_json.deinit();

    try std.testing.expect(authed_json.value == .array);
    try std.testing.expectEqual(@as(usize, 2), authed_json.value.array.items.len);

    const pinned_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/statuses?pinned=true", .{id_str});
    const pinned_resp = handle(&app_state, a, .{ .method = .GET, .target = pinned_target });
    try std.testing.expectEqual(std.http.Status.ok, pinned_resp.status);

    var pinned_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, pinned_resp.body, .{});
    defer pinned_json.deinit();
    try std.testing.expect(pinned_json.value == .array);
    try std.testing.expectEqual(@as(usize, 0), pinned_json.value.array.items.len);
}

test "accounts: followers + following lists" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    try followers.upsertPending(&app_state.conn, user_id, "https://remote.test/users/bob", "https://remote.test/follows/1");
    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, "https://remote.test/users/bob"));

    _ = try follows.createPending(&app_state.conn, user_id, "https://remote.test/users/bob", "http://example.test/follows/1");
    try std.testing.expect(try follows.markAcceptedByActivityId(&app_state.conn, "http://example.test/follows/1"));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const id_str = try std.fmt.allocPrint(a, "{d}", .{user_id});

    const followers_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/followers", .{id_str});
    const followers_resp = handle(&app_state, a, .{ .method = .GET, .target = followers_target });
    try std.testing.expectEqual(std.http.Status.ok, followers_resp.status);

    var followers_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, followers_resp.body, .{});
    defer followers_json.deinit();
    try std.testing.expect(followers_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), followers_json.value.array.items.len);
    try std.testing.expectEqualStrings("bob", followers_json.value.array.items[0].object.get("username").?.string);
    try std.testing.expectEqualStrings("bob@remote.test", followers_json.value.array.items[0].object.get("acct").?.string);

    const following_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/following", .{id_str});
    const following_resp = handle(&app_state, a, .{ .method = .GET, .target = following_target });
    try std.testing.expectEqual(std.http.Status.ok, following_resp.status);

    var following_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, following_resp.body, .{});
    defer following_json.deinit();
    try std.testing.expect(following_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), following_json.value.array.items.len);
    try std.testing.expectEqualStrings("bob", following_json.value.array.items[0].object.get("username").?.string);
    try std.testing.expectEqualStrings("bob@remote.test", following_json.value.array.items[0].object.get("acct").?.string);
}

test "statuses: create + get + home timeline" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();

    const id = create_json.value.object.get("id").?.string;
    try std.testing.expectEqualStrings("<p>hello</p>", create_json.value.object.get("content").?.string);
    try std.testing.expectEqualStrings("alice", create_json.value.object.get("account").?.object.get("username").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", create_json.value.object.get("account").?.object.get("url").?.string);
    try std.testing.expectEqualStrings(
        "http://example.test/static/avatar.png",
        create_json.value.object.get("account").?.object.get("avatar_static").?.string,
    );
    try std.testing.expectEqualStrings(
        "http://example.test/static/header.png",
        create_json.value.object.get("account").?.object.get("header_static").?.string,
    );
    try std.testing.expectEqual(@as(bool, false), create_json.value.object.get("sensitive").?.bool);

    const expected_uri = try std.fmt.allocPrint(a, "http://example.test/api/v1/statuses/{s}", .{id});
    try std.testing.expectEqualStrings(expected_uri, create_json.value.object.get("uri").?.string);

    const get_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id});
    const get_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = get_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, get_resp.status);

    var get_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, get_resp.body, .{});
    defer get_json.deinit();
    try std.testing.expectEqualStrings(id, get_json.value.object.get("id").?.string);

    const tl_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/home",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, tl_resp.status);

    var tl_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, tl_resp.body, .{});
    defer tl_json.deinit();

    try std.testing.expectEqual(@as(usize, 1), tl_json.value.array.items.len);
    try std.testing.expectEqualStrings(id, tl_json.value.array.items[0].object.get("id").?.string);
}

test "POST /api/v1/statuses publishes streaming update" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    const sub = try app_state.streaming.subscribe(user_id, &.{.user});
    defer app_state.streaming.unsubscribe(sub);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    const msg = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg);

    var env_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg, .{});
    defer env_json.deinit();

    try std.testing.expectEqualStrings("update", env_json.value.object.get("event").?.string);
    try std.testing.expectEqualStrings(create_resp.body, env_json.value.object.get("payload").?.string);
}

test "statuses: context endpoint returns empty arrays" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id = create_json.value.object.get("id").?.string;

    const ctx_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}/context", .{id});
    const ctx_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = ctx_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, ctx_resp.status);

    var ctx_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, ctx_resp.body, .{});
    defer ctx_json.deinit();

    try std.testing.expect(ctx_json.value == .object);
    const ancestors = ctx_json.value.object.get("ancestors").?;
    const descendants = ctx_json.value.object.get("descendants").?;
    try std.testing.expect(ancestors == .array);
    try std.testing.expect(descendants == .array);
    try std.testing.expectEqual(@as(usize, 0), ancestors.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), descendants.array.items.len);
}

test "statuses: favourite/reblog/bookmark endpoints return status" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id = create_json.value.object.get("id").?.string;

    const suffixes = [_][]const u8{
        "/favourite",
        "/unfavourite",
        "/reblog",
        "/unreblog",
        "/bookmark",
        "/unbookmark",
    };

    for (suffixes) |suffix| {
        const target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}{s}", .{ id, suffix });
        const resp = handle(&app_state, a, .{
            .method = .POST,
            .target = target,
            .authorization = auth_header,
        });
        try std.testing.expectEqual(std.http.Status.ok, resp.status);

        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings(id, parsed.value.object.get("id").?.string);
    }
}

test "media: upload + update + fetch" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const ct = "multipart/form-data; boundary=abc";
    const body =
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"description\"\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "PNGDATA\r\n" ++
        "--abc--\r\n";

    const upload_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/media",
        .content_type = ct,
        .body = body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, upload_resp.status);

    var upload_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, upload_resp.body, .{});
    defer upload_json.deinit();

    const media_id = upload_json.value.object.get("id").?.string;
    try std.testing.expectEqualStrings("image", upload_json.value.object.get("type").?.string);
    try std.testing.expectEqualStrings("hello", upload_json.value.object.get("description").?.string);

    const url = upload_json.value.object.get("url").?.string;
    try std.testing.expect(std.mem.startsWith(u8, url, "http://example.test/media/"));

    const path = url["http://example.test".len..];
    const file_resp = handle(&app_state, a, .{ .method = .GET, .target = path });
    try std.testing.expectEqual(std.http.Status.ok, file_resp.status);
    try std.testing.expectEqualStrings("image/png", file_resp.content_type);
    try std.testing.expectEqualStrings("PNGDATA", file_resp.body);

    const put_target = try std.fmt.allocPrint(a, "/api/v1/media/{s}", .{media_id});
    const upd_resp = handle(&app_state, a, .{
        .method = .PUT,
        .target = put_target,
        .content_type = "application/x-www-form-urlencoded",
        .body = "description=new",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, upd_resp.status);

    var upd_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, upd_resp.body, .{});
    defer upd_json.deinit();
    try std.testing.expectEqualStrings("new", upd_json.value.object.get("description").?.string);
}

test "statuses: create supports media_ids[] attachments" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const now_ms: i64 = 123;
    const m1 = try media.createWithToken(&app_state.conn, a, user_id, "tok1", "image/png", "x", "d1", now_ms);
    const m2 = try media.createWithToken(&app_state.conn, a, user_id, "tok2", "image/png", "y", "d2", now_ms);

    const create_body = try std.fmt.allocPrint(
        a,
        "status=hello&visibility=public&media_ids[]={d}&media_ids[]={d}",
        .{ m1.id, m2.id },
    );

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = create_body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();

    const attachments = create_json.value.object.get("media_attachments").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), attachments.len);
    try std.testing.expectEqualStrings(
        try std.fmt.allocPrint(a, "{d}", .{m1.id}),
        attachments[0].object.get("id").?.string,
    );
    try std.testing.expectEqualStrings(
        try std.fmt.allocPrint(a, "{d}", .{m2.id}),
        attachments[1].object.get("id").?.string,
    );
    try std.testing.expect(std.mem.endsWith(u8, attachments[0].object.get("url").?.string, "/media/tok1"));
    try std.testing.expect(std.mem.endsWith(u8, attachments[1].object.get("url").?.string, "/media/tok2"));
}

test "statuses: delete removes attached media" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const now_ms: i64 = 123;
    const m1 = try media.createWithToken(&app_state.conn, a, user_id, "tok1", "image/png", "x", "d1", now_ms);

    const create_body = try std.fmt.allocPrint(
        a,
        "status=hello&visibility=public&media_ids[]={d}",
        .{m1.id},
    );
    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = create_body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const status_id = create_json.value.object.get("id").?.string;

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{status_id});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    const file_resp = handle(&app_state, a, .{ .method = .GET, .target = "/media/tok1" });
    try std.testing.expectEqual(std.http.Status.not_found, file_resp.status);
}

test "statuses: create rolls back on invalid media id" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public&media_ids[]=999",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.unprocessable_entity, create_resp.status);

    const tl_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/home",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, tl_resp.status);

    var tl_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, tl_resp.body, .{});
    defer tl_json.deinit();
    try std.testing.expect(tl_json.value == .array);
    try std.testing.expectEqual(@as(usize, 0), tl_json.value.array.items.len);
}

test "timelines: public timeline returns local statuses" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=hello&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();

    const id = create_json.value.object.get("id").?.string;

    const tl_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/public?local=true&only_media=false",
    });
    try std.testing.expectEqual(std.http.Status.ok, tl_resp.status);

    var tl_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, tl_resp.body, .{});
    defer tl_json.deinit();

    try std.testing.expect(tl_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), tl_json.value.array.items.len);
    try std.testing.expectEqualStrings(id, tl_json.value.array.items[0].object.get("id").?.string);
}

test "timelines: tag/list/link placeholders return empty arrays" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const targets = [_][]const u8{
        "/api/v1/timelines/tag/test",
        "/api/v1/timelines/list/1",
        "/api/v1/timelines/link?url=https%3A%2F%2Fexample.test%2F",
    };

    for (targets) |target| {
        const resp = handle(&app_state, a, .{ .method = .GET, .target = target });
        try std.testing.expectEqual(std.http.Status.ok, resp.status);

        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value == .array);
        try std.testing.expectEqual(@as(usize, 0), parsed.value.array.items.len);
    }
}

test "timelines: home timeline pagination (Link + max_id/since_id)" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    _ = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=one&visibility=public",
        .authorization = auth_header,
    });
    _ = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=two&visibility=public",
        .authorization = auth_header,
    });
    _ = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=three&visibility=public",
        .authorization = auth_header,
    });

    const page1 = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/home?limit=2",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, page1.status);

    const link = blk: {
        for (page1.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "link")) break :blk h.value;
        }
        break :blk null;
    };
    try std.testing.expect(link != null);

    var page1_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, page1.body, .{});
    defer page1_json.deinit();
    try std.testing.expect(page1_json.value == .array);
    try std.testing.expectEqual(@as(usize, 2), page1_json.value.array.items.len);

    const newest_id = page1_json.value.array.items[0].object.get("id").?.string;
    const oldest_id = page1_json.value.array.items[1].object.get("id").?.string;

    const next_max_id = extractBetween(link.?, "max_id=", ">;") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(oldest_id, next_max_id);

    const page2_target = try std.fmt.allocPrint(a, "/api/v1/timelines/home?limit=2&max_id={s}", .{next_max_id});
    const page2 = handle(&app_state, a, .{
        .method = .GET,
        .target = page2_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, page2.status);

    var page2_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, page2.body, .{});
    defer page2_json.deinit();
    try std.testing.expect(page2_json.value == .array);
    try std.testing.expectEqual(@as(usize, 1), page2_json.value.array.items.len);
    const page2_id = page2_json.value.array.items[0].object.get("id").?.string;
    try std.testing.expect(!std.mem.eql(u8, page2_id, newest_id));
    try std.testing.expect(!std.mem.eql(u8, page2_id, oldest_id));

    const since_target = try std.fmt.allocPrint(a, "/api/v1/timelines/home?since_id={s}", .{newest_id});
    const since_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = since_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, since_resp.status);

    var since_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, since_resp.body, .{});
    defer since_json.deinit();
    try std.testing.expect(since_json.value == .array);
    try std.testing.expectEqual(@as(usize, 0), since_json.value.array.items.len);
}

test "statuses: delete" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=bye&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id = create_json.value.object.get("id").?.string;

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    const get_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.not_found, get_resp.status);
}

test "ActivityPub: deleted local status returns Tombstone" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=bye&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id = create_json.value.object.get("id").?.string;

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    const ap_target = try std.fmt.allocPrint(a, "/users/alice/statuses/{s}", .{id});
    const ap_resp = handle(&app_state, a, .{ .method = .GET, .target = ap_target });
    try std.testing.expectEqual(std.http.Status.ok, ap_resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, ap_resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("Tombstone", parsed.value.object.get("type").?.string);
    try std.testing.expect(parsed.value.object.get("deleted") != null);
}

test "remote statuses: appear in home timeline and can be fetched" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const local_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=local&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, local_resp.status);

    var local_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, local_resp.body, .{});
    defer local_json.deinit();

    const local_id = local_json.value.object.get("id").?.string;

    const sub = try app_state.streaming.subscribe(user_id, &.{.user});
    defer app_state.streaming.unsubscribe(sub);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const inbox_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Remote</p>","published":"2999-01-01T00:00:00.000Z"}}
    ;

    const inbox_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = inbox_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, inbox_resp.status);

    const msg = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg);

    var env_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg, .{});
    defer env_json.deinit();
    try std.testing.expectEqualStrings("update", env_json.value.object.get("event").?.string);

    const payload_str = env_json.value.object.get("payload").?.string;
    var payload_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload_str, .{});
    defer payload_json.deinit();

    const remote_id_copy = try a.dupe(u8, payload_json.value.object.get("id").?.string);
    try std.testing.expect(std.mem.startsWith(u8, remote_id_copy, "-"));
    try std.testing.expectEqualStrings("<p>Remote</p>", payload_json.value.object.get("content").?.string);

    const tl_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/home",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, tl_resp.status);

    var tl_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, tl_resp.body, .{});
    defer tl_json.deinit();

    try std.testing.expectEqual(@as(usize, 2), tl_json.value.array.items.len);

    const first_id = tl_json.value.array.items[0].object.get("id").?.string;
    const second_id = tl_json.value.array.items[1].object.get("id").?.string;

    try std.testing.expect(std.mem.startsWith(u8, first_id, "-"));
    try std.testing.expectEqualStrings(remote_id_copy, first_id);
    try std.testing.expectEqualStrings(local_id, second_id);
    try std.testing.expectEqualStrings("<p>Remote</p>", tl_json.value.array.items[0].object.get("content").?.string);
    try std.testing.expectEqualStrings(
        "bob",
        tl_json.value.array.items[0].object.get("account").?.object.get("username").?.string,
    );

    const get_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{first_id});
    const get_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = get_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, get_resp.status);

    var get_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, get_resp.body, .{});
    defer get_json.deinit();

    try std.testing.expectEqualStrings(first_id, get_json.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("<p>Remote</p>", get_json.value.object.get("content").?.string);
    try std.testing.expectEqualStrings(
        "bob@remote.test",
        get_json.value.object.get("account").?.object.get("acct").?.string,
    );
}

test "POST /api/v1/follows requires bearer token" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .POST,
        .target = "/api/v1/follows",
        .content_type = "application/x-www-form-urlencoded",
        .body = "uri=@bob@remote.test",
    });
    try std.testing.expectEqual(std.http.Status.unauthorized, resp.status);
}

test "GET /api/v2/search resolves acct handle into an account" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try mock.pushExpected(.{
        .method = .GET,
        .url = "http://remote.test/.well-known/webfinger?resource=acct:bob@remote.test",
        .response_status = .ok,
        .response_body = "{\"subject\":\"acct:bob@remote.test\",\"links\":[{\"rel\":\"self\",\"type\":\"application/activity+json\",\"href\":\"http://remote.test/users/bob\"}]}",
    });
    try mock.pushExpected(.{
        .method = .GET,
        .url = "http://remote.test/users/bob",
        .response_status = .ok,
        .response_body = "{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"http://remote.test/users/bob\",\"type\":\"Person\",\"preferredUsername\":\"bob\",\"inbox\":\"http://remote.test/users/bob/inbox\",\"publicKey\":{\"id\":\"http://remote.test/users/bob#main-key\",\"owner\":\"http://remote.test/users/bob\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n\"}}",
    });

    const handle_str = "@bob@remote.test";
    const q_enc = try percentEncodeAlloc(a, handle_str);

    const target = try std.fmt.allocPrint(a, "/api/v2/search?q={s}&resolve=true&limit=1", .{q_enc});
    const resp = handle(&app_state, a, .{ .method = .GET, .target = target });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    const accounts = parsed.value.object.get("accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);

    const actor_id = "http://remote.test/users/bob";
    const rowid = (try remote_actors.lookupRowIdById(&app_state.conn, actor_id)).?;
    const expected_id = try std.fmt.allocPrint(a, "{d}", .{remote_actor_id_base + rowid});

    try std.testing.expectEqualStrings(expected_id, accounts[0].object.get("id").?.string);
    try std.testing.expectEqualStrings("bob@remote.test", accounts[0].object.get("acct").?.string);
    try std.testing.expectEqualStrings(actor_id, accounts[0].object.get("url").?.string);
}

test "POST /api/v1/accounts/:id/follow creates pending follow and delivers Follow" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_actor_id = "http://remote.test/users/bob";
    const remote_inbox = "http://remote.test/users/bob/inbox";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = remote_inbox,
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const rowid = (try remote_actors.lookupRowIdById(&app_state.conn, remote_actor_id)).?;
    const account_id_str = try std.fmt.allocPrint(a, "{d}", .{remote_actor_id_base + rowid});

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read follow",
        "",
    );
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read follow");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const follow_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/follow", .{account_id_str});
    const follow_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = follow_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, follow_resp.status);

    var follow_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, follow_resp.body, .{});
    defer follow_json.deinit();

    try std.testing.expectEqualStrings(account_id_str, follow_json.value.object.get("id").?.string);
    try std.testing.expect(follow_json.value.object.get("requested").?.bool);

    const f = (try follows.lookupByUserAndRemoteActorId(&app_state.conn, a, user_id, remote_actor_id)).?;
    try std.testing.expectEqual(follows.FollowState.pending, f.state);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];
    try std.testing.expectEqual(std.http.Method.POST, delivered.method);
    try std.testing.expectEqualStrings(remote_inbox, delivered.url);

    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;
    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();
    try std.testing.expectEqualStrings("Follow", delivered_json.value.object.get("type").?.string);
}

test "GET /.well-known/webfinger returns actor self link" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .GET,
        .target = "/.well-known/webfinger?resource=acct:alice@example.test",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("acct:alice@example.test", parsed.value.object.get("subject").?.string);

    const links = parsed.value.object.get("links").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), links.len);
    try std.testing.expectEqualStrings("self", links[0].object.get("rel").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", links[0].object.get("href").?.string);
}

test "GET /.well-known/host-meta advertises WebFinger template" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .GET,
        .target = "/.well-known/host-meta",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    try std.testing.expect(std.mem.indexOf(u8, resp.body, ".well-known/webfinger") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "http://example.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "{uri}") != null);
}

test "GET /.well-known/nodeinfo returns discovery document" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .GET,
        .target = "/.well-known/nodeinfo",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    const links = parsed.value.object.get("links").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), links.len);
    try std.testing.expectEqualStrings(
        "http://nodeinfo.diaspora.software/ns/schema/2.0",
        links[0].object.get("rel").?.string,
    );
    try std.testing.expectEqualStrings("http://example.test/nodeinfo/2.0", links[0].object.get("href").?.string);
}

test "GET /nodeinfo/2.0 returns nodeinfo document" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .GET,
        .target = "/nodeinfo/2.0",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("2.0", parsed.value.object.get("version").?.string);
    try std.testing.expectEqualStrings("feddyspice", parsed.value.object.get("software").?.object.get("name").?.string);
}

test "GET /users/:name returns ActivityPub actor" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const resp = handle(&app_state, arena.allocator(), .{
        .method = .GET,
        .target = "/users/alice",
    });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, resp.body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("Person", parsed.value.object.get("type").?.string);
    try std.testing.expectEqualStrings("alice", parsed.value.object.get("preferredUsername").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", parsed.value.object.get("id").?.string);

    const pk_pem = parsed.value.object.get("publicKey").?.object.get("publicKeyPem").?.string;
    try std.testing.expect(std.mem.indexOf(u8, pk_pem, "BEGIN PUBLIC KEY") != null);
}

test "POST /users/:name/inbox Follow stores follower and sends Accept" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    _ = try actor_keys.ensureForUser(&app_state.conn, a, user_id);

    const remote_actor_id = "https://remote.test/users/bob";
    const remote_inbox = "https://remote.test/users/bob/inbox";
    const follow_id = "https://remote.test/follows/1";

    try mock.pushExpected(.{
        .method = .GET,
        .url = remote_actor_id,
        .response_status = .ok,
        .response_body = "{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://remote.test/users/bob\",\"type\":\"Person\",\"preferredUsername\":\"bob\",\"inbox\":\"https://remote.test/users/bob/inbox\",\"publicKey\":{\"id\":\"https://remote.test/users/bob#main-key\",\"owner\":\"https://remote.test/users/bob\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n\"}}",
    });
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const follow_body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"{s}\",\"type\":\"Follow\",\"actor\":\"{s}\",\"object\":\"http://example.test/users/alice\"}}",
        .{ follow_id, remote_actor_id },
    );

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = follow_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 2), mock.requests.items.len);
    const accept_req = mock.requests.items[1];
    try std.testing.expectEqual(std.http.Method.POST, accept_req.method);
    try std.testing.expectEqualStrings(remote_inbox, accept_req.url);

    const accept_body = accept_req.payload orelse return error.TestUnexpectedResult;
    var accept_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, accept_body, .{});
    defer accept_json.deinit();

    try std.testing.expectEqualStrings("Accept", accept_json.value.object.get("type").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", accept_json.value.object.get("actor").?.string);

    const obj = accept_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings("Follow", obj.get("type").?.string);
    try std.testing.expectEqualStrings(follow_id, obj.get("id").?.string);
    try std.testing.expectEqualStrings(remote_actor_id, obj.get("actor").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", obj.get("object").?.string);

    const follower = (try followers.lookupByRemoteActorId(&app_state.conn, a, user_id, remote_actor_id)).?;
    try std.testing.expectEqual(followers.FollowerState.accepted, follower.state);

    const notifs = try notifications.list(&app_state.conn, a, user_id, 10, null);
    try std.testing.expectEqual(@as(usize, 1), notifs.len);
    try std.testing.expectEqualStrings("follow", notifs[0].kind);
    try std.testing.expectEqualStrings(remote_actor_id, notifs[0].actor_id);
    try std.testing.expectEqual(@as(?i64, null), notifs[0].status_id);

    const followers_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/users/alice/followers",
    });
    try std.testing.expectEqual(std.http.Status.ok, followers_resp.status);

    var followers_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, followers_resp.body, .{});
    defer followers_json.deinit();

    const items = followers_json.value.object.get("orderedItems").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expectEqualStrings(remote_actor_id, items[0].string);
}

test "GET /users/:name/outbox and /users/:name/statuses/:id return ActivityPub objects" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const s1 = try statuses.create(&app_state.conn, a, user_id, "hello", "public");
    const s2 = try statuses.create(&app_state.conn, a, user_id, "world", "public");

    const outbox_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/users/alice/outbox",
    });
    try std.testing.expectEqual(std.http.Status.ok, outbox_resp.status);

    var outbox_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, outbox_resp.body, .{});
    defer outbox_json.deinit();
    try std.testing.expectEqualStrings("OrderedCollection", outbox_json.value.object.get("type").?.string);
    try std.testing.expect(outbox_json.value.object.get("first") != null);

    const page_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/users/alice/outbox?page=true",
    });
    try std.testing.expectEqual(std.http.Status.ok, page_resp.status);

    var page_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, page_resp.body, .{});
    defer page_json.deinit();
    try std.testing.expectEqualStrings("OrderedCollectionPage", page_json.value.object.get("type").?.string);

    const items = page_json.value.object.get("orderedItems").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("Create", items[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("Note", items[0].object.get("object").?.object.get("type").?.string);

    const note_id_str = std.fmt.allocPrint(a, "/users/alice/statuses/{d}", .{s1.id}) catch
        return error.OutOfMemory;

    const note_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = note_id_str,
    });
    try std.testing.expectEqual(std.http.Status.ok, note_resp.status);

    var note_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, note_resp.body, .{});
    defer note_json.deinit();
    try std.testing.expectEqualStrings("Note", note_json.value.object.get("type").?.string);

    const expected_note_id = std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{d}", .{s1.id}) catch
        return error.OutOfMemory;
    try std.testing.expectEqualStrings(expected_note_id, note_json.value.object.get("id").?.string);
    try std.testing.expectEqualStrings("<p>hello</p>", note_json.value.object.get("content").?.string);

    const expected_note2_id = std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{d}", .{s2.id}) catch
        return error.OutOfMemory;
    try std.testing.expectEqualStrings(expected_note2_id, items[0].object.get("object").?.object.get("id").?.string);
}

test "ActivityPub visibility: outbox + note endpoints do not leak private/direct, and unlisted uses cc=Public" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const public_st = try statuses.create(&app_state.conn, a, user_id, "pub", "public");
    const unlisted_st = try statuses.create(&app_state.conn, a, user_id, "unlisted", "unlisted");
    const private_st = try statuses.create(&app_state.conn, a, user_id, "priv", "private");
    const direct_st = try statuses.create(&app_state.conn, a, user_id, "dm", "direct");

    const outbox_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/users/alice/outbox",
    });
    try std.testing.expectEqual(std.http.Status.ok, outbox_resp.status);

    var outbox_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, outbox_resp.body, .{});
    defer outbox_json.deinit();

    try std.testing.expectEqualStrings("OrderedCollection", outbox_json.value.object.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 2), outbox_json.value.object.get("totalItems").?.integer);

    const page_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/users/alice/outbox?page=true",
    });
    try std.testing.expectEqual(std.http.Status.ok, page_resp.status);

    var page_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, page_resp.body, .{});
    defer page_json.deinit();

    const items = page_json.value.object.get("orderedItems").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), items.len);

    // Public Note is visible and uses to=Public.
    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    const public_note_id = try std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{d}", .{public_st.id});
    const unlisted_note_id = try std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{d}", .{unlisted_st.id});

    // We don't care about ordering here; check by ID.
    var saw_public: bool = false;
    var saw_unlisted: bool = false;
    for (items) |it| {
        const obj = it.object.get("object").?.object;
        const id_val = obj.get("id").?.string;
        if (std.mem.eql(u8, id_val, public_note_id)) saw_public = true;
        if (std.mem.eql(u8, id_val, unlisted_note_id)) saw_unlisted = true;
    }
    try std.testing.expect(saw_public);
    try std.testing.expect(saw_unlisted);

    const followers_url = "http://example.test/users/alice/followers";

    const unlisted_note_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = try std.fmt.allocPrint(a, "/users/alice/statuses/{d}", .{unlisted_st.id}),
    });
    try std.testing.expectEqual(std.http.Status.ok, unlisted_note_resp.status);

    var unlisted_note_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, unlisted_note_resp.body, .{});
    defer unlisted_note_json.deinit();

    const unlisted_to = unlisted_note_json.value.object.get("to").?.array.items;
    const unlisted_cc = unlisted_note_json.value.object.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), unlisted_to.len);
    try std.testing.expectEqual(@as(usize, 1), unlisted_cc.len);
    try std.testing.expectEqualStrings(followers_url, unlisted_to[0].string);
    try std.testing.expectEqualStrings(public_iri, unlisted_cc[0].string);

    const private_note_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = try std.fmt.allocPrint(a, "/users/alice/statuses/{d}", .{private_st.id}),
    });
    try std.testing.expectEqual(std.http.Status.not_found, private_note_resp.status);

    const direct_note_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = try std.fmt.allocPrint(a, "/users/alice/statuses/{d}", .{direct_st.id}),
    });
    try std.testing.expectEqual(std.http.Status.not_found, direct_note_resp.status);
}

test "POST /api/v1/statuses delivers Create to followers" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const keys = try actor_keys.ensureForUser(&app_state.conn, a, user_id);

    const remote_actor_id = "http://remote.test/users/bob";
    const remote_inbox = "http://remote.test/users/bob/inbox";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = remote_inbox,
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const follow_id = "http://remote.test/follows/1";
    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, follow_id);
    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=federated&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];
    try std.testing.expectEqual(std.http.Method.POST, delivered.method);
    try std.testing.expectEqualStrings(remote_inbox, delivered.url);

    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;

    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();

    try std.testing.expectEqualStrings("Create", delivered_json.value.object.get("type").?.string);
    const obj = delivered_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings("<p>federated</p>", obj.get("content").?.string);

    const date = headerValue(delivered.extra_headers, "date") orelse return error.TestUnexpectedResult;
    const digest = headerValue(delivered.extra_headers, "digest") orelse return error.TestUnexpectedResult;
    const signature = headerValue(delivered.extra_headers, "signature") orelse return error.TestUnexpectedResult;

    const expected_digest = try @import("http_signatures.zig").digestHeaderValueAlloc(a, delivered_body);
    try std.testing.expectEqualStrings(expected_digest, digest);

    const signing_string = try @import("http_signatures.zig").signingStringAlloc(a, .POST, "/users/bob/inbox", "remote.test", date, digest);

    const sig_prefix = "signature=\"";
    const sig_b64_i = std.mem.indexOf(u8, signature, sig_prefix) orelse return error.TestUnexpectedResult;
    const sig_b64_start = sig_b64_i + sig_prefix.len;
    const sig_b64_end = std.mem.indexOfPos(u8, signature, sig_b64_start, "\"") orelse return error.TestUnexpectedResult;
    const sig_b64 = signature[sig_b64_start..sig_b64_end];

    const sig_len = std.base64.standard.Decoder.calcSizeForSlice(sig_b64) catch return error.TestUnexpectedResult;
    const sig_bytes = try a.alloc(u8, sig_len);
    std.base64.standard.Decoder.decode(sig_bytes, sig_b64) catch return error.TestUnexpectedResult;

    try std.testing.expect(try @import("crypto_rsa.zig").verifyRsaSha256Pem(keys.public_key_pem, signing_string, sig_bytes));
}

test "POST /api/v1/statuses visibility=private delivers Create without Public recipients" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_actor_id = "http://remote.test/users/bob";
    const remote_inbox = "http://remote.test/users/bob/inbox";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = remote_inbox,
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const follow_id = "http://remote.test/follows/1";
    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, follow_id);
    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=secret&visibility=private",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];

    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;
    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    const followers_url = "http://example.test/users/alice/followers";

    const to_arr = delivered_json.value.object.get("to").?.array.items;
    const cc_arr = delivered_json.value.object.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), to_arr.len);
    try std.testing.expectEqualStrings(followers_url, to_arr[0].string);
    try std.testing.expectEqual(@as(usize, 0), cc_arr.len);

    const obj = delivered_json.value.object.get("object").?.object;
    const obj_to = obj.get("to").?.array.items;
    const obj_cc = obj.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), obj_to.len);
    try std.testing.expectEqualStrings(followers_url, obj_to[0].string);
    try std.testing.expectEqual(@as(usize, 0), obj_cc.len);

    // Defensive: ensure we never include Public in the recipients.
    try std.testing.expect(!std.mem.eql(u8, obj_to[0].string, public_iri));
    if (cc_arr.len > 0) try std.testing.expect(!std.mem.eql(u8, cc_arr[0].string, public_iri));
}

test "DELETE /api/v1/statuses delivers Delete to followers" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const keys = try actor_keys.ensureForUser(&app_state.conn, a, user_id);

    const remote_actor_id = "http://remote.test/users/bob";
    const remote_inbox = "http://remote.test/users/bob/inbox";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = remote_inbox,
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const follow_id = "http://remote.test/follows/1";
    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, follow_id);
    try std.testing.expectEqual(@as(usize, 0), (try followers.listAcceptedRemoteActorIds(&app_state.conn, a, user_id, 10)).len);

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=to-delete&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id_str = create_json.value.object.get("id").?.string;

    try background.runQueued(&app_state, a);

    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));
    try std.testing.expectEqual(@as(usize, 1), (try followers.listAcceptedRemoteActorIds(&app_state.conn, a, user_id, 10)).len);

    const expected_object_id = try std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{s}", .{id_str});
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id_str});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];
    try std.testing.expectEqual(std.http.Method.POST, delivered.method);
    try std.testing.expectEqualStrings(remote_inbox, delivered.url);

    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;
    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();

    try std.testing.expectEqualStrings("Delete", delivered_json.value.object.get("type").?.string);
    const obj = delivered_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings(expected_object_id, obj.get("id").?.string);

    const date = headerValue(delivered.extra_headers, "date") orelse return error.TestUnexpectedResult;
    const digest = headerValue(delivered.extra_headers, "digest") orelse return error.TestUnexpectedResult;
    const signature = headerValue(delivered.extra_headers, "signature") orelse return error.TestUnexpectedResult;

    const expected_digest = try @import("http_signatures.zig").digestHeaderValueAlloc(a, delivered_body);
    try std.testing.expectEqualStrings(expected_digest, digest);

    const signing_string = try @import("http_signatures.zig").signingStringAlloc(a, .POST, "/users/bob/inbox", "remote.test", date, digest);

    const sig_prefix = "signature=\"";
    const sig_b64_i = std.mem.indexOf(u8, signature, sig_prefix) orelse return error.TestUnexpectedResult;
    const sig_b64_start = sig_b64_i + sig_prefix.len;
    const sig_b64_end = std.mem.indexOfPos(u8, signature, sig_b64_start, "\"") orelse return error.TestUnexpectedResult;
    const sig_b64 = signature[sig_b64_start..sig_b64_end];

    const sig_len = std.base64.standard.Decoder.calcSizeForSlice(sig_b64) catch return error.TestUnexpectedResult;
    const sig_bytes = try a.alloc(u8, sig_len);
    std.base64.standard.Decoder.decode(sig_bytes, sig_b64) catch return error.TestUnexpectedResult;

    try std.testing.expect(try @import("crypto_rsa.zig").verifyRsaSha256Pem(keys.public_key_pem, signing_string, sig_bytes));
}

test "DELETE /api/v1/statuses publishes streaming delete" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    const sub = try app_state.streaming.subscribe(user_id, &.{.user});
    defer app_state.streaming.unsubscribe(sub);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const app_creds = try oauth.createApp(&app_state.conn, a, "pl-fe", "urn:ietf:wg:oauth:2.0:oob", "read write", "");
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=bye&visibility=public",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    // Drain the create update.
    const msg_update = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg_update);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id = create_json.value.object.get("id").?.string;

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    const msg_delete = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg_delete);

    var env_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg_delete, .{});
    defer env_json.deinit();

    try std.testing.expectEqualStrings("delete", env_json.value.object.get("event").?.string);
    try std.testing.expectEqualStrings(id, env_json.value.object.get("payload").?.string);
}

test "DELETE /api/v1/statuses visibility=private delivers Delete without Public recipients" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_actor_id = "http://remote.test/users/bob";
    const remote_inbox = "http://remote.test/users/bob/inbox";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = remote_inbox,
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    const follow_id = "http://remote.test/follows/1";
    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, follow_id);
    try std.testing.expectEqual(@as(usize, 0), (try followers.listAcceptedRemoteActorIds(&app_state.conn, a, user_id, 10)).len);

    const app_creds = try oauth.createApp(
        &app_state.conn,
        a,
        "pl-fe",
        "urn:ietf:wg:oauth:2.0:oob",
        "read write",
        "",
    );

    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = "status=to-delete&visibility=private",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, create_resp.status);

    var create_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, create_resp.body, .{});
    defer create_json.deinit();
    const id_str = create_json.value.object.get("id").?.string;

    // No accepted followers yet, so no Create delivery should happen.
    try background.runQueued(&app_state, a);
    try std.testing.expectEqual(@as(usize, 0), mock.requests.items.len);

    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));

    const expected_object_id = try std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{s}", .{id_str});
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{s}", .{id_str});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];
    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;

    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();

    const followers_url = "http://example.test/users/alice/followers";
    const to_arr = delivered_json.value.object.get("to").?.array.items;
    const cc_arr = delivered_json.value.object.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), to_arr.len);
    try std.testing.expectEqualStrings(followers_url, to_arr[0].string);
    try std.testing.expectEqual(@as(usize, 0), cc_arr.len);

    try std.testing.expectEqualStrings("Delete", delivered_json.value.object.get("type").?.string);
    const obj = delivered_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings(expected_object_id, obj.get("id").?.string);
}

test "POST /users/:name/inbox Accept marks follow accepted" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    _ = try follows.createPending(
        &app_state.conn,
        user_id,
        "https://remote.test/users/bob",
        "http://example.test/follows/1",
    );

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Accept\",\"actor\":\"https://remote.test/users/bob\",\"object\":\"http://example.test/follows/1\"}}",
        .{},
    );

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const follow = (try follows.lookupByActivityId(&app_state.conn, a, "http://example.test/follows/1")).?;
    try std.testing.expectEqual(follows.FollowState.accepted, follow.state);
}

test "POST /users/:name/inbox Accept marks follow accepted with trailing slash variant" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    _ = try follows.createPending(
        &app_state.conn,
        user_id,
        "https://remote.test/users/bob",
        "http://example.test/follows/1",
    );

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Accept\",\"actor\":\"https://remote.test/users/bob\",\"object\":\"http://example.test/follows/1/\"}}",
        .{},
    );

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const follow = (try follows.lookupByActivityId(&app_state.conn, a, "http://example.test/follows/1")).?;
    try std.testing.expectEqual(follows.FollowState.accepted, follow.state);
}

test "POST /users/:name/inbox Create discovers actor when addressed" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const actor_id = "https://remote.test/users/bob";

    try mock.pushExpected(.{
        .method = .GET,
        .url = actor_id,
        .response_status = .ok,
        .response_body = "{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://remote.test/users/bob\",\"type\":\"Person\",\"preferredUsername\":\"bob\",\"inbox\":\"https://remote.test/users/bob/inbox\",\"icon\":{\"type\":\"Image\",\"url\":\"https://remote.test/media/avatar.jpg\"},\"image\":{\"type\":\"Image\",\"url\":\"https://remote.test/media/header.jpg\"},\"publicKey\":{\"id\":\"https://remote.test/users/bob#main-key\",\"owner\":\"https://remote.test/users/bob\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n\"}}",
    });

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Create\",\"actor\":\"{s}\",\"to\":[\"http://example.test/users/alice\"],\"object\":{{\"id\":\"https://remote.test/notes/1\",\"type\":\"Note\",\"content\":\"<p>Hello</p>\",\"published\":\"2020-01-01T00:00:00.000Z\"}}}}",
        .{actor_id},
    );

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);

    const actor = (try remote_actors.lookupById(&app_state.conn, a, actor_id)).?;
    try std.testing.expectEqualStrings("https://remote.test/media/avatar.jpg", actor.avatar_url.?);
    try std.testing.expectEqualStrings("https://remote.test/media/header.jpg", actor.header_url.?);
    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")).?;
    try std.testing.expectEqualStrings("direct", st.visibility);
}

test "POST /users/:name/inbox Create discovers actor even when not addressed" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const actor_id = "https://remote.test/users/bob";

    try mock.pushExpected(.{
        .method = .GET,
        .url = actor_id,
        .response_status = .ok,
        .response_body = "{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://remote.test/users/bob\",\"type\":\"Person\",\"preferredUsername\":\"bob\",\"inbox\":\"https://remote.test/users/bob/inbox\",\"publicKey\":{\"id\":\"https://remote.test/users/bob#main-key\",\"owner\":\"https://remote.test/users/bob\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n\"}}",
    });

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Create\",\"actor\":\"{s}\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"object\":{{\"id\":\"https://remote.test/notes/1\",\"type\":\"Note\",\"content\":\"<p>Hello</p>\",\"published\":\"2020-01-01T00:00:00.000Z\"}}}}",
        .{actor_id},
    );

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);

    try std.testing.expect((try remote_actors.lookupById(&app_state.conn, a, actor_id)) != null);
    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")).?;
    try std.testing.expectEqualStrings("public", st.visibility);
}

test "POST /users/:name/inbox Create infers unlisted visibility when Public is in cc" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","to":["https://remote.test/users/bob/followers"],"cc":["https://www.w3.org/ns/activitystreams#Public"],"object":{"id":"https://remote.test/notes/2","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z","to":["https://remote.test/users/bob/followers"],"cc":["https://www.w3.org/ns/activitystreams#Public"]}}
    ;

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/2")).?;
    try std.testing.expectEqualStrings("unlisted", st.visibility);
}

test "POST /users/:name/inbox Create stores remote status" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")).?;
    try std.testing.expect(st.id < 0);
    try std.testing.expectEqualStrings("<p>Hello</p>", st.content_html);
    try std.testing.expectEqualStrings("public", st.visibility);
}

test "POST /users/:name/inbox Delete marks remote status deleted" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const create_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = create_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, create_resp.status);
    try std.testing.expect((try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")) != null);

    const deleted_ts = "2020-01-01T00:00:02.000Z";
    const delete_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Delete","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Tombstone","deleted":"2020-01-01T00:00:02.000Z"}}
    ;

    const delete_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = delete_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, delete_resp.status);

    try std.testing.expect((try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")) == null);
    const st2 = (try remote_statuses.lookupByUriIncludingDeleted(&app_state.conn, a, "https://remote.test/notes/1")).?;
    try std.testing.expectEqualStrings(deleted_ts, st2.deleted_at.?);
}

test "POST /users/:name/inbox Delete publishes streaming delete" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    const sub = try app_state.streaming.subscribe(user_id, &.{.user});
    defer app_state.streaming.unsubscribe(sub);

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const create_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = create_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, create_resp.status);

    // Drain the create update and capture the remote API id.
    const msg_update = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg_update);

    var env_update = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg_update, .{});
    defer env_update.deinit();
    const payload_str = env_update.value.object.get("payload").?.string;

    var payload_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload_str, .{});
    defer payload_json.deinit();
    const remote_id = payload_json.value.object.get("id").?.string;
    try std.testing.expect(std.mem.startsWith(u8, remote_id, "-"));

    const delete_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Delete","actor":"https://remote.test/users/bob","object":"https://remote.test/notes/1"}
    ;

    const delete_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = delete_body,
    });
    try std.testing.expectEqual(std.http.Status.accepted, delete_resp.status);

    const msg_delete = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg_delete);

    var env_delete = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg_delete, .{});
    defer env_delete.deinit();

    try std.testing.expectEqualStrings("delete", env_delete.value.object.get("event").?.string);
    try std.testing.expectEqualStrings(remote_id, env_delete.value.object.get("payload").?.string);
}

fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

fn extractBetween(haystack: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, haystack, start) orelse return null;
    const j = std.mem.indexOfPos(u8, haystack, i + start.len, end) orelse return null;
    return haystack[i + start.len .. j];
}

const std = @import("std");

const app = @import("app.zig");
const actor_keys = @import("actor_keys.zig");
const background = @import("background.zig");
const form = @import("form.zig");
const follows = @import("follows.zig");
const followers = @import("followers.zig");
const inbox_dedupe = @import("inbox_dedupe.zig");
const util_html = @import("util/html.zig");
const util_ids = @import("util/ids.zig");
const media = @import("media.zig");
const notifications = @import("notifications.zig");
const oauth = @import("oauth.zig");
const remote_actors = @import("remote_actors.zig");
const remote_statuses = @import("remote_statuses.zig");
const sessions = @import("sessions.zig");
const statuses = @import("statuses.zig");
const transport = @import("transport.zig");
const users = @import("users.zig");
const http_types = @import("http_types.zig");
const common = @import("http/common.zig");
const discovery = @import("http/discovery.zig");
const instance = @import("http/instance.zig");
const pages = @import("http/pages.zig");
const accounts_api = @import("http/accounts_api.zig");
const oauth_api = @import("http/oauth_api.zig");
const http_urls = @import("http/urls.zig");
const masto = @import("http/mastodon.zig");
const statuses_api = @import("http/statuses_api.zig");
const timelines_api = @import("http/timelines_api.zig");
const activitypub_api = @import("http/activitypub_api.zig");
const media_api = @import("http/media_api.zig");
const notifications_api = @import("http/notifications_api.zig");
const conversations_api = @import("http/conversations_api.zig");
const follows_api = @import("http/follows_api.zig");
const compat_api = @import("http/compat_api.zig");
const metrics_api = @import("http/metrics_api.zig");

const transparent_png = [_]u8{
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0xb5, 0x1c, 0x0c,
    0x02, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xff, 0x1f, 0x00,
    0x03, 0x03, 0x02, 0x00, 0xef, 0xa4, 0xbe, 0x95, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82,
};

pub const Request = http_types.Request;
pub const Response = http_types.Response;

pub fn handle(app_state: *app.App, allocator: std.mem.Allocator, req: Request) Response {
    const path = targetPath(req.target);

    if (req.method == .HEAD) {
        var get_req = req;
        get_req.method = .GET;
        const get_resp = handle(app_state, allocator, get_req);
        return .{
            .status = get_resp.status,
            .content_type = get_resp.content_type,
            .headers = get_resp.headers,
            .body = "",
        };
    }

    if (req.method == .OPTIONS) {
        return .{ .status = .no_content, .body = "" };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/healthz")) {
        return .{ .body = "ok\n" };
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/metrics")) {
        return metrics_api.metricsGet(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/robots.txt")) {
        return .{
            .content_type = "text/plain; charset=utf-8",
            .body = "User-agent: *\nDisallow:\n",
        };
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
        return media_api.mediaFileGet(app_state, allocator, path);
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
        return discovery.webfinger(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/.well-known/host-meta")) {
        return discovery.hostMeta(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/.well-known/nodeinfo")) {
        return discovery.nodeinfoDiscovery(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/nodeinfo/2.0")) {
        return discovery.nodeinfoDocumentWithVersion(app_state, allocator, "2.0");
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/nodeinfo/2.1")) {
        return discovery.nodeinfoDocumentWithVersion(app_state, allocator, "2.1");
    }

    if (std.mem.startsWith(u8, path, "/users/")) {
        if (req.method == .POST and std.mem.endsWith(u8, path, "/inbox")) {
            return activitypub_api.inboxPost(app_state, allocator, req, path);
        }

        if (req.method == .GET) {
            if (std.mem.endsWith(u8, path, "/followers")) return activitypub_api.followersGet(app_state, allocator, path);
            if (std.mem.endsWith(u8, path, "/following")) return activitypub_api.followingGet(app_state, allocator, path);
            if (std.mem.endsWith(u8, path, "/outbox")) return activitypub_api.outboxGet(app_state, allocator, req, path);
            if (std.mem.indexOf(u8, path, "/statuses/") != null) return activitypub_api.userStatusGet(app_state, allocator, path);
            return activitypub_api.actorGet(app_state, allocator, path);
        }
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/instance")) {
        return instance.instanceV1(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/instance/peers")) {
        return instance.instancePeers(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/instance/activity")) {
        return instance.instanceActivity(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/instance/extended_description")) {
        return instance.instanceExtendedDescription(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/directory")) {
        return instance.directory(app_state, allocator);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/instance")) {
        return instance.instanceV2(app_state, allocator);
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

    // --- Client-compat endpoints (Elk/pl-fe) ---
    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/notifications")) {
        return notifications_api.notificationsGet(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/notifications/clear")) {
        return notifications_api.notificationsClear(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/notifications/") and std.mem.endsWith(u8, path, "/dismiss")) {
        return notifications_api.notificationsDismiss(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/conversations")) {
        return conversations_api.conversationsGet(app_state, allocator, req);
    }

    if (req.method == .DELETE and std.mem.startsWith(u8, path, "/api/v1/conversations/")) {
        const rest = path["/api/v1/conversations/".len..];
        if (std.mem.indexOfScalar(u8, rest, '/') == null) {
            return conversations_api.conversationsDelete(app_state, allocator, req, path);
        }
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/conversations/") and std.mem.endsWith(u8, path, "/read")) {
        return conversations_api.conversationsRead(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v2/search")) {
        return accounts_api.apiV2Search(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/apps")) {
        return oauth_api.registerApp(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/signup")) {
        return pages.signupGet(app_state, allocator);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/signup")) {
        return pages.signupPost(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/login")) {
        return pages.loginGet(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/login")) {
        return pages.loginPost(app_state, allocator, req);
    }

    if (std.mem.eql(u8, path, "/oauth/authorize")) {
        if (req.method == .GET) return oauth_api.authorizeGet(app_state, allocator, req);
        if (req.method == .POST) return oauth_api.authorizePost(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/oauth/token")) {
        return oauth_api.token(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/verify_credentials")) {
        return accounts_api.verifyCredentials(app_state, allocator, req);
    }

    if ((req.method == .PATCH or req.method == .POST) and std.mem.eql(u8, path, "/api/v1/accounts/update_credentials")) {
        return accounts_api.updateCredentials(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/lookup")) {
        return accounts_api.lookup(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/accounts/relationships")) {
        return accounts_api.accountRelationships(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/statuses")) {
        return accounts_api.accountStatuses(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/followers")) {
        return accounts_api.accountFollowers(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/following")) {
        return accounts_api.accountFollowing(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/follow")) {
        return accounts_api.accountFollow(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/accounts/") and std.mem.endsWith(u8, path, "/unfollow")) {
        return accounts_api.accountUnfollow(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/accounts/")) {
        const rest = path["/api/v1/accounts/".len..];
        if (std.mem.indexOfScalar(u8, rest, '/') == null) {
            return accounts_api.accountGet(app_state, allocator, path);
        }
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/follows")) {
        return follows_api.followsPost(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/media")) {
        return media_api.createMedia(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v2/media")) {
        return media_api.createMedia(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/media/")) {
        return media_api.getMedia(app_state, allocator, req, path);
    }

    if (req.method == .PUT and std.mem.startsWith(u8, path, "/api/v1/media/")) {
        return media_api.updateMedia(app_state, allocator, req, path);
    }

    if (req.method == .POST and std.mem.eql(u8, path, "/api/v1/statuses")) {
        return statuses_api.createStatus(app_state, allocator, req);
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/favourite")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/favourite");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unfavourite")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/unfavourite");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/reblog")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/reblog");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unreblog")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/unreblog");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/bookmark")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/bookmark");
    }

    if (req.method == .POST and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/unbookmark")) {
        return statuses_api.statusActionNoop(app_state, allocator, req, path, "/unbookmark");
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/public")) {
        return timelines_api.publicTimeline(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.eql(u8, path, "/api/v1/timelines/home")) {
        return timelines_api.homeTimeline(app_state, allocator, req);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/statuses/") and std.mem.endsWith(u8, path, "/context")) {
        return statuses_api.statusContext(app_state, allocator, req, path);
    }

    if (req.method == .GET and std.mem.startsWith(u8, path, "/api/v1/statuses/")) {
        return statuses_api.getStatus(app_state, allocator, req, path);
    }

    if (req.method == .DELETE and std.mem.startsWith(u8, path, "/api/v1/statuses/")) {
        return statuses_api.deleteStatus(app_state, allocator, req, path);
    }

    if (compat_api.maybeHandle(allocator, req, path)) |resp| return resp;

    return .{ .status = .not_found, .body = "not found\n" };
}

fn isPubliclyVisibleVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}
const AccountPayload = masto.AccountPayload;
const MediaAttachmentPayload = masto.MediaAttachmentPayload;
const StatusPayload = masto.StatusPayload;

const remote_actor_id_base: i64 = util_ids.remote_actor_id_base;

fn makeStatusPayload(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) StatusPayload {
    return masto.makeStatusPayload(app_state, allocator, user, st);
}

fn makeRemoteStatusPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) StatusPayload {
    return masto.makeRemoteStatusPayload(app_state, allocator, actor, st);
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
    return util_html.textToHtmlAlloc(allocator, text);
}

fn jsonOk(allocator: std.mem.Allocator, payload: anytype) Response {
    return common.jsonOk(allocator, payload);
}

fn bearerToken(authorization: ?[]const u8) ?[]const u8 {
    return common.bearerToken(authorization);
}

fn unauthorized(allocator: std.mem.Allocator) Response {
    return common.unauthorized(allocator);
}

fn queryString(target: []const u8) []const u8 {
    return common.queryString(target);
}

fn parseQueryParam(allocator: std.mem.Allocator, query: []const u8, name: []const u8) !?[]const u8 {
    return common.parseQueryParam(allocator, query, name);
}

fn percentEncodeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    return common.percentEncodeAlloc(allocator, raw);
}

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

fn isForm(content_type: ?[]const u8) bool {
    return common.isForm(content_type);
}

fn isJson(content_type: ?[]const u8) bool {
    return common.isJson(content_type);
}

fn isMultipart(content_type: ?[]const u8) bool {
    return common.isMultipart(content_type);
}

fn parseBodyParams(allocator: std.mem.Allocator, req: Request) !form.Form {
    return common.parseBodyParams(allocator, req);
}

fn targetPath(target: []const u8) []const u8 {
    const raw = if (std.mem.indexOfScalar(u8, target, '?')) |idx|
        target[0..idx]
    else
        target;

    if (raw.len <= 1) return raw;
    if (raw[raw.len - 1] != '/') return raw;

    var end = raw.len;
    while (end > 1 and raw[end - 1] == '/') {
        end -= 1;
    }
    return raw[0..end];
}

fn signedInboxRequest(
    allocator: std.mem.Allocator,
    host: []const u8,
    target: []const u8,
    body: []const u8,
    key_id: []const u8,
    private_key_pem: []const u8,
) !Request {
    const http_signatures = @import("http_signatures.zig");
    const now_sec: i64 = std.time.timestamp();
    const signed = try http_signatures.signRequest(
        allocator,
        private_key_pem,
        key_id,
        .POST,
        target,
        host,
        body,
        now_sec,
    );
    return .{
        .method = .POST,
        .target = target,
        .content_type = "application/activity+json",
        .body = body,
        .host = host,
        .date = signed.date,
        .digest = signed.digest,
        .signature = signed.signature,
    };
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

test "HEAD / -> 200 and empty body" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{ .method = .HEAD, .target = "/" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expectEqualStrings("", resp.body);
}

test "GET /api/v1/instance/ -> 200" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const resp = handle(&app_state, a, .{ .method = .GET, .target = "/api/v1/instance/" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expect(std.mem.startsWith(u8, resp.content_type, "application/json"));
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
        .{ .method = .GET, .target = "/api/v1/instance/peers", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/instance/activity", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/follow_requests", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/scheduled_statuses", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/lists", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/announcements", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/trends/tags", .kind = .array },
        .{ .method = .GET, .target = "/api/v2/filters", .kind = .array },
        .{ .method = .GET, .target = "/api/v2/suggestions?", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/directory?limit=1", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/followed_tags", .kind = .array },
        .{ .method = .GET, .target = "/api/v1/preferences", .kind = .object },
        .{ .method = .GET, .target = "/api/v1/push/subscription", .kind = .object },
        .{ .method = .GET, .target = "/api/v1/instance/extended_description", .kind = .object, .require_key = "content" },
        .{ .method = .GET, .target = "/api/v2/search?q=https%3A%2F%2Fexample.test%2F&resolve=true&limit=1", .kind = .object, .require_key = "accounts" },
        .{ .method = .GET, .target = "/api/v1/markers?timeline[]=notifications", .kind = .object, .require_key = "notifications" },
        .{ .method = .POST, .target = "/api/v1/markers", .kind = .object, .require_key = "notifications" },
        .{ .method = .GET, .target = "/nodeinfo/2.1", .kind = .object, .require_key = "version" },
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

        if (std.mem.eql(u8, tc.target, "/nodeinfo/2.1")) {
            try std.testing.expectEqualStrings("2.1", parsed.value.object.get("version").?.string);
        }
    }
}

test "GET /robots.txt -> 200 text" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const resp = handle(&app_state, std.testing.allocator, .{ .method = .GET, .target = "/robots.txt" });
    try std.testing.expectEqual(std.http.Status.ok, resp.status);
    try std.testing.expect(std.mem.startsWith(u8, resp.content_type, "text/plain"));
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "User-agent") != null);
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

test "conversations: list/read/delete direct messages" {
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

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const inbox_body1 =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","to":["http://example.test/users/alice"],"content":"<p>DM 1</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const inbox_req1 = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        inbox_body1,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const inbox_resp1 = handle(&app_state, a, inbox_req1);
    try std.testing.expectEqual(std.http.Status.accepted, inbox_resp1.status);

    const list_resp1 = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/conversations",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, list_resp1.status);

    var list_json1 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list_resp1.body, .{});
    defer list_json1.deinit();
    try std.testing.expect(list_json1.value == .array);
    try std.testing.expectEqual(@as(usize, 1), list_json1.value.array.items.len);

    const conv = list_json1.value.array.items[0].object;
    const conv_id = conv.get("id").?.string;
    try std.testing.expect(conv.get("unread").?.bool);

    const accounts = conv.get("accounts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqualStrings("bob@remote.test", accounts[0].object.get("acct").?.string);

    const last_status = conv.get("last_status").?.object;
    try std.testing.expectEqualStrings("<p>DM 1</p>", last_status.get("content").?.string);

    const read_target = try std.fmt.allocPrint(a, "/api/v1/conversations/{s}/read", .{conv_id});
    const read_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = read_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, read_resp.status);

    var read_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, read_resp.body, .{});
    defer read_json.deinit();
    try std.testing.expectEqualStrings(conv_id, read_json.value.object.get("id").?.string);
    try std.testing.expect(!read_json.value.object.get("unread").?.bool);

    const del_target = try std.fmt.allocPrint(a, "/api/v1/conversations/{s}", .{conv_id});
    const del_resp = handle(&app_state, a, .{
        .method = .DELETE,
        .target = del_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, del_resp.status);

    const list_resp2 = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/conversations",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, list_resp2.status);

    var list_json2 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list_resp2.body, .{});
    defer list_json2.deinit();
    try std.testing.expect(list_json2.value == .array);
    try std.testing.expectEqual(@as(usize, 0), list_json2.value.array.items.len);

    const inbox_body2 =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/2","type":"Note","to":["http://example.test/users/alice"],"content":"<p>DM 2</p>","published":"2020-01-01T00:00:01.000Z"}}
    ;

    const inbox_req2 = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        inbox_body2,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const inbox_resp2 = handle(&app_state, a, inbox_req2);
    try std.testing.expectEqual(std.http.Status.accepted, inbox_resp2.status);

    const list_resp3 = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/conversations",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, list_resp3.status);

    var list_json3 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list_resp3.body, .{});
    defer list_json3.deinit();
    try std.testing.expect(list_json3.value == .array);
    try std.testing.expectEqual(@as(usize, 1), list_json3.value.array.items.len);
    try std.testing.expect(list_json3.value.array.items[0].object.get("unread").?.bool);
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
    try std.testing.expectEqualStrings("no-store", headerValue(token_resp.headers, "cache-control").?);
    try std.testing.expectEqualStrings("no-cache", headerValue(token_resp.headers, "pragma").?);

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

test "PATCH /api/v1/accounts/update_credentials updates display_name and note" {
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

    const update_resp = handle(&app_state, a, .{
        .method = .PATCH,
        .target = "/api/v1/accounts/update_credentials",
        .content_type = "application/x-www-form-urlencoded",
        .body = "display_name=Alice&note=Hello",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, update_resp.status);

    var update_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, update_resp.body, .{});
    defer update_json.deinit();
    try std.testing.expectEqualStrings("Alice", update_json.value.object.get("display_name").?.string);
    try std.testing.expectEqualStrings("<p>Hello</p>", update_json.value.object.get("note").?.string);

    const verify_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/accounts/verify_credentials",
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, verify_resp.status);

    var verify_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, verify_resp.body, .{});
    defer verify_json.deinit();
    try std.testing.expectEqualStrings("Alice", verify_json.value.object.get("display_name").?.string);
    try std.testing.expectEqualStrings("<p>Hello</p>", verify_json.value.object.get("note").?.string);
}

test "PATCH /api/v1/accounts/update_credentials accepts avatar and header uploads" {
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
        "Content-Disposition: form-data; name=\"display_name\"\r\n" ++
        "\r\n" ++
        "Alice\r\n" ++
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"note\"\r\n" ++
        "\r\n" ++
        "Hello\r\n" ++
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "AVATAR\r\n" ++
        "--abc\r\n" ++
        "Content-Disposition: form-data; name=\"header\"; filename=\"h.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "HEADER\r\n" ++
        "--abc--\r\n";

    const update_resp = handle(&app_state, a, .{
        .method = .PATCH,
        .target = "/api/v1/accounts/update_credentials",
        .content_type = ct,
        .body = body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, update_resp.status);

    var update_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, update_resp.body, .{});
    defer update_json.deinit();

    const avatar_url = update_json.value.object.get("avatar_static").?.string;
    const header_url = update_json.value.object.get("header_static").?.string;
    try std.testing.expect(std.mem.startsWith(u8, avatar_url, "http://example.test/media/"));
    try std.testing.expect(std.mem.startsWith(u8, header_url, "http://example.test/media/"));

    const avatar_token = avatar_url["http://example.test/media/".len..];
    const header_token = header_url["http://example.test/media/".len..];

    const avatar_target = try std.fmt.allocPrint(a, "/media/{s}", .{avatar_token});
    const header_target = try std.fmt.allocPrint(a, "/media/{s}", .{header_token});

    const avatar_resp = handle(&app_state, a, .{ .method = .GET, .target = avatar_target });
    try std.testing.expectEqual(std.http.Status.ok, avatar_resp.status);
    try std.testing.expectEqualStrings("image/png", avatar_resp.content_type);
    try std.testing.expectEqualStrings("AVATAR", avatar_resp.body);

    const header_resp = handle(&app_state, a, .{ .method = .GET, .target = header_target });
    try std.testing.expectEqual(std.http.Status.ok, header_resp.status);
    try std.testing.expectEqualStrings("image/png", header_resp.content_type);
    try std.testing.expectEqualStrings("HEADER", header_resp.body);
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

    const get_meta_target = try std.fmt.allocPrint(a, "/api/v1/media/{s}", .{media_id});
    const get_meta_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = get_meta_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, get_meta_resp.status);

    var get_meta_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, get_meta_resp.body, .{});
    defer get_meta_json.deinit();
    try std.testing.expectEqualStrings("new", get_meta_json.value.object.get("description").?.string);
}

test "media: /api/v2/media upload works" {
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
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n" ++
        "Content-Type: image/png\r\n" ++
        "\r\n" ++
        "PNGDATA\r\n" ++
        "--abc--\r\n";

    const upload_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v2/media",
        .content_type = ct,
        .body = body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, upload_resp.status);

    var upload_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, upload_resp.body, .{});
    defer upload_json.deinit();

    _ = upload_json.value.object.get("id") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("image", upload_json.value.object.get("type").?.string);
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

test "statuses: create allows empty status when media attached" {
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
        "status=&visibility=public&media_ids[]={d}",
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

    try std.testing.expectEqualStrings("<p></p>", create_json.value.object.get("content").?.string);

    const attachments = create_json.value.object.get("media_attachments").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), attachments.len);
    try std.testing.expect(std.mem.endsWith(u8, attachments[0].object.get("url").?.string, "/media/tok1"));
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

test "statuses: create rejects more than 4 media attachments" {
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

    var ids: [5]i64 = undefined;
    for (ids[0..], 0..) |*out, i| {
        const tok = try std.fmt.allocPrint(a, "tok{d}", .{i});
        const meta = try media.createWithToken(&app_state.conn, a, user_id, tok, "image/png", "DATA", null, 0);
        out.* = meta.id;
    }

    var body_list: std.ArrayList(u8) = .{};
    defer body_list.deinit(a);
    try body_list.appendSlice(a, "status=&visibility=public");
    for (ids) |id| {
        try body_list.writer(a).print("&media_ids[]={d}", .{id});
    }
    const body = try body_list.toOwnedSlice(a);

    const create_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/api/v1/statuses",
        .content_type = "application/x-www-form-urlencoded",
        .body = body,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.unprocessable_entity, create_resp.status);
    try std.testing.expectEqualStrings("too many media\n", create_resp.body);
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

test "timelines: public timeline excludes unlisted/private/direct statuses (local + remote)" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    _ = try statuses.create(&app_state.conn, a, user_id, "Lpub", "public");
    _ = try statuses.create(&app_state.conn, a, user_id, "Lunl", "unlisted");
    _ = try statuses.create(&app_state.conn, a, user_id, "Lpriv", "private");
    _ = try statuses.create(&app_state.conn, a, user_id, "Ldm", "direct");

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    _ = try remote_statuses.createIfNotExists(
        &app_state.conn,
        a,
        "https://remote.test/notes/1",
        "https://remote.test/users/bob",
        "<p>Rpub</p>",
        null,
        "public",
        "2020-01-01T00:00:00.000Z",
    );
    _ = try remote_statuses.createIfNotExists(
        &app_state.conn,
        a,
        "https://remote.test/notes/2",
        "https://remote.test/users/bob",
        "<p>Rdm</p>",
        null,
        "direct",
        "2020-01-01T00:00:01.000Z",
    );

    const tl_resp = handle(&app_state, a, .{
        .method = .GET,
        .target = "/api/v1/timelines/public",
    });
    try std.testing.expectEqual(std.http.Status.ok, tl_resp.status);

    var tl_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, tl_resp.body, .{});
    defer tl_json.deinit();

    try std.testing.expect(tl_json.value == .array);
    try std.testing.expectEqual(@as(usize, 2), tl_json.value.array.items.len);

    var saw_lpub: bool = false;
    var saw_rpub: bool = false;
    for (tl_json.value.array.items) |it| {
        const content = it.object.get("content").?.string;
        if (std.mem.eql(u8, content, "<p>Lpub</p>")) saw_lpub = true;
        if (std.mem.eql(u8, content, "<p>Rpub</p>")) saw_rpub = true;
        try std.testing.expect(!std.mem.eql(u8, content, "<p>Lunl</p>"));
        try std.testing.expect(!std.mem.eql(u8, content, "<p>Lpriv</p>"));
        try std.testing.expect(!std.mem.eql(u8, content, "<p>Ldm</p>"));
        try std.testing.expect(!std.mem.eql(u8, content, "<p>Rdm</p>"));
    }
    try std.testing.expect(saw_lpub);
    try std.testing.expect(saw_rpub);
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

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const inbox_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Remote</p>","published":"2999-01-01T00:00:00.000Z"}}
    ;

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        inbox_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const inbox_resp = handle(&app_state, a, inbox_req);
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

test "POST /api/v1/accounts/:id/unfollow deletes follow and delivers Undo(Follow)" {
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

    const follow_activity_id = "http://example.test/follows/1";
    _ = try follows.createPending(&app_state.conn, user_id, remote_actor_id, follow_activity_id);

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

    const unfollow_target = try std.fmt.allocPrint(a, "/api/v1/accounts/{s}/unfollow", .{account_id_str});
    const unfollow_resp = handle(&app_state, a, .{
        .method = .POST,
        .target = unfollow_target,
        .authorization = auth_header,
    });
    try std.testing.expectEqual(std.http.Status.ok, unfollow_resp.status);

    try std.testing.expect((try follows.lookupByUserAndRemoteActorId(&app_state.conn, a, user_id, remote_actor_id)) == null);

    try background.runQueued(&app_state, a);

    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    const delivered = mock.requests.items[0];
    try std.testing.expectEqual(std.http.Method.POST, delivered.method);
    try std.testing.expectEqualStrings(remote_inbox, delivered.url);

    const delivered_body = delivered.payload orelse return error.TestUnexpectedResult;
    var delivered_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, delivered_body, .{});
    defer delivered_json.deinit();
    try std.testing.expectEqualStrings("Undo", delivered_json.value.object.get("type").?.string);

    const obj = delivered_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings("Follow", obj.get("type").?.string);
    try std.testing.expectEqualStrings(follow_activity_id, obj.get("id").?.string);
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

test "POST /users/:name/inbox rejects overly nested JSON" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const depth: usize = 100;
    var body = try a.alloc(u8, depth * 2);
    for (0..depth) |i| body[i] = '[';
    for (0..depth) |i| body[depth + i] = ']';

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
    });
    try std.testing.expectEqual(std.http.Status.bad_request, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "json too deep") != null);
}

test "POST /users/:name/inbox rejects overly complex JSON" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);
    app_state.cfg.json_max_tokens = 4;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const resp = handle(&app_state, a, .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = "{\"a\":1,\"b\":2,\"c\":3}",
    });
    try std.testing.expectEqual(std.http.Status.bad_request, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "json too many tokens") != null);
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

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);

    const remote_actor_id = "https://remote.test/users/bob";
    const remote_key_id = "https://remote.test/users/bob#main-key";
    const remote_inbox = "https://remote.test/users/bob/inbox";
    const follow_id = "https://remote.test/follows/1";

    const actor_doc_json = try std.json.Stringify.valueAlloc(a, .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = remote_actor_id,
        .type = "Person",
        .preferredUsername = "bob",
        .inbox = remote_inbox,
        .publicKey = .{
            .id = remote_key_id,
            .owner = remote_actor_id,
            .publicKeyPem = remote_kp.public_key_pem,
        },
    }, .{});

    try mock.pushExpected(.{
        .method = .GET,
        .url = remote_actor_id,
        .response_status = .ok,
        .response_body = actor_doc_json,
    });
    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const follow_body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"{s}\",\"type\":\"Follow\",\"actor\":\"{s}\",\"object\":\"http://example.test/users/alice\"}}",
        .{ follow_id, remote_actor_id },
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        follow_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
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

test "POST /users/:name/inbox Undo(Follow) removes follower" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);

    const remote_actor_id = "https://remote.test/users/bob";
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const follow_id = "https://remote.test/follows/1";
    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, follow_id);
    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));

    const undo_body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://remote.test/undo/1\",\"type\":\"Undo\",\"actor\":\"{s}\",\"object\":{{\"id\":\"{s}\",\"type\":\"Follow\",\"actor\":\"{s}\",\"object\":\"http://example.test/users/alice\"}}}}",
        .{ remote_actor_id, follow_id, remote_actor_id },
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        undo_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    try std.testing.expect((try followers.lookupByRemoteActorId(&app_state.conn, a, user_id, remote_actor_id)) == null);
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

test "POST /api/v1/statuses visibility=direct delivers Create to mentioned recipients" {
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
        .body = "status=@bob@remote.test%20hi&visibility=direct",
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

    const to_arr = delivered_json.value.object.get("to").?.array.items;
    const cc_arr = delivered_json.value.object.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), to_arr.len);
    try std.testing.expectEqualStrings(remote_actor_id, to_arr[0].string);
    try std.testing.expectEqual(@as(usize, 0), cc_arr.len);

    const obj = delivered_json.value.object.get("object").?.object;
    const obj_to = obj.get("to").?.array.items;
    const obj_cc = obj.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), obj_to.len);
    try std.testing.expectEqualStrings(remote_actor_id, obj_to[0].string);
    try std.testing.expectEqual(@as(usize, 0), obj_cc.len);
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

test "DELETE /api/v1/statuses visibility=direct delivers Delete to mentioned recipients" {
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

    const st = try statuses.create(&app_state.conn, a, user_id, "@bob@remote.test hi", "direct");

    const app_creds = try oauth.createApp(&app_state.conn, a, "pl-fe", "urn:ietf:wg:oauth:2.0:oob", "read write", "");
    const token = try oauth.createAccessToken(&app_state.conn, a, app_creds.id, user_id, "read write");
    const auth_header = try std.fmt.allocPrint(a, "Bearer {s}", .{token});

    const expected_object_id = try std.fmt.allocPrint(a, "http://example.test/users/alice/statuses/{d}", .{st.id});

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    const del_target = try std.fmt.allocPrint(a, "/api/v1/statuses/{d}", .{st.id});
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

    const to_arr = delivered_json.value.object.get("to").?.array.items;
    const cc_arr = delivered_json.value.object.get("cc").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), to_arr.len);
    try std.testing.expectEqualStrings(remote_actor_id, to_arr[0].string);
    try std.testing.expectEqual(@as(usize, 0), cc_arr.len);

    const obj = delivered_json.value.object.get("object").?.object;
    try std.testing.expectEqualStrings(expected_object_id, obj.get("id").?.string);
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_actor_id = "https://remote.test/users/bob";
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    _ = try follows.createPending(
        &app_state.conn,
        user_id,
        remote_actor_id,
        "http://example.test/follows/1",
    );

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Accept\",\"actor\":\"{s}\",\"object\":\"http://example.test/follows/1\"}}",
        .{remote_actor_id},
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );

    const resp = handle(&app_state, a, inbox_req);
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const follow = (try follows.lookupByActivityId(&app_state.conn, a, "http://example.test/follows/1")).?;
    try std.testing.expectEqual(follows.FollowState.accepted, follow.state);
}

test "POST /users/:name/inbox Accept marks follow accepted with trailing slash variant" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_actor_id = "https://remote.test/users/bob";
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = remote_actor_id,
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    _ = try follows.createPending(
        &app_state.conn,
        user_id,
        remote_actor_id,
        "http://example.test/follows/1",
    );

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Accept\",\"actor\":\"{s}\",\"object\":\"http://example.test/follows/1/\"}}",
        .{remote_actor_id},
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );

    const resp = handle(&app_state, a, inbox_req);
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
    const remote_key_id = "https://remote.test/users/bob#main-key";
    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);

    const actor_doc_json = try std.json.Stringify.valueAlloc(a, .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = actor_id,
        .type = "Person",
        .preferredUsername = "bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .icon = .{ .type = "Image", .url = "https://remote.test/media/avatar.jpg" },
        .image = .{ .type = "Image", .url = "https://remote.test/media/header.jpg" },
        .publicKey = .{
            .id = remote_key_id,
            .owner = actor_id,
            .publicKeyPem = remote_kp.public_key_pem,
        },
    }, .{});

    try mock.pushExpected(.{
        .method = .GET,
        .url = actor_id,
        .response_status = .ok,
        .response_body = actor_doc_json,
    });

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Create\",\"actor\":\"{s}\",\"to\":[\"http://example.test/users/alice\"],\"object\":{{\"id\":\"https://remote.test/notes/1\",\"type\":\"Note\",\"content\":\"<p>Hello</p>\",\"published\":\"2020-01-01T00:00:00.000Z\"}}}}",
        .{actor_id},
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
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
    const remote_key_id = "https://remote.test/users/bob#main-key";
    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);

    const actor_doc_json = try std.json.Stringify.valueAlloc(a, .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = actor_id,
        .type = "Person",
        .preferredUsername = "bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .publicKey = .{
            .id = remote_key_id,
            .owner = actor_id,
            .publicKeyPem = remote_kp.public_key_pem,
        },
    }, .{});

    try mock.pushExpected(.{
        .method = .GET,
        .url = actor_id,
        .response_status = .ok,
        .response_body = actor_doc_json,
    });

    const body = try std.fmt.allocPrint(
        a,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"type\":\"Create\",\"actor\":\"{s}\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"object\":{{\"id\":\"https://remote.test/notes/1\",\"type\":\"Note\",\"content\":\"<p>Hello</p>\",\"published\":\"2020-01-01T00:00:00.000Z\"}}}}",
        .{actor_id},
    );

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","to":["https://remote.test/users/bob/followers"],"cc":["https://www.w3.org/ns/activitystreams#Public"],"object":{"id":"https://remote.test/notes/2","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z","to":["https://remote.test/users/bob/followers"],"cc":["https://www.w3.org/ns/activitystreams#Public"]}}
    ;

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/2")).?;
    try std.testing.expectEqualStrings("unlisted", st.visibility);
}

test "POST /users/:name/inbox Create stores remote status" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const inbox_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp = handle(&app_state, a, inbox_req);
    try std.testing.expectEqual(std.http.Status.accepted, resp.status);

    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")).?;
    try std.testing.expect(st.id < 0);
    try std.testing.expectEqualStrings("<p>Hello</p>", st.content_html);
    try std.testing.expectEqualStrings("public", st.visibility);
}

test "POST /users/:name/inbox Create without activity id is replay-deduped" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    // No top-level ActivityPub `id`, but still a valid Create(Note).
    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/9","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const req1 = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp1 = handle(&app_state, a, req1);
    try std.testing.expectEqual(std.http.Status.accepted, resp1.status);
    try std.testing.expectEqualStrings("ok\n", resp1.body);

    const req2 = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const resp2 = handle(&app_state, a, req2);
    try std.testing.expectEqual(std.http.Status.accepted, resp2.status);
    try std.testing.expectEqualStrings("duplicate\n", resp2.body);
}

test "POST /users/:name/inbox Delete marks remote status deleted" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const create_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const create_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        create_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const create_resp = handle(&app_state, a, create_req);
    try std.testing.expectEqual(std.http.Status.accepted, create_resp.status);
    try std.testing.expect((try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")) != null);

    const deleted_ts = "2020-01-01T00:00:02.000Z";
    const delete_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Delete","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Tombstone","deleted":"2020-01-01T00:00:02.000Z"}}
    ;

    const delete_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        delete_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const delete_resp = handle(&app_state, a, delete_req);
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const create_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z"}}
    ;

    const create_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        create_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const create_resp = handle(&app_state, a, create_req);
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

    const delete_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        delete_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const delete_resp = handle(&app_state, a, delete_req);
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

test "POST /users/:name/inbox Create stores remote attachments and returns them in API payloads" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    const params = app_state.cfg.password_params;
    _ = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const remote_kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const remote_key_id = "https://remote.test/users/bob#main-key";

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = remote_kp.public_key_pem,
    });

    const create_body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","type":"Create","actor":"https://remote.test/users/bob","object":{"id":"https://remote.test/notes/1","type":"Note","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z","attachment":[{"type":"Document","mediaType":"image/png","url":"https://remote.test/media/a.png","name":"alt"}]}}
    ;

    const create_req = try signedInboxRequest(
        a,
        "example.test",
        "/users/alice/inbox",
        create_body,
        remote_key_id,
        remote_kp.private_key_pem,
    );
    const create_resp = handle(&app_state, a, create_req);
    try std.testing.expectEqual(std.http.Status.accepted, create_resp.status);

    const actor = (try remote_actors.lookupById(&app_state.conn, a, "https://remote.test/users/bob")).?;
    const st = (try remote_statuses.lookupByUri(&app_state.conn, a, "https://remote.test/notes/1")).?;

    const status_resp = remoteStatusResponse(&app_state, a, actor, st);
    try std.testing.expectEqual(std.http.Status.ok, status_resp.status);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, status_resp.body, .{});
    defer parsed.deinit();

    const attachments = parsed.value.object.get("media_attachments").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), attachments.len);
    try std.testing.expectEqualStrings("image", attachments[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("https://remote.test/media/a.png", attachments[0].object.get("url").?.string);
    try std.testing.expectEqualStrings("https://remote.test/media/a.png", attachments[0].object.get("preview_url").?.string);
    try std.testing.expectEqualStrings("https://remote.test/media/a.png", attachments[0].object.get("remote_url").?.string);
    try std.testing.expectEqualStrings("alt", attachments[0].object.get("description").?.string);
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

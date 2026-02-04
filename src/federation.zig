const std = @import("std");

const actor_keys = @import("actor_keys.zig");
const app = @import("app.zig");
const config = @import("config.zig");
const html = @import("util/html.zig");
const ids = @import("util/ids.zig");
const follows = @import("follows.zig");
const followers = @import("followers.zig");
const http_signatures = @import("http_signatures.zig");
const http_urls = @import("http/urls.zig");
const log = @import("log.zig");
const notifications = @import("notifications.zig");
const remote_actors = @import("remote_actors.zig");
const statuses = @import("statuses.zig");
const status_recipients = @import("status_recipients.zig");
const transport = @import("transport.zig");
const url = @import("util/url.zig");
const users = @import("users.zig");

pub const Error =
    std.mem.Allocator.Error ||
    transport.Error ||
    std.json.ParseError(std.json.Scanner) ||
    std.Uri.ParseError ||
    actor_keys.Error ||
    follows.Error ||
    followers.Error ||
    remote_actors.Error ||
    users.Error ||
    error{
        InvalidHandle,
        WebfingerNoSelfLink,
        ActorDocMissingFields,
        ActorDocIdMismatch,
        ActorDocInvalidUrl,
        FollowSendFailed,
        RemoteFetchFailed,
        RemoteActorMissing,
    };

pub const FollowResult = struct {
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
};

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

const ParsedHandle = struct {
    username: []const u8,
    host: []const u8,
    port: ?u16,
};

fn parseHandle(handle: []const u8) Error!ParsedHandle {
    const trimmed = std.mem.trim(u8, handle, " \t\r\n");
    const h = if (std.mem.startsWith(u8, trimmed, "@")) trimmed[1..] else trimmed;

    const at = std.mem.indexOfScalar(u8, h, '@') orelse return error.InvalidHandle;
    const username = h[0..at];
    const host_port = h[at + 1 ..];
    if (username.len == 0 or host_port.len == 0) return error.InvalidHandle;

    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon| {
        const host = host_port[0..colon];
        const port_str = host_port[colon + 1 ..];
        if (host.len == 0 or port_str.len == 0) return error.InvalidHandle;
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidHandle;
        return .{ .username = username, .host = host, .port = port };
    }

    return .{ .username = username, .host = host_port, .port = null };
}

fn hostHeaderAlloc(allocator: std.mem.Allocator, host: []const u8, port: ?u16, scheme: config.Scheme) ![]u8 {
    const default_port: u16 = switch (scheme) {
        .http => 80,
        .https => 443,
    };
    if (port == null or port.? == default_port) return allocator.dupe(u8, host);
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port.? });
}

fn baseUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return url.baseUrlAlloc(app_state, allocator);
}

fn defaultAvatarUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return url.defaultAvatarUrlAlloc(app_state, allocator);
}

fn defaultHeaderUrlAlloc(app_state: *app.App, allocator: std.mem.Allocator) ![]u8 {
    return url.defaultHeaderUrlAlloc(app_state, allocator);
}

fn remoteAccountApiIdAlloc(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) []const u8 {
    return ids.remoteAccountApiIdAlloc(app_state, allocator, actor_id);
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

fn requestTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    if (uri.path.isEmpty()) {
        try aw.writer.writeAll("/");
    } else {
        try aw.writer.print("{f}", .{std.fmt.alt(uri.path, .formatPath)});
    }

    if (uri.query) |q| {
        try aw.writer.writeByte('?');
        try aw.writer.print("{f}", .{std.fmt.alt(q, .formatQuery)});
    }

    const out = try aw.toOwnedSlice();
    aw.deinit();
    return out;
}

const SignedDelivery = struct {
    inbox_host_header: []const u8,
    inbox_target: []const u8,
    signed: http_signatures.SignedHeaders,
};

fn signInboxPost(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    private_key_pem: []const u8,
    key_id: []const u8,
    inbox_url: []const u8,
    body: []const u8,
) Error!SignedDelivery {
    const inbox_uri = try std.Uri.parse(inbox_url);
    const inbox_target = try requestTargetAlloc(allocator, inbox_uri);

    const inbox_host_part = inbox_uri.host orelse return error.FollowSendFailed;
    const inbox_host = try inbox_host_part.toRawMaybeAlloc(allocator);
    const inbox_host_header = try hostHeaderAlloc(allocator, inbox_host, inbox_uri.port, app_state.cfg.scheme);

    const signed = try http_signatures.signRequest(
        allocator,
        private_key_pem,
        key_id,
        .POST,
        inbox_target,
        inbox_host_header,
        body,
        std.time.timestamp(),
    );

    return .{
        .inbox_host_header = inbox_host_header,
        .inbox_target = inbox_target,
        .signed = signed,
    };
}

fn fetchSignedInboxPost(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    inbox_url: []const u8,
    inbox_host_header: []const u8,
    signed: http_signatures.SignedHeaders,
    body: []const u8,
) Error!transport.Response {
    const extra_headers = [_]std.http.Header{
        .{ .name = "accept", .value = "application/activity+json" },
        .{ .name = "date", .value = signed.date },
        .{ .name = "digest", .value = signed.digest },
        .{ .name = "signature", .value = signed.signature },
    };

    return try app_state.transport.fetch(allocator, .{
        .url = inbox_url,
        .method = .POST,
        .headers = .{
            .host = .{ .override = inbox_host_header },
            .content_type = .{ .override = "application/activity+json" },
            .accept_encoding = .omit,
            .user_agent = .{ .override = "feddyspice" },
        },
        .extra_headers = &extra_headers,
        .payload = body,
    });
}

fn deliverSignedInboxPostOkDiscardBody(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    private_key_pem: []const u8,
    key_id: []const u8,
    inbox_url: []const u8,
    body: []const u8,
) Error!void {
    const delivery = try signInboxPost(app_state, allocator, private_key_pem, key_id, inbox_url, body);
    const resp = try fetchSignedInboxPost(app_state, allocator, inbox_url, delivery.inbox_host_header, delivery.signed, body);
    allocator.free(resp.body);
    if (resp.status.class() != .success) return error.FollowSendFailed;
}

fn fetchBodySuccessAlloc(app_state: *app.App, allocator: std.mem.Allocator, opts: transport.FetchOptions) Error![]u8 {
    const resp = try app_state.transport.fetch(allocator, opts);
    if (resp.status.class() != .success) {
        allocator.free(resp.body);
        return error.RemoteFetchFailed;
    }
    return resp.body;
}

fn deliveryInboxUrl(actor: remote_actors.RemoteActor) []const u8 {
    return actor.shared_inbox orelse actor.inbox;
}

fn extractWebfingerSelfHref(allocator: std.mem.Allocator, body: []const u8) Error![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.WebfingerNoSelfLink;

    const links_val = parsed.value.object.get("links") orelse return error.WebfingerNoSelfLink;
    if (links_val != .array) return error.WebfingerNoSelfLink;

    for (links_val.array.items) |link| {
        if (link != .object) continue;
        const rel = link.object.get("rel") orelse continue;
        const href = link.object.get("href") orelse continue;
        if (rel == .string and std.mem.eql(u8, rel.string, "self") and href == .string and href.string.len > 0) {
            return allocator.dupe(u8, href.string);
        }
    }

    return error.WebfingerNoSelfLink;
}

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

fn parseActorDoc(
    allocator: std.mem.Allocator,
    body: []const u8,
    expected_domain: []const u8,
    expected_id: []const u8,
) Error!remote_actors.RemoteActor {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.ActorDocMissingFields;

    const id_val = parsed.value.object.get("id") orelse return error.ActorDocMissingFields;
    const inbox_val = parsed.value.object.get("inbox") orelse return error.ActorDocMissingFields;
    const user_val = parsed.value.object.get("preferredUsername") orelse return error.ActorDocMissingFields;
    if (id_val != .string or inbox_val != .string or user_val != .string) return error.ActorDocMissingFields;
    if (!url.isHttpOrHttpsUrl(id_val.string) or !url.isHttpOrHttpsUrl(inbox_val.string)) return error.ActorDocInvalidUrl;
    if (!std.mem.eql(u8, trimTrailingSlash(id_val.string), trimTrailingSlash(expected_id))) return error.ActorDocIdMismatch;

    const pk_val = parsed.value.object.get("publicKey") orelse return error.ActorDocMissingFields;
    if (pk_val != .object) return error.ActorDocMissingFields;
    const pem_val = pk_val.object.get("publicKeyPem") orelse return error.ActorDocMissingFields;
    if (pem_val != .string) return error.ActorDocMissingFields;

    const shared_inbox: ?[]u8 = blk: {
        const endpoints = parsed.value.object.get("endpoints") orelse break :blk null;
        if (endpoints != .object) break :blk null;
        const si = endpoints.object.get("sharedInbox") orelse break :blk null;
        if (si != .string) break :blk null;
        if (!url.isHttpOrHttpsUrl(si.string)) break :blk null;
        break :blk try allocator.dupe(u8, si.string);
    };

    const avatar_url: ?[]u8 = blk: {
        const icon_val = parsed.value.object.get("icon") orelse break :blk null;
        const u = try jsonFirstUrlAlloc(allocator, icon_val) orelse break :blk null;
        if (!url.isHttpOrHttpsUrl(u)) {
            allocator.free(u);
            break :blk null;
        }
        break :blk u;
    };

    const header_url: ?[]u8 = blk: {
        const image_val = parsed.value.object.get("image") orelse break :blk null;
        const u = try jsonFirstUrlAlloc(allocator, image_val) orelse break :blk null;
        if (!url.isHttpOrHttpsUrl(u)) {
            allocator.free(u);
            break :blk null;
        }
        break :blk u;
    };

    return .{
        .id = try allocator.dupe(u8, id_val.string),
        .inbox = try allocator.dupe(u8, inbox_val.string),
        .shared_inbox = shared_inbox,
        .preferred_username = try allocator.dupe(u8, user_val.string),
        .domain = try allocator.dupe(u8, expected_domain),
        .public_key_pem = try allocator.dupe(u8, pem_val.string),
        .avatar_url = avatar_url,
        .header_url = header_url,
    };
}

fn jsonFirstUrlAlloc(allocator: std.mem.Allocator, val: std.json.Value) std.mem.Allocator.Error!?[]u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else try allocator.dupe(u8, s),
        .object => |o| {
            if (o.get("url")) |u| return try jsonFirstUrlAlloc(allocator, u);
            if (o.get("href")) |h| {
                if (h == .string and h.string.len > 0) return try allocator.dupe(u8, h.string);
            }
            return null;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (try jsonFirstUrlAlloc(allocator, item)) |u| return u;
            }
            return null;
        },
        else => return null,
    }
}

pub fn ensureRemoteActorById(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) Error!remote_actors.RemoteActor {
    if (try remote_actors.lookupById(&app_state.conn, allocator, actor_id)) |existing| return existing;

    const actor_uri = try std.Uri.parse(actor_id);
    const host = try actor_uri.host.?.toRawMaybeAlloc(allocator);
    const host_header = try hostHeaderAlloc(allocator, host, actor_uri.port, app_state.cfg.scheme);

    const actor_body = try fetchBodySuccessAlloc(app_state, allocator, .{
        .url = actor_id,
        .method = .GET,
        .headers = .{ .host = .{ .override = host_header }, .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "accept", .value = "application/activity+json" }},
        .payload = null,
    });

    const actor = try parseActorDoc(allocator, actor_body, host, actor_id);
    try remote_actors.upsert(&app_state.conn, actor);
    return actor;
}

fn htmlEscapeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    return html.htmlEscapeAlloc(allocator, raw);
}

fn textToHtmlAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return html.textToHtmlAlloc(allocator, text);
}

fn isMentionUsernameChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '_' or
        c == '-' or
        c == '.';
}

fn isMentionHostChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '-' or
        c == '.' or
        c == ':' or
        c == '_';
}

fn trimTrailingMentionPunct(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0) {
        const c = s[end - 1];
        if (c == '.' or c == ',' or c == ':' or c == ';' or c == '!' or c == '?' or c == ')' or c == ']' or c == '}' or c == '>' or c == '"' or c == '\'') {
            end -= 1;
            continue;
        }
        break;
    }
    return s[0..end];
}

fn hasActorId(actors: []const remote_actors.RemoteActor, actor_id: []const u8) bool {
    for (actors) |a| {
        if (std.mem.eql(u8, a.id, actor_id)) return true;
    }
    return false;
}

fn collectMentionRecipients(app_state: *app.App, allocator: std.mem.Allocator, text: []const u8) Error![]remote_actors.RemoteActor {
    var recipients: std.ArrayListUnmanaged(remote_actors.RemoteActor) = .empty;
    errdefer recipients.deinit(allocator);

    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] != '@') continue;

        var j = i + 1;
        if (j >= text.len) continue;

        const username_start = j;
        while (j < text.len and isMentionUsernameChar(text[j])) : (j += 1) {}
        if (j >= text.len or text[j] != '@') continue;
        const username = text[username_start..j];
        if (username.len == 0) continue;

        j += 1; // skip '@'
        const domain_start = j;
        while (j < text.len and isMentionHostChar(text[j])) : (j += 1) {}
        var domain = trimTrailingMentionPunct(text[domain_start..j]);
        if (domain.len == 0) continue;

        // For DB lookups, ignore an explicit :port.
        const host_only = blk: {
            const colon = std.mem.lastIndexOfScalar(u8, domain, ':') orelse break :blk domain;
            const port_str = domain[colon + 1 ..];
            if (port_str.len == 0) break :blk domain;
            _ = std.fmt.parseInt(u16, port_str, 10) catch break :blk domain;
            const host = domain[0..colon];
            if (host.len == 0) break :blk domain;
            break :blk host;
        };

        const actor_opt: ?remote_actors.RemoteActor = blk: {
            if (remote_actors.lookupByHandle(&app_state.conn, allocator, username, host_only) catch null) |a| break :blk a;
            const handle = std.fmt.allocPrint(allocator, "@{s}@{s}", .{ username, domain }) catch break :blk null;
            break :blk resolveRemoteActorByHandle(app_state, allocator, handle) catch null;
        };

        if (actor_opt) |actor| {
            if (!hasActorId(recipients.items, actor.id)) {
                recipients.append(allocator, actor) catch return error.OutOfMemory;
            }
        }
    }

    return recipients.toOwnedSlice(allocator);
}

fn directRecipientActorIdsAlloc(app_state: *app.App, allocator: std.mem.Allocator, status_id: i64, text: []const u8) Error![][]u8 {
    const existing = status_recipients.listRemoteActorIds(&app_state.conn, allocator, status_id, 50) catch
        return error.RemoteFetchFailed;
    if (existing.len > 0) return existing;

    const recipients = try collectMentionRecipients(app_state, allocator, text);
    if (recipients.len == 0) return try allocator.alloc([]u8, 0);

    for (recipients) |actor| {
        status_recipients.add(&app_state.conn, status_id, actor.id) catch
            return error.RemoteFetchFailed;
    }

    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (out.items) |s| allocator.free(s);
        out.deinit(allocator);
    }

    for (recipients) |actor| {
        try out.append(allocator, try allocator.dupe(u8, actor.id));
    }

    return out.toOwnedSlice(allocator);
}

pub fn resolveRemoteActorByHandle(app_state: *app.App, allocator: std.mem.Allocator, handle: []const u8) Error!remote_actors.RemoteActor {
    const remote = try parseHandle(handle);

    const host_header = try hostHeaderAlloc(allocator, remote.host, remote.port, app_state.cfg.scheme);

    const webfinger_url = std.fmt.allocPrint(
        allocator,
        "{s}://{s}{s}/.well-known/webfinger?resource=acct:{s}@{s}",
        .{
            @tagName(app_state.cfg.scheme),
            remote.host,
            if (remote.port) |p| try std.fmt.allocPrint(allocator, ":{d}", .{p}) else "",
            remote.username,
            remote.host,
        },
    ) catch return error.OutOfMemory;

    const webfinger_body = try fetchBodySuccessAlloc(app_state, allocator, .{
        .url = webfinger_url,
        .method = .GET,
        .headers = .{ .host = .{ .override = host_header }, .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "accept", .value = "application/jrd+json" }},
        .payload = null,
    });

    const actor_id = try extractWebfingerSelfHref(allocator, webfinger_body);

    const actor_uri = try std.Uri.parse(actor_id);
    const actor_host = try actor_uri.host.?.toRawMaybeAlloc(allocator);
    const actor_host_header = try hostHeaderAlloc(allocator, actor_host, actor_uri.port, app_state.cfg.scheme);

    const actor_body = try fetchBodySuccessAlloc(app_state, allocator, .{
        .url = actor_id,
        .method = .GET,
        .headers = .{ .host = .{ .override = actor_host_header }, .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "accept", .value = "application/activity+json" }},
        .payload = null,
    });

    const actor = try parseActorDoc(allocator, actor_body, remote.host, actor_id);
    try remote_actors.upsert(&app_state.conn, actor);
    return actor;
}

test "parseActorDoc validates id and sanitizes optional URLs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body_mismatch =
        \\{"id":"https://evil.test/users/bob","inbox":"https://evil.test/users/bob/inbox","preferredUsername":"bob","publicKey":{"publicKeyPem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}}
    ;
    try std.testing.expectError(error.ActorDocIdMismatch, parseActorDoc(a, body_mismatch, "remote.test", "https://remote.test/users/bob"));

    const body_bad_inbox =
        \\{"id":"https://remote.test/users/bob","inbox":"javascript:alert(1)","preferredUsername":"bob","publicKey":{"publicKeyPem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}}
    ;
    try std.testing.expectError(error.ActorDocInvalidUrl, parseActorDoc(a, body_bad_inbox, "remote.test", "https://remote.test/users/bob"));

    const body_bad_avatar =
        \\{"id":"https://remote.test/users/bob","inbox":"https://remote.test/users/bob/inbox","preferredUsername":"bob","publicKey":{"publicKeyPem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"},"icon":{"url":"javascript:alert(1)"},"image":{"url":"data:text/plain,hi"}}
    ;
    const actor = try parseActorDoc(a, body_bad_avatar, "remote.test", "https://remote.test/users/bob");
    try std.testing.expect(actor.avatar_url == null);
    try std.testing.expect(actor.header_url == null);
}

pub fn sendFollowActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) Error!void {
    const actor = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = follow_activity_id,
        .type = "Follow",
        .actor = local_actor_id,
        .object = actor.id,
    };
    const follow_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const inbox_url = deliveryInboxUrl(actor);
    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    const delivery = try signInboxPost(app_state, allocator, keys.private_key_pem, key_id, inbox_url, follow_body);
    const resp = try fetchSignedInboxPost(app_state, allocator, inbox_url, delivery.inbox_host_header, delivery.signed, follow_body);
    defer allocator.free(resp.body);

    if (resp.status.class() != .success) {
        const snippet = resp.body[0..@min(resp.body.len, 256)];
        app_state.logger.err(
            "sendFollowActivity: inbox={s} status={d} body={f}",
            .{ inbox_url, @intFromEnum(resp.status), log.safe(snippet) },
        );
        return error.FollowSendFailed;
    }
}

pub fn sendUndoFollowActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
) Error!void {
    const actor = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    const undo_id = try std.fmt.allocPrint(allocator, "{s}#undo", .{follow_activity_id});

    const to = [_][]const u8{actor.id};
    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = undo_id,
        .type = "Undo",
        .actor = local_actor_id,
        .to = to[0..],
        .object = .{
            .id = follow_activity_id,
            .type = "Follow",
            .actor = local_actor_id,
            .object = actor.id,
        },
    };
    const undo_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const inbox_url = deliveryInboxUrl(actor);
    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    try deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, undo_body);
}

pub fn sendLikeActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) Error!void {
    const actor = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(remote_status_uri, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const like_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}/likes/{s}", .{ base, local_user.username, hex[0..] });

    const to = [_][]const u8{actor.id};
    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = like_id,
        .type = "Like",
        .actor = local_actor_id,
        .object = remote_status_uri,
        .to = to[0..],
    };
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const inbox_url = deliveryInboxUrl(actor);
    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);
    try deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, body);
}

pub fn sendUndoLikeActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) Error!void {
    const actor = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(remote_status_uri, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const like_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}/likes/{s}", .{ base, local_user.username, hex[0..] });

    const undo_id = try std.fmt.allocPrint(allocator, "{s}#undo", .{like_id});
    const to = [_][]const u8{actor.id};
    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = undo_id,
        .type = "Undo",
        .actor = local_actor_id,
        .to = to[0..],
        .object = .{
            .id = like_id,
            .type = "Like",
            .actor = local_actor_id,
            .object = remote_status_uri,
        },
    };
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const inbox_url = deliveryInboxUrl(actor);
    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);
    try deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, body);
}

pub fn sendAnnounceActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) Error!void {
    const author = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, local_user.username });

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(remote_status_uri, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const announce_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}/announces/{s}", .{ base, local_user.username, hex[0..] });

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";

    const to = [_][]const u8{public_iri};
    const cc = [_][]const u8{ followers_url, author.id };

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = announce_id,
        .type = "Announce",
        .actor = local_actor_id,
        .object = remote_status_uri,
        .to = to[0..],
        .cc = cc[0..],
    };
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user_id, 200);

    var deliver_ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deliver_ids.deinit(allocator);
    for (follower_ids) |id| try deliver_ids.append(allocator, id);
    var has_author: bool = false;
    for (deliver_ids.items) |existing| {
        if (std.mem.eql(u8, existing, author.id)) {
            has_author = true;
            break;
        }
    }
    if (!has_author) try deliver_ids.append(allocator, author.id);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    for (deliver_ids.items) |deliver_actor_id| {
        const actor = if (std.mem.eql(u8, deliver_actor_id, author.id)) author else blk: {
            const a = remote_actors.lookupById(&app_state.conn, allocator, deliver_actor_id) catch null;
            break :blk a orelse continue;
        };
        const inbox_url = deliveryInboxUrl(actor);
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, body) catch |err| {
            app_state.logger.err("sendAnnounceActivity: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

pub fn sendUndoAnnounceActivity(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    remote_actor_id: []const u8,
    remote_status_uri: []const u8,
) Error!void {
    const author = (try remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id)) orelse
        return error.RemoteActorMissing;

    const local_user = (try users.lookupUserById(&app_state.conn, allocator, user_id)) orelse
        return error.InvalidHandle;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, local_user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, local_user.username });

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(remote_status_uri, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const announce_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}/announces/{s}", .{ base, local_user.username, hex[0..] });

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";

    const to = [_][]const u8{public_iri};
    const cc = [_][]const u8{ followers_url, author.id };

    const undo_id = try std.fmt.allocPrint(allocator, "{s}#undo", .{announce_id});
    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = undo_id,
        .type = "Undo",
        .actor = local_actor_id,
        .to = to[0..],
        .cc = cc[0..],
        .object = .{
            .id = announce_id,
            .type = "Announce",
            .actor = local_actor_id,
            .object = remote_status_uri,
            .to = to[0..],
            .cc = cc[0..],
        },
    };
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user_id, 200);

    var deliver_ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deliver_ids.deinit(allocator);
    for (follower_ids) |id| try deliver_ids.append(allocator, id);
    var has_author: bool = false;
    for (deliver_ids.items) |existing| {
        if (std.mem.eql(u8, existing, author.id)) {
            has_author = true;
            break;
        }
    }
    if (!has_author) try deliver_ids.append(allocator, author.id);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    for (deliver_ids.items) |deliver_actor_id| {
        const actor = if (std.mem.eql(u8, deliver_actor_id, author.id)) author else blk: {
            const a = remote_actors.lookupById(&app_state.conn, allocator, deliver_actor_id) catch null;
            break :blk a orelse continue;
        };
        const inbox_url = deliveryInboxUrl(actor);
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, body) catch |err| {
            app_state.logger.err("sendUndoAnnounceActivity: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

pub fn followHandle(app_state: *app.App, allocator: std.mem.Allocator, user_id: i64, handle: []const u8) Error!FollowResult {
    const actor = try resolveRemoteActorByHandle(app_state, allocator, handle);

    const base = try baseUrlAlloc(app_state, allocator);

    var id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const follow_activity_id = try std.fmt.allocPrint(allocator, "{s}/follows/{s}", .{ base, id_hex[0..] });

    _ = try follows.createPending(&app_state.conn, user_id, actor.id, follow_activity_id);
    try sendFollowActivity(app_state, allocator, user_id, actor.id, follow_activity_id);

    return .{
        .remote_actor_id = actor.id,
        .follow_activity_id = follow_activity_id,
    };
}

pub fn acceptInboundFollow(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    username: []const u8,
    remote_actor_id: []const u8,
    remote_follow_activity_id: []const u8,
) Error!void {
    const actor = try ensureRemoteActorById(app_state, allocator, remote_actor_id);

    try followers.upsertPending(&app_state.conn, user_id, actor.id, remote_follow_activity_id);

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    var id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const accept_activity_id = try std.fmt.allocPrint(allocator, "{s}/accepts/{s}", .{ base, id_hex[0..] });

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = accept_activity_id,
        .type = "Accept",
        .actor = local_actor_id,
        .object = .{
            .id = remote_follow_activity_id,
            .type = "Follow",
            .actor = actor.id,
            .object = local_actor_id,
        },
    };
    const accept_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const inbox_url = deliveryInboxUrl(actor);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    try deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, accept_body);

    _ = try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, actor.id);
    const notif_id = try notifications.create(&app_state.conn, user_id, "follow", actor.id, null);

    const NotificationPayload = struct {
        id: []const u8,
        type: []const u8,
        created_at: []const u8,
        account: AccountPayload,
        status: ?struct {} = null,
    };

    const rows = notifications.list(&app_state.conn, allocator, user_id, 1, notif_id + 1) catch &.{};
    const created_at = if (rows.len > 0) rows[0].created_at else "1970-01-01T00:00:00.000Z";

    const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);
    const acct = makeRemoteAccountPayload(app_state, allocator, api_id, actor);

    const notif_id_str = std.fmt.allocPrint(allocator, "{d}", .{notif_id}) catch "0";
    const notif_json = std.json.Stringify.valueAlloc(
        allocator,
        NotificationPayload{
            .id = notif_id_str,
            .type = "follow",
            .created_at = created_at,
            .account = acct,
        },
        .{},
    ) catch return error.OutOfMemory;

    app_state.streaming.publishNotification(user_id, notif_json);
}

pub fn deliverStatusToFollowers(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    if (std.mem.eql(u8, st.visibility, "direct")) {
        try deliverDirectStatus(app_state, allocator, user, st);
        return;
    }

    app_state.logger.debug("deliverStatusToFollowers: user_id={d}", .{user.id});
    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    const mentioned_ids = try directRecipientActorIdsAlloc(app_state, allocator, st.id, st.text);

    app_state.logger.debug(
        "deliverStatusToFollowers: followers={d} mentioned={d}",
        .{ follower_ids.len, mentioned_ids.len },
    );
    if (follower_ids.len == 0 and mentioned_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, user.username });

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const create_id = try std.fmt.allocPrint(allocator, "{s}#create", .{status_url});

    const content_html = try textToHtmlAlloc(allocator, st.text);

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";

    var to_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer to_list.deinit(allocator);
    var cc_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer cc_list.deinit(allocator);

    if (std.mem.eql(u8, st.visibility, "public")) {
        try to_list.append(allocator, public_iri);
        try cc_list.append(allocator, followers_url);
    } else if (std.mem.eql(u8, st.visibility, "unlisted")) {
        try to_list.append(allocator, followers_url);
        try cc_list.append(allocator, public_iri);
    } else if (std.mem.eql(u8, st.visibility, "private")) {
        try to_list.append(allocator, followers_url);
    } else {
        app_state.logger.info("deliverStatusToFollowers: skipping visibility={s}", .{st.visibility});
        return;
    }

    for (mentioned_ids) |actor_id| {
        var already: bool = false;
        for (to_list.items) |existing| {
            if (std.mem.eql(u8, existing, actor_id)) {
                already = true;
                break;
            }
        }
        if (!already) try to_list.append(allocator, actor_id);
    }

    var deliver_ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deliver_ids.deinit(allocator);
    for (follower_ids) |id| try deliver_ids.append(allocator, id);
    for (mentioned_ids) |id| {
        var already: bool = false;
        for (deliver_ids.items) |existing| {
            if (std.mem.eql(u8, existing, id)) {
                already = true;
                break;
            }
        }
        if (!already) try deliver_ids.append(allocator, id);
    }

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = create_id,
        .type = "Create",
        .actor = local_actor_id,
        .published = st.created_at,
        .to = to_list.items,
        .cc = cc_list.items,
        .object = .{
            .id = status_url,
            .type = "Note",
            .attributedTo = local_actor_id,
            .content = content_html,
            .published = st.created_at,
            .to = to_list.items,
            .cc = cc_list.items,
        },
    };

    const create_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    for (deliver_ids.items) |remote_actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: lookup remote actor failed actor_id={s} err={any}", .{ remote_actor_id, err });
            continue;
        };
        if (actor == null) {
            app_state.logger.err("deliverStatusToFollowers: remote actor missing actor_id={s}", .{remote_actor_id});
            continue;
        }

        const inbox_url = deliveryInboxUrl(actor.?);
        app_state.logger.debug("deliverStatusToFollowers: inbox={s}", .{inbox_url});
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, create_body) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

pub fn deliverActorUpdate(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) Error!void {
    app_state.logger.debug("deliverActorUpdate: user_id={d}", .{user.id});

    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    const following_ids = try follows.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    if (follower_ids.len == 0 and following_ids.len == 0) return;

    var deliver_ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deliver_ids.deinit(allocator);
    for (follower_ids) |id| try deliver_ids.append(allocator, id);
    for (following_ids) |id| {
        var already: bool = false;
        for (deliver_ids.items) |existing| {
            if (std.mem.eql(u8, existing, id)) {
                already = true;
                break;
            }
        }
        if (!already) try deliver_ids.append(allocator, id);
    }

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    const inbox = try std.fmt.allocPrint(allocator, "{s}/users/{s}/inbox", .{ base, user.username });
    const outbox = try std.fmt.allocPrint(allocator, "{s}/users/{s}/outbox", .{ base, user.username });
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, user.username });
    const following_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/following", .{ base, user.username });

    const update_id = try std.fmt.allocPrint(allocator, "{s}#updates/{d}", .{ local_actor_id, std.time.timestamp() });

    const avatar_url = http_urls.userAvatarUrlAlloc(app_state, allocator, user);
    const header_url = http_urls.userHeaderUrlAlloc(app_state, allocator, user);
    const note_html = try textToHtmlAlloc(allocator, user.note);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    const to = [_][]const u8{ public_iri, followers_url };

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = update_id,
        .type = "Update",
        .actor = local_actor_id,
        .to = to[0..],
        .object = .{
            .id = local_actor_id,
            .type = "Person",
            .name = user.display_name,
            .preferredUsername = user.username,
            .summary = note_html,
            .icon = .{ .type = "Image", .url = avatar_url },
            .image = .{ .type = "Image", .url = header_url },
            .inbox = inbox,
            .outbox = outbox,
            .followers = followers_url,
            .following = following_url,
            .publicKey = .{
                .id = key_id,
                .owner = local_actor_id,
                .publicKeyPem = keys.public_key_pem,
            },
        },
    };

    const update_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    for (deliver_ids.items) |remote_actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id) catch |err| {
            app_state.logger.err("deliverActorUpdate: lookup remote actor failed actor_id={s} err={any}", .{ remote_actor_id, err });
            continue;
        };
        if (actor == null) {
            app_state.logger.err("deliverActorUpdate: remote actor missing actor_id={s}", .{remote_actor_id});
            continue;
        }

        const inbox_url = deliveryInboxUrl(actor.?);
        app_state.logger.debug("deliverActorUpdate: inbox={s}", .{inbox_url});
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, update_body) catch |err| {
            app_state.logger.err("deliverActorUpdate: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

fn deliverDirectStatus(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    const recipient_ids = try directRecipientActorIdsAlloc(app_state, allocator, st.id, st.text);
    if (recipient_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const create_id = try std.fmt.allocPrint(allocator, "{s}#create", .{status_url});

    const content_html = try textToHtmlAlloc(allocator, st.text);

    const to = try allocator.alloc([]const u8, recipient_ids.len);
    for (recipient_ids, 0..) |actor_id, idx| {
        to[idx] = actor_id;
    }
    const cc: []const []const u8 = &.{};

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = create_id,
        .type = "Create",
        .actor = local_actor_id,
        .published = st.created_at,
        .to = to,
        .cc = cc,
        .object = .{
            .id = status_url,
            .type = "Note",
            .attributedTo = local_actor_id,
            .content = content_html,
            .published = st.created_at,
            .to = to,
            .cc = cc,
        },
    };

    const create_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    for (recipient_ids) |actor_id| {
        const actor = (remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch null) orelse
            (ensureRemoteActorById(app_state, allocator, actor_id) catch null) orelse
            continue;
        const inbox_url = deliveryInboxUrl(actor);
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, create_body) catch |err| {
            app_state.logger.err("deliverDirectStatus: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

pub fn deliverDeleteToFollowers(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    if (st.deleted_at == null) return;

    if (std.mem.eql(u8, st.visibility, "direct")) {
        try deliverDirectDelete(app_state, allocator, user, st);
        return;
    }

    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    const mentioned_ids = try directRecipientActorIdsAlloc(app_state, allocator, st.id, st.text);
    if (follower_ids.len == 0 and mentioned_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, user.username });

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const delete_id = try std.fmt.allocPrint(allocator, "{s}#delete", .{status_url});

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";

    var to_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer to_list.deinit(allocator);
    var cc_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer cc_list.deinit(allocator);

    if (std.mem.eql(u8, st.visibility, "public")) {
        try to_list.append(allocator, public_iri);
        try cc_list.append(allocator, followers_url);
    } else if (std.mem.eql(u8, st.visibility, "unlisted")) {
        try to_list.append(allocator, followers_url);
        try cc_list.append(allocator, public_iri);
    } else if (std.mem.eql(u8, st.visibility, "private")) {
        try to_list.append(allocator, followers_url);
    } else {
        app_state.logger.info("deliverDeleteToFollowers: skipping visibility={s}", .{st.visibility});
        return;
    }

    for (mentioned_ids) |actor_id| {
        var already: bool = false;
        for (to_list.items) |existing| {
            if (std.mem.eql(u8, existing, actor_id)) {
                already = true;
                break;
            }
        }
        if (!already) try to_list.append(allocator, actor_id);
    }

    var deliver_ids: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deliver_ids.deinit(allocator);
    for (follower_ids) |id| try deliver_ids.append(allocator, id);
    for (mentioned_ids) |id| {
        var already: bool = false;
        for (deliver_ids.items) |existing| {
            if (std.mem.eql(u8, existing, id)) {
                already = true;
                break;
            }
        }
        if (!already) try deliver_ids.append(allocator, id);
    }

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = delete_id,
        .type = "Delete",
        .actor = local_actor_id,
        .to = to_list.items,
        .cc = cc_list.items,
        .object = .{
            .id = status_url,
            .type = "Tombstone",
            .formerType = "Note",
            .deleted = st.deleted_at.?,
        },
    };

    const delete_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    for (deliver_ids.items) |remote_actor_id| {
        const actor = remote_actors.lookupById(&app_state.conn, allocator, remote_actor_id) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: lookup remote actor failed actor_id={s} err={any}", .{ remote_actor_id, err });
            continue;
        };
        if (actor == null) {
            app_state.logger.err("deliverDeleteToFollowers: remote actor missing actor_id={s}", .{remote_actor_id});
            continue;
        }

        const inbox_url = deliveryInboxUrl(actor.?);
        app_state.logger.debug("deliverDeleteToFollowers: inbox={s}", .{inbox_url});
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, delete_body) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

fn deliverDirectDelete(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    if (st.deleted_at == null) return;

    const recipient_ids = try directRecipientActorIdsAlloc(app_state, allocator, st.id, st.text);
    if (recipient_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const delete_id = try std.fmt.allocPrint(allocator, "{s}#delete", .{status_url});

    const to = try allocator.alloc([]const u8, recipient_ids.len);
    for (recipient_ids, 0..) |actor_id, idx| {
        to[idx] = actor_id;
    }
    const cc: []const []const u8 = &.{};

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = delete_id,
        .type = "Delete",
        .actor = local_actor_id,
        .to = to,
        .cc = cc,
        .object = .{
            .id = status_url,
            .type = "Tombstone",
            .formerType = "Note",
            .deleted = st.deleted_at.?,
        },
    };

    const delete_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    for (recipient_ids) |actor_id| {
        const actor = (remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch null) orelse
            (ensureRemoteActorById(app_state, allocator, actor_id) catch null) orelse
            continue;
        const inbox_url = deliveryInboxUrl(actor);
        deliverSignedInboxPostOkDiscardBody(app_state, allocator, keys.private_key_pem, key_id, inbox_url, delete_body) catch |err| {
            app_state.logger.err("deliverDirectDelete: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

test "deliverStatusToFollowers direct uses stored recipients without resolving handles" {
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

    const user = (try users.lookupUserById(&app_state.conn, a, user_id)).?;
    const st = try statuses.create(&app_state.conn, a, user_id, "hello @bob@remote.test", "direct", null);
    try status_recipients.add(&app_state.conn, st.id, remote_actor_id);

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    try deliverStatusToFollowers(&app_state, a, user, st);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);
    try std.testing.expectEqual(std.http.Method.POST, mock.requests.items[0].method);
    try std.testing.expectEqualStrings(remote_inbox, mock.requests.items[0].url);
}

fn jsonArrayHasString(val: std.json.Value, needle: []const u8) bool {
    if (val != .array) return false;
    for (val.array.items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, needle)) return true;
    }
    return false;
}

test "deliverStatusToFollowers includes stored recipients for non-direct statuses" {
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

    const user = (try users.lookupUserById(&app_state.conn, a, user_id)).?;
    const st = try statuses.create(&app_state.conn, a, user_id, "hello", "private", null);
    try status_recipients.add(&app_state.conn, st.id, remote_actor_id);

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    try deliverStatusToFollowers(&app_state, a, user, st);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);

    const payload_bytes = mock.requests.items[0].payload.?;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, payload_bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("Create", parsed.value.object.get("type").?.string);

    const base = try baseUrlAlloc(&app_state, a);
    const followers_url = try std.fmt.allocPrint(a, "{s}/users/{s}/followers", .{ base, user.username });

    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("to").?, followers_url));
    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("to").?, remote_actor_id));
    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("object").?.object.get("to").?, remote_actor_id));
}

test "deliverDeleteToFollowers includes stored recipients for non-direct statuses" {
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

    const user = (try users.lookupUserById(&app_state.conn, a, user_id)).?;
    const created = try statuses.create(&app_state.conn, a, user_id, "hello", "private", null);
    try status_recipients.add(&app_state.conn, created.id, remote_actor_id);
    try std.testing.expect(try statuses.markDeleted(&app_state.conn, created.id, user_id));
    const st = (try statuses.lookupIncludingDeleted(&app_state.conn, a, created.id)).?;

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    try deliverDeleteToFollowers(&app_state, a, user, st);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);

    const payload_bytes = mock.requests.items[0].payload.?;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, payload_bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("Delete", parsed.value.object.get("type").?.string);
    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("to").?, remote_actor_id));
}

test "deliverActorUpdate delivers Update with avatar and header to follower inbox" {
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

    try followers.upsertPending(&app_state.conn, user_id, remote_actor_id, "http://remote.test/follows/1");
    try std.testing.expect(try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, remote_actor_id));

    const media = @import("media.zig");
    const now_ms: i64 = 1_000_000;
    var avatar_meta = try media.create(&app_state.conn, a, user_id, "image/png", "AVATAR", null, now_ms);
    defer avatar_meta.deinit(a);
    var header_meta = try media.create(&app_state.conn, a, user_id, "image/png", "HEADER", null, now_ms);
    defer header_meta.deinit(a);

    try std.testing.expect(try users.updateProfile(&app_state.conn, user_id, "Alice", "Hello", avatar_meta.id, header_meta.id));

    const user = (try users.lookupUserById(&app_state.conn, a, user_id)).?;

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    try deliverActorUpdate(&app_state, a, user);
    try std.testing.expectEqual(@as(usize, 1), mock.requests.items.len);

    const payload_bytes = mock.requests.items[0].payload.?;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, payload_bytes, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("Update", parsed.value.object.get("type").?.string);

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("to").?, public_iri));

    const base = try baseUrlAlloc(&app_state, a);
    const followers_url = try std.fmt.allocPrint(a, "{s}/users/{s}/followers", .{ base, user.username });
    try std.testing.expect(jsonArrayHasString(parsed.value.object.get("to").?, followers_url));

    const object = parsed.value.object.get("object").?.object;
    const icon_url = object.get("icon").?.object.get("url").?.string;
    const image_url = object.get("image").?.object.get("url").?.string;

    try std.testing.expect(std.mem.startsWith(u8, icon_url, "http://example.test/media/"));
    try std.testing.expect(std.mem.startsWith(u8, image_url, "http://example.test/media/"));
}

test "followHandle sends signed Follow to remote inbox" {
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

    const actor_id = "http://remote.test/users/bob";
    const inbox_url = "http://remote.test/users/bob/inbox";

    try mock.pushExpected(.{
        .method = .GET,
        .url = "http://remote.test/.well-known/webfinger?resource=acct:bob@remote.test",
        .response_status = .ok,
        .response_body = "{\"subject\":\"acct:bob@remote.test\",\"links\":[{\"rel\":\"self\",\"type\":\"application/activity+json\",\"href\":\"http://remote.test/users/bob\"}]}",
    });

    try mock.pushExpected(.{
        .method = .GET,
        .url = actor_id,
        .response_status = .ok,
        .response_body = "{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"http://remote.test/users/bob\",\"type\":\"Person\",\"preferredUsername\":\"bob\",\"inbox\":\"http://remote.test/users/bob/inbox\",\"publicKey\":{\"id\":\"http://remote.test/users/bob#main-key\",\"owner\":\"http://remote.test/users/bob\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n\"}}",
    });

    try mock.pushExpected(.{
        .method = .POST,
        .url = inbox_url,
        .response_status = .accepted,
        .response_body = "",
    });

    _ = try followHandle(&app_state, a, user_id, "@bob@remote.test");

    try std.testing.expectEqual(@as(usize, 3), mock.requests.items.len);

    const req = mock.requests.items[2];
    try std.testing.expectEqual(std.http.Method.POST, req.method);
    try std.testing.expectEqualStrings(inbox_url, req.url);

    const body = req.payload orelse return error.TestUnexpectedResult;

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("Follow", parsed.value.object.get("type").?.string);
    try std.testing.expectEqualStrings("http://example.test/users/alice", parsed.value.object.get("actor").?.string);
    try std.testing.expectEqualStrings(actor_id, parsed.value.object.get("object").?.string);
    try std.testing.expect(std.mem.startsWith(u8, parsed.value.object.get("id").?.string, "http://example.test/follows/"));

    const date = headerValue(req.extra_headers, "date") orelse return error.TestUnexpectedResult;
    const digest = headerValue(req.extra_headers, "digest") orelse return error.TestUnexpectedResult;
    const signature = headerValue(req.extra_headers, "signature") orelse return error.TestUnexpectedResult;

    const expected_digest = try http_signatures.digestHeaderValueAlloc(a, body);
    try std.testing.expectEqualStrings(expected_digest, digest);

    const signing_string = try http_signatures.signingStringAlloc(a, .POST, "/users/bob/inbox", "remote.test", date, digest);

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

test "acceptInboundFollow publishes streaming follow notification" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var mock = transport.MockTransport.init(std.testing.allocator);
    app_state.transport = mock.transport();

    const params = app_state.cfg.password_params;
    const user_id = try users.create(&app_state.conn, std.testing.allocator, "alice", "password", params);

    const sub = try app_state.streaming.subscribe(user_id, &.{.user});
    defer app_state.streaming.unsubscribe(sub);

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

    try mock.pushExpected(.{ .method = .POST, .url = remote_inbox, .response_status = .accepted, .response_body = "" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try acceptInboundFollow(&app_state, a, user_id, "alice", remote_actor_id, "http://remote.test/follows/1");

    const msg = sub.pop() orelse {
        try std.testing.expect(false);
        return;
    };
    defer app_state.streaming.allocator.free(msg);

    var env_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg, .{});
    defer env_json.deinit();
    try std.testing.expectEqualStrings("notification", env_json.value.object.get("event").?.string);

    const payload_str = env_json.value.object.get("payload").?.string;
    var payload_json = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload_str, .{});
    defer payload_json.deinit();

    try std.testing.expectEqualStrings("follow", payload_json.value.object.get("type").?.string);
    try std.testing.expectEqualStrings("bob", payload_json.value.object.get("account").?.object.get("username").?.string);
}

fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

test "signInboxPost includes query in request-target" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try @import("crypto_rsa.zig").generateRsaKeyPairPem(a, 512);
    const body = "{\"hello\":\"world\"}";
    const key_id = "http://example.test/users/alice#main-key";

    const delivery = try signInboxPost(
        &app_state,
        a,
        kp.private_key_pem,
        key_id,
        "http://remote.test:8080/inbox?x=1",
        body,
    );

    try std.testing.expectEqualStrings("/inbox?x=1", delivery.inbox_target);

    const signing_string = try http_signatures.signingStringAlloc(a, .POST, delivery.inbox_target, "remote.test:8080", delivery.signed.date, delivery.signed.digest);

    const sig_prefix = "signature=\"";
    const sig_b64_i = std.mem.indexOf(u8, delivery.signed.signature, sig_prefix) orelse return error.TestUnexpectedResult;
    const sig_b64_start = sig_b64_i + sig_prefix.len;
    const sig_b64_end = std.mem.indexOfPos(u8, delivery.signed.signature, sig_b64_start, "\"") orelse return error.TestUnexpectedResult;
    const sig_b64 = delivery.signed.signature[sig_b64_start..sig_b64_end];

    const sig_len = std.base64.standard.Decoder.calcSizeForSlice(sig_b64) catch return error.TestUnexpectedResult;
    const sig_bytes = try a.alloc(u8, sig_len);
    std.base64.standard.Decoder.decode(sig_bytes, sig_b64) catch return error.TestUnexpectedResult;

    try std.testing.expect(try @import("crypto_rsa.zig").verifyRsaSha256Pem(kp.public_key_pem, signing_string, sig_bytes));
}

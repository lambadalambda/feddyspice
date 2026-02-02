const std = @import("std");

const actor_keys = @import("actor_keys.zig");
const app = @import("app.zig");
const config = @import("config.zig");
const follows = @import("follows.zig");
const followers = @import("followers.zig");
const http_signatures = @import("http_signatures.zig");
const remote_actors = @import("remote_actors.zig");
const statuses = @import("statuses.zig");
const transport = @import("transport.zig");
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
        FollowSendFailed,
        RemoteFetchFailed,
        RemoteActorMissing,
    };

pub const FollowResult = struct {
    remote_actor_id: []const u8,
    follow_activity_id: []const u8,
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

fn schemeString(s: config.Scheme) []const u8 {
    return @tagName(s);
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
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{ schemeString(app_state.cfg.scheme), app_state.cfg.domain });
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

fn fetchBodySuccessAlloc(app_state: *app.App, allocator: std.mem.Allocator, opts: transport.FetchOptions) Error![]u8 {
    const resp = try app_state.transport.fetch(allocator, opts);
    if (resp.status.class() != .success) {
        allocator.free(resp.body);
        return error.RemoteFetchFailed;
    }
    return resp.body;
}

fn fetchOkDiscardBody(app_state: *app.App, allocator: std.mem.Allocator, opts: transport.FetchOptions) Error!void {
    const resp = try app_state.transport.fetch(allocator, opts);
    allocator.free(resp.body);
    if (resp.status.class() != .success) return error.FollowSendFailed;
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

fn parseActorDoc(allocator: std.mem.Allocator, body: []const u8, expected_domain: []const u8) Error!remote_actors.RemoteActor {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.ActorDocMissingFields;

    const id_val = parsed.value.object.get("id") orelse return error.ActorDocMissingFields;
    const inbox_val = parsed.value.object.get("inbox") orelse return error.ActorDocMissingFields;
    const user_val = parsed.value.object.get("preferredUsername") orelse return error.ActorDocMissingFields;
    if (id_val != .string or inbox_val != .string or user_val != .string) return error.ActorDocMissingFields;

    const pk_val = parsed.value.object.get("publicKey") orelse return error.ActorDocMissingFields;
    if (pk_val != .object) return error.ActorDocMissingFields;
    const pem_val = pk_val.object.get("publicKeyPem") orelse return error.ActorDocMissingFields;
    if (pem_val != .string) return error.ActorDocMissingFields;

    const shared_inbox: ?[]u8 = blk: {
        const endpoints = parsed.value.object.get("endpoints") orelse break :blk null;
        if (endpoints != .object) break :blk null;
        const si = endpoints.object.get("sharedInbox") orelse break :blk null;
        if (si != .string) break :blk null;
        break :blk try allocator.dupe(u8, si.string);
    };

    return .{
        .id = try allocator.dupe(u8, id_val.string),
        .inbox = try allocator.dupe(u8, inbox_val.string),
        .shared_inbox = shared_inbox,
        .preferred_username = try allocator.dupe(u8, user_val.string),
        .domain = try allocator.dupe(u8, expected_domain),
        .public_key_pem = try allocator.dupe(u8, pem_val.string),
    };
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

    const actor = try parseActorDoc(allocator, actor_body, host);
    try remote_actors.upsert(&app_state.conn, actor);
    return actor;
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

fn textToHtmlAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const escaped = try htmlEscapeAlloc(allocator, text);
    return std.fmt.allocPrint(allocator, "<p>{s}</p>", .{escaped});
}

pub fn resolveRemoteActorByHandle(app_state: *app.App, allocator: std.mem.Allocator, handle: []const u8) Error!remote_actors.RemoteActor {
    const remote = try parseHandle(handle);

    const host_header = try hostHeaderAlloc(allocator, remote.host, remote.port, app_state.cfg.scheme);

    const webfinger_url = std.fmt.allocPrint(
        allocator,
        "{s}://{s}{s}/.well-known/webfinger?resource=acct:{s}@{s}",
        .{
            schemeString(app_state.cfg.scheme),
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

    const actor = try parseActorDoc(allocator, actor_body, remote.host);
    try remote_actors.upsert(&app_state.conn, actor);
    return actor;
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
    const inbox_uri = try std.Uri.parse(inbox_url);
    const inbox_target = try requestTargetAlloc(allocator, inbox_uri);

    const inbox_host = try inbox_uri.host.?.toRawMaybeAlloc(allocator);
    const inbox_host_header = try hostHeaderAlloc(allocator, inbox_host, inbox_uri.port, app_state.cfg.scheme);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    const signed = try http_signatures.signRequest(
        allocator,
        keys.private_key_pem,
        key_id,
        .POST,
        inbox_target,
        inbox_host_header,
        follow_body,
        std.time.timestamp(),
    );

    const resp = try app_state.transport.fetch(allocator, .{
        .url = inbox_url,
        .method = .POST,
        .headers = .{
            .host = .{ .override = inbox_host_header },
            .content_type = .{ .override = "application/activity+json" },
            .accept_encoding = .omit,
            .user_agent = .{ .override = "feddyspice" },
        },
        .extra_headers = &.{
            .{ .name = "accept", .value = "application/activity+json" },
            .{ .name = "date", .value = signed.date },
            .{ .name = "digest", .value = signed.digest },
            .{ .name = "signature", .value = signed.signature },
        },
        .payload = follow_body,
    });
    defer allocator.free(resp.body);

    if (resp.status.class() != .success) {
        const snippet = resp.body[0..@min(resp.body.len, 256)];
        app_state.logger.err(
            "sendFollowActivity: inbox={s} status={d} body={s}",
            .{ inbox_url, @intFromEnum(resp.status), snippet },
        );
        return error.FollowSendFailed;
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
    const inbox_uri = try std.Uri.parse(inbox_url);
    const inbox_target = try requestTargetAlloc(allocator, inbox_uri);

    const inbox_host = try inbox_uri.host.?.toRawMaybeAlloc(allocator);
    const inbox_host_header = try hostHeaderAlloc(allocator, inbox_host, inbox_uri.port, app_state.cfg.scheme);

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user_id);

    const signed = try http_signatures.signRequest(
        allocator,
        keys.private_key_pem,
        key_id,
        .POST,
        inbox_target,
        inbox_host_header,
        accept_body,
        std.time.timestamp(),
    );

    try fetchOkDiscardBody(app_state, allocator, .{
        .url = inbox_url,
        .method = .POST,
        .headers = .{
            .host = .{ .override = inbox_host_header },
            .content_type = .{ .override = "application/activity+json" },
            .accept_encoding = .omit,
            .user_agent = .{ .override = "feddyspice" },
        },
        .extra_headers = &.{
            .{ .name = "accept", .value = "application/activity+json" },
            .{ .name = "date", .value = signed.date },
            .{ .name = "digest", .value = signed.digest },
            .{ .name = "signature", .value = signed.signature },
        },
        .payload = accept_body,
    });

    _ = try followers.markAcceptedByRemoteActorId(&app_state.conn, user_id, actor.id);
}

pub fn deliverStatusToFollowers(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    app_state.logger.debug("deliverStatusToFollowers: user_id={d}", .{user.id});
    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    app_state.logger.debug("deliverStatusToFollowers: followers={d}", .{follower_ids.len});
    if (follower_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, user.username });

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const create_id = try std.fmt.allocPrint(allocator, "{s}#create", .{status_url});

    const content_html = try textToHtmlAlloc(allocator, st.text);

    const to = [_][]const u8{"https://www.w3.org/ns/activitystreams#Public"};
    const cc = [_][]const u8{followers_url};

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = create_id,
        .type = "Create",
        .actor = local_actor_id,
        .published = st.created_at,
        .to = to[0..],
        .cc = cc[0..],
        .object = .{
            .id = status_url,
            .type = "Note",
            .attributedTo = local_actor_id,
            .content = content_html,
            .published = st.created_at,
            .to = to[0..],
            .cc = cc[0..],
        },
    };

    const create_body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return error.OutOfMemory;

    const keys = try actor_keys.ensureForUser(&app_state.conn, allocator, user.id);

    for (follower_ids) |remote_actor_id| {
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
        const inbox_uri = std.Uri.parse(inbox_url) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: invalid inbox url={s} err={any}", .{ inbox_url, err });
            continue;
        };
        const inbox_target = requestTargetAlloc(allocator, inbox_uri) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: requestTargetAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        const inbox_host_part = inbox_uri.host orelse {
            app_state.logger.err("deliverStatusToFollowers: inbox url missing host url={s}", .{inbox_url});
            continue;
        };
        const inbox_host = inbox_host_part.toRawMaybeAlloc(allocator) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: toRawMaybeAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
        const inbox_host_header = hostHeaderAlloc(allocator, inbox_host, inbox_uri.port, app_state.cfg.scheme) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: hostHeaderAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        const signed = http_signatures.signRequest(
            allocator,
            keys.private_key_pem,
            key_id,
            .POST,
            inbox_target,
            inbox_host_header,
            create_body,
            std.time.timestamp(),
        ) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: signRequest failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        fetchOkDiscardBody(app_state, allocator, .{
            .url = inbox_url,
            .method = .POST,
            .headers = .{
                .host = .{ .override = inbox_host_header },
                .content_type = .{ .override = "application/activity+json" },
                .accept_encoding = .omit,
                .user_agent = .{ .override = "feddyspice" },
            },
            .extra_headers = &.{
                .{ .name = "accept", .value = "application/activity+json" },
                .{ .name = "date", .value = signed.date },
                .{ .name = "digest", .value = signed.digest },
                .{ .name = "signature", .value = signed.signature },
            },
            .payload = create_body,
        }) catch |err| {
            app_state.logger.err("deliverStatusToFollowers: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
}

pub fn deliverDeleteToFollowers(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) Error!void {
    if (st.deleted_at == null) return;

    const follower_ids = try followers.listAcceptedRemoteActorIds(&app_state.conn, allocator, user.id, 200);
    if (follower_ids.len == 0) return;

    const base = try baseUrlAlloc(app_state, allocator);
    const local_actor_id = try std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, user.username });
    const key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{local_actor_id});
    const followers_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, user.username });

    const status_url = try std.fmt.allocPrint(allocator, "{s}/users/{s}/statuses/{d}", .{ base, user.username, st.id });
    const delete_id = try std.fmt.allocPrint(allocator, "{s}#delete", .{status_url});

    const to = [_][]const u8{"https://www.w3.org/ns/activitystreams#Public"};
    const cc = [_][]const u8{followers_url};

    const payload = .{
        .@"@context" = "https://www.w3.org/ns/activitystreams",
        .id = delete_id,
        .type = "Delete",
        .actor = local_actor_id,
        .to = to[0..],
        .cc = cc[0..],
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

    for (follower_ids) |remote_actor_id| {
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
        const inbox_uri = std.Uri.parse(inbox_url) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: invalid inbox url={s} err={any}", .{ inbox_url, err });
            continue;
        };
        const inbox_target = requestTargetAlloc(allocator, inbox_uri) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: requestTargetAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        const inbox_host_part = inbox_uri.host orelse {
            app_state.logger.err("deliverDeleteToFollowers: inbox url missing host url={s}", .{inbox_url});
            continue;
        };
        const inbox_host = inbox_host_part.toRawMaybeAlloc(allocator) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: toRawMaybeAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
        const inbox_host_header = hostHeaderAlloc(allocator, inbox_host, inbox_uri.port, app_state.cfg.scheme) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: hostHeaderAlloc failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        const signed = http_signatures.signRequest(
            allocator,
            keys.private_key_pem,
            key_id,
            .POST,
            inbox_target,
            inbox_host_header,
            delete_body,
            std.time.timestamp(),
        ) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: signRequest failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };

        fetchOkDiscardBody(app_state, allocator, .{
            .url = inbox_url,
            .method = .POST,
            .headers = .{
                .host = .{ .override = inbox_host_header },
                .content_type = .{ .override = "application/activity+json" },
                .accept_encoding = .omit,
                .user_agent = .{ .override = "feddyspice" },
            },
            .extra_headers = &.{
                .{ .name = "accept", .value = "application/activity+json" },
                .{ .name = "date", .value = signed.date },
                .{ .name = "digest", .value = signed.digest },
                .{ .name = "signature", .value = signed.signature },
            },
            .payload = delete_body,
        }) catch |err| {
            app_state.logger.err("deliverDeleteToFollowers: deliver failed inbox={s} err={any}", .{ inbox_url, err });
            continue;
        };
    }
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

fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

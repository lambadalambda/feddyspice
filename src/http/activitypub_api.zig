const std = @import("std");

const app = @import("../app.zig");
const actor_keys = @import("../actor_keys.zig");
const activitypub_attachments = @import("../activitypub_attachments.zig");
const background = @import("../background.zig");
const common = @import("common.zig");
const conversations = @import("../conversations.zig");
const db = @import("../db.zig");
const federation = @import("../federation.zig");
const form = @import("../form.zig");
const follows = @import("../follows.zig");
const followers = @import("../followers.zig");
const http_types = @import("../http_types.zig");
const http_signatures = @import("../http_signatures.zig");
const inbox_dedupe = @import("../inbox_dedupe.zig");
const masto = @import("mastodon.zig");
const notifications = @import("../notifications.zig");
const notifications_api = @import("notifications_api.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const rate_limit = @import("../rate_limit.zig");
const status_reactions = @import("../status_reactions.zig");
const statuses = @import("../statuses.zig");
const urls = @import("urls.zig");
const users = @import("../users.zig");
const util_html = @import("../util/html.zig");
const util_json = @import("../util/json.zig");
const util_url = @import("../util/url.zig");

fn isPubliclyVisibleVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}

fn remoteStatusResponse(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) http_types.Response {
    const payload = masto.makeRemoteStatusPayload(app_state, allocator, actor, st);
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

fn stripLocalBase(app_state: *app.App, iri: []const u8) ?[]const u8 {
    const domain = app_state.cfg.domain;

    const schemes = [_][]const u8{ "http://", "https://" };
    for (schemes) |scheme| {
        if (!std.mem.startsWith(u8, iri, scheme)) continue;
        const rest = iri[scheme.len..];
        if (!std.mem.startsWith(u8, rest, domain)) continue;
        const after_domain = rest[domain.len..];
        if (after_domain.len == 0) return "";
        if (after_domain[0] == '/') return after_domain;
    }
    return null;
}

fn parseLeadingI64(s: []const u8) ?i64 {
    if (s.len == 0) return null;
    var end: usize = 0;
    while (end < s.len and s[end] >= '0' and s[end] <= '9') : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(i64, s[0..end], 10) catch null;
}

fn localStatusIdFromIri(app_state: *app.App, iri: []const u8) ?i64 {
    const path = stripLocalBase(app_state, iri) orelse return null;
    if (path.len == 0) return null;

    const api_prefix = "/api/v1/statuses/";
    if (std.mem.startsWith(u8, path, api_prefix)) {
        const rest = path[api_prefix.len..];
        const id = parseLeadingI64(rest) orelse return null;
        if (id <= 0) return null;
        return id;
    }

    const users_prefix = "/users/";
    if (!std.mem.startsWith(u8, path, users_prefix)) return null;
    const rest = path[users_prefix.len..];
    const marker = "/statuses/";
    const idx = std.mem.indexOf(u8, rest, marker) orelse return null;
    if (idx == 0) return null;
    const after_marker = rest[idx + marker.len ..];
    const id = parseLeadingI64(after_marker) orelse return null;
    if (id <= 0) return null;
    return id;
}

const VerifyInboxError = error{ Unauthorized, Internal };

fn verifyInboxSignature(
    allocator: std.mem.Allocator,
    req: http_types.Request,
    actor: remote_actors.RemoteActor,
    now_sec: i64,
    max_clock_skew_sec: i64,
) VerifyInboxError!void {
    const sig_hdr = req.signature orelse return error.Unauthorized;
    const host_hdr = req.host orelse return error.Unauthorized;
    const date_hdr = req.date orelse return error.Unauthorized;
    const digest_hdr = req.digest orelse return error.Unauthorized;

    if (!http_signatures.digestHeaderHasSha256(req.body, digest_hdr)) return error.Unauthorized;
    if (!http_signatures.httpDateWithinSkew(date_hdr, now_sec, max_clock_skew_sec)) return error.Unauthorized;

    var cl_buf: [32]u8 = undefined;
    const content_length = std.fmt.bufPrint(&cl_buf, "{d}", .{req.body.len}) catch return error.Internal;

    const ok = http_signatures.verifyRequestSignaturePem(
        allocator,
        actor.public_key_pem,
        sig_hdr,
        req.method,
        req.target,
        host_hdr,
        date_hdr,
        digest_hdr,
        req.content_type,
        content_length,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.Internal,
        else => return error.Unauthorized,
    };
    if (!ok) return error.Unauthorized;
}

fn unauthorizedResponse() http_types.Response {
    return .{ .status = .unauthorized, .body = "unauthorized\n" };
}

fn verifyInboxSignatureOrReject(
    allocator: std.mem.Allocator,
    req: http_types.Request,
    actor: remote_actors.RemoteActor,
    now_sec: i64,
    max_clock_skew_sec: i64,
) ?http_types.Response {
    verifyInboxSignature(allocator, req, actor, now_sec, max_clock_skew_sec) catch |err| switch (err) {
        error.Unauthorized => return unauthorizedResponse(),
        error.Internal => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };
    return null;
}

fn jsonFirstUrlString(val: std.json.Value) ?[]const u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else s,
        .object => |o| {
            if (o.get("url")) |u| {
                if (jsonFirstUrlString(u)) |s| return s;
            }
            if (o.get("href")) |h| {
                if (h == .string and h.string.len > 0) return h.string;
            }
            return null;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (jsonFirstUrlString(item)) |s| return s;
            }
            return null;
        },
        else => return null,
    }
}

pub fn sharedInboxPost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const user = users.lookupFirstUser(&app_state.conn, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const path = std.fmt.allocPrint(allocator, "/users/{s}/inbox", .{user.?.username}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return inboxPost(app_state, allocator, req, path);
}

pub fn actorGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
    const username = path["/users/".len..];
    if (username.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, username, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const keys = actor_keys.ensureForUser(&app_state.conn, allocator, user.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const actor_id = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const inbox = std.fmt.allocPrint(allocator, "{s}/users/{s}/inbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const shared_inbox = std.fmt.allocPrint(allocator, "{s}/inbox", .{base}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const outbox = std.fmt.allocPrint(allocator, "{s}/users/{s}/outbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const followers_url = std.fmt.allocPrint(allocator, "{s}/users/{s}/followers", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const following = std.fmt.allocPrint(allocator, "{s}/users/{s}/following", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const key_id = std.fmt.allocPrint(allocator, "{s}#main-key", .{actor_id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, user.?);
    const header_url = urls.userHeaderUrlAlloc(app_state, allocator, user.?);
    const note_html = textToHtmlAlloc(allocator, user.?.note) catch user.?.note;

    const payload = .{
        .@"@context" = [_][]const u8{
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        },
        .id = actor_id,
        .type = "Person",
        .name = user.?.display_name,
        .preferredUsername = user.?.username,
        .summary = note_html,
        .icon = .{ .type = "Image", .url = avatar_url },
        .image = .{ .type = "Image", .url = header_url },
        .inbox = inbox,
        .endpoints = .{ .sharedInbox = shared_inbox },
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

pub fn followersGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
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

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
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

pub fn followingGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
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

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
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

pub fn outboxGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
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

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const outbox_id = std.fmt.allocPrint(allocator, "{s}/users/{s}/outbox", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const q = common.queryString(req.target);
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

pub fn userStatusGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
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

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
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
    const want = util_url.trimTrailingSlash(needle);

    switch (val) {
        .string => |s| return std.mem.eql(u8, util_url.trimTrailingSlash(s), want),
        .object => |o| {
            const id_val = o.get("id") orelse return false;
            if (id_val != .string) return false;
            return std.mem.eql(u8, util_url.trimTrailingSlash(id_val.string), want);
        },
        .array => |arr| {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| if (std.mem.eql(u8, util_url.trimTrailingSlash(s), want)) return true,
                    .object => |o| {
                        const id_val = o.get("id") orelse continue;
                        if (id_val != .string) continue;
                        if (std.mem.eql(u8, util_url.trimTrailingSlash(id_val.string), want)) return true;
                    },
                    else => continue,
                }
            }
            return false;
        },
        else => return false,
    }
}

fn jsonTruthiness(v: ?std.json.Value) bool {
    const val = v orelse return false;
    return switch (val) {
        .bool => |b| b,
        else => false,
    };
}

fn jsonFirstUrl(val: std.json.Value) ?[]const u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else s,
        .object => |o| {
            if (o.get("url")) |u| {
                if (jsonFirstUrl(u)) |s| return s;
            }
            if (o.get("href")) |h| {
                if (h == .string and h.string.len > 0) return h.string;
            }
            return null;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (jsonFirstUrl(item)) |s| return s;
            }
            return null;
        },
        else => return null,
    }
}

fn remoteAttachmentsJsonAlloc(allocator: std.mem.Allocator, note: std.json.ObjectMap) !?[]u8 {
    return activitypub_attachments.remoteAttachmentsJsonAlloc(allocator, note);
}

test "remoteAttachmentsJsonAlloc ignores non-http(s) URLs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const note1 =
        \\{"attachment":[{"url":"javascript:alert(1)","type":"Image"},{"url":"https://cdn.test/a.png","type":"Image"}]}
    ;
    var parsed1 = try std.json.parseFromSlice(std.json.Value, a, note1, .{});
    defer parsed1.deinit();
    const out1 = (try remoteAttachmentsJsonAlloc(a, parsed1.value.object)).?;

    var out1_parsed = try std.json.parseFromSlice(std.json.Value, a, out1, .{});
    defer out1_parsed.deinit();
    try std.testing.expect(out1_parsed.value == .array);
    try std.testing.expectEqual(@as(usize, 1), out1_parsed.value.array.items.len);
    try std.testing.expectEqualStrings("https://cdn.test/a.png", out1_parsed.value.array.items[0].object.get("url").?.string);

    const note2 =
        \\{"attachment":{"url":"data:text/plain,hi","type":"Image"}}
    ;
    var parsed2 = try std.json.parseFromSlice(std.json.Value, a, note2, .{});
    defer parsed2.deinit();
    try std.testing.expect((try remoteAttachmentsJsonAlloc(a, parsed2.value.object)) == null);
}

test "remoteAttachmentsJsonAlloc caps attachments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const note =
        \\{"attachment":[
        \\  {"url":"https://cdn.test/1.png","type":"Image"},
        \\  {"url":"https://cdn.test/2.png","type":"Image"},
        \\  {"url":"https://cdn.test/3.png","type":"Image"},
        \\  {"url":"https://cdn.test/4.png","type":"Image"},
        \\  {"url":"https://cdn.test/5.png","type":"Image"}
        \\]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, note, .{});
    defer parsed.deinit();
    const out = (try remoteAttachmentsJsonAlloc(a, parsed.value.object)).?;

    var out_parsed = try std.json.parseFromSlice(std.json.Value, a, out, .{});
    defer out_parsed.deinit();
    try std.testing.expect(out_parsed.value == .array);
    try std.testing.expectEqual(@as(usize, 4), out_parsed.value.array.items.len);
    try std.testing.expectEqualStrings("https://cdn.test/1.png", out_parsed.value.array.items[0].object.get("url").?.string);
    try std.testing.expectEqualStrings("https://cdn.test/4.png", out_parsed.value.array.items[3].object.get("url").?.string);
}

test "verifyInboxSignature enforces Date max clock skew" {
    const crypto_rsa = @import("../crypto_rsa.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try crypto_rsa.generateRsaKeyPairPem(a, 512);

    const actor: remote_actors.RemoteActor = .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = kp.public_key_pem,
    };

    const body = "{}";
    const signed = try http_signatures.signRequest(
        a,
        kp.private_key_pem,
        "https://remote.test/users/bob#main-key",
        .POST,
        "/users/alice/inbox",
        "example.test",
        body,
        0,
    );

    const req: http_types.Request = .{
        .method = .POST,
        .target = "/users/alice/inbox",
        .content_type = "application/activity+json",
        .body = body,
        .host = "example.test",
        .date = signed.date,
        .digest = signed.digest,
        .signature = signed.signature,
    };

    try verifyInboxSignature(a, req, actor, 0, 0);
    try std.testing.expectError(error.Unauthorized, verifyInboxSignature(a, req, actor, 1000, 10));

    var bad = req;
    bad.date = "not-a-date";
    try std.testing.expectError(error.Unauthorized, verifyInboxSignature(a, bad, actor, 0, 100));
}

pub fn inboxPost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
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

    if (util_json.maxNestingDepth(req.body) > app_state.cfg.json_max_nesting_depth) {
        return .{ .status = .bad_request, .body = "json too deep\n" };
    }

    if (util_json.structuralTokenCount(req.body) > app_state.cfg.json_max_tokens) {
        return .{ .status = .bad_request, .body = "json too many tokens\n" };
    }

    const ok = rate_limit.allowNow(&app_state.conn, "ap_inbox", 60_000, 1200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .too_many_requests, .body = "too many requests\n" };

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
        if (!util_url.isHttpOrHttpsUrl(note_id_val.string)) return .{ .status = .accepted, .body = "ignored\n" };

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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_val.string, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

        var remote_actor = remote_actors.lookupByIdAny(&app_state.conn, allocator, actor_val.string) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (remote_actor == null) {
            remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch null;
            if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };
        }

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?, now_sec, max_clock_skew_sec)) |resp| return resp;

        const visibility: []const u8 = blk: {
            const direct_message =
                jsonTruthiness(parsed.value.object.get("directMessage")) or
                jsonTruthiness(obj.object.get("directMessage"));
            if (direct_message) break :blk "direct";

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

        const attachments_json = remoteAttachmentsJsonAlloc(allocator, obj.object) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const safe_content_html = util_html.safeHtmlFromRemoteHtmlAlloc(allocator, content_val.string) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const InReplyTo = struct { id: ?i64, uri: ?[]const u8 };

        const in_reply_to: ?InReplyTo = blk: {
            const raw = obj.object.get("inReplyTo") orelse break :blk null;

            const uri_str: []const u8 = switch (raw) {
                .string => |s| s,
                .object => |o| blk2: {
                    const id_val = o.get("id") orelse break :blk2 "";
                    if (id_val != .string) break :blk2 "";
                    break :blk2 id_val.string;
                },
                else => "",
            };
            if (uri_str.len == 0) break :blk null;

            const trimmed = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(uri_str));
            if (!util_url.isHttpOrHttpsUrl(trimmed)) break :blk null;

            if (localStatusIdFromIri(app_state, trimmed)) |local_id| {
                const parent = statuses.lookup(&app_state.conn, allocator, local_id) catch break :blk null;
                if (parent != null) break :blk InReplyTo{ .id = local_id, .uri = null };
                break :blk null;
            }

            const remote_parent = remote_statuses.lookupByUriAny(&app_state.conn, allocator, trimmed) catch break :blk null;
            if (remote_parent) |p| break :blk InReplyTo{ .id = p.id, .uri = null };

            break :blk InReplyTo{ .id = null, .uri = trimmed };
        };
        const in_reply_to_id: ?i64 = if (in_reply_to) |it| it.id else null;
        const in_reply_to_uri: ?[]const u8 = if (in_reply_to) |it| it.uri else null;

        const created = remote_statuses.createIfNotExists(
            &app_state.conn,
            allocator,
            note_id_val.string,
            remote_actor.?.id,
            in_reply_to_id,
            safe_content_html,
            attachments_json,
            visibility,
            created_at,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (created.in_reply_to_id == null) {
            if (in_reply_to_uri) |uri| {
                background.backfillThread(app_state, allocator, user.?.id, created.id, uri);
            }
        }

        if (std.mem.eql(u8, visibility, "direct")) {
            conversations.upsertDirect(
                &app_state.conn,
                user.?.id,
                remote_actor.?.id,
                created.id,
                received_at_ms,
            ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        const st_resp = remoteStatusResponse(app_state, allocator, remote_actor.?, created);
        app_state.streaming.publishUpdate(user.?.id, st_resp.body);

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    if (std.mem.eql(u8, typ.string, "Update")) {
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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_val.string, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch null;
        if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?, now_sec, max_clock_skew_sec)) |resp| return resp;

        const obj_val = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };
        if (obj_val != .object) return .{ .status = .accepted, .body = "ignored\n" };

        const obj_id_val = obj_val.object.get("id") orelse return .{ .status = .accepted, .body = "ignored\n" };
        if (obj_id_val != .string) return .{ .status = .accepted, .body = "ignored\n" };

        const obj_type_val = obj_val.object.get("type") orelse return .{ .status = .accepted, .body = "ignored\n" };
        if (obj_type_val != .string) return .{ .status = .accepted, .body = "ignored\n" };

        if (std.mem.eql(u8, obj_type_val.string, "Person")) {
            if (!std.mem.eql(u8, util_url.trimTrailingSlash(obj_id_val.string), util_url.trimTrailingSlash(remote_actor.?.id))) {
                return .{ .status = .accepted, .body = "ignored\n" };
            }

            var inbox_url: []const u8 = remote_actor.?.inbox;
            if (obj_val.object.get("inbox")) |inbox_val| {
                if (inbox_val == .string and util_url.isHttpOrHttpsUrl(inbox_val.string)) {
                    inbox_url = inbox_val.string;
                }
            }

            var shared_inbox: ?[]const u8 = remote_actor.?.shared_inbox;
            if (obj_val.object.get("endpoints")) |endpoints_val| {
                if (endpoints_val == .object) {
                    if (endpoints_val.object.get("sharedInbox")) |si| {
                        if (si == .string and util_url.isHttpOrHttpsUrl(si.string)) {
                            shared_inbox = si.string;
                        }
                    }
                }
            }

            var preferred_username: []const u8 = remote_actor.?.preferred_username;
            if (obj_val.object.get("preferredUsername")) |user_val| {
                if (user_val == .string and user_val.string.len > 0) {
                    preferred_username = user_val.string;
                }
            }

            var public_key_pem: []const u8 = remote_actor.?.public_key_pem;
            if (obj_val.object.get("publicKey")) |pk_val| {
                if (pk_val == .object) {
                    if (pk_val.object.get("publicKeyPem")) |pem_val| {
                        if (pem_val == .string and pem_val.string.len > 0) {
                            public_key_pem = pem_val.string;
                        }
                    }
                }
            }

            var avatar_url: ?[]const u8 = remote_actor.?.avatar_url;
            if (obj_val.object.get("icon")) |icon_val| {
                if (jsonFirstUrlString(icon_val)) |u| {
                    if (util_url.isHttpOrHttpsUrl(u)) avatar_url = u;
                }
            }

            var header_url: ?[]const u8 = remote_actor.?.header_url;
            if (obj_val.object.get("image")) |image_val| {
                if (jsonFirstUrlString(image_val)) |u| {
                    if (util_url.isHttpOrHttpsUrl(u)) header_url = u;
                }
            }

            remote_actors.upsert(&app_state.conn, .{
                .id = remote_actor.?.id,
                .inbox = inbox_url,
                .shared_inbox = shared_inbox,
                .preferred_username = preferred_username,
                .domain = remote_actor.?.domain,
                .public_key_pem = public_key_pem,
                .avatar_url = avatar_url,
                .header_url = header_url,
            }) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

            dedupe_keep = true;
            return .{ .status = .accepted, .body = "ok\n" };
        }

        if (std.mem.eql(u8, obj_type_val.string, "Note")) {
            if (!util_url.isHttpOrHttpsUrl(obj_id_val.string)) return .{ .status = .accepted, .body = "ignored\n" };

            const content_val = obj_val.object.get("content") orelse return .{ .status = .accepted, .body = "ignored\n" };
            if (content_val != .string) return .{ .status = .accepted, .body = "ignored\n" };

            const remote_status = blk: {
                if (remote_statuses.lookupByUri(&app_state.conn, allocator, obj_id_val.string) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                {
                    break :blk found;
                }

                const trimmed = util_url.trimTrailingSlash(obj_id_val.string);
                if (!std.mem.eql(u8, trimmed, obj_id_val.string)) {
                    if (remote_statuses.lookupByUri(&app_state.conn, allocator, trimmed) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                    {
                        break :blk found;
                    }
                } else {
                    const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{obj_id_val.string}) catch
                        break :blk null;
                    if (remote_statuses.lookupByUri(&app_state.conn, allocator, with_slash) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                    {
                        break :blk found;
                    }
                }

                const stripped = util_url.stripQueryAndFragment(obj_id_val.string);
                if (!std.mem.eql(u8, stripped, obj_id_val.string)) {
                    if (remote_statuses.lookupByUri(&app_state.conn, allocator, stripped) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                    {
                        break :blk found;
                    }

                    const stripped_trimmed = util_url.trimTrailingSlash(stripped);
                    if (!std.mem.eql(u8, stripped_trimmed, stripped)) {
                        if (remote_statuses.lookupByUri(&app_state.conn, allocator, stripped_trimmed) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                        {
                            break :blk found;
                        }
                    } else {
                        const with_slash = std.fmt.allocPrint(allocator, "{s}/", .{stripped}) catch
                            break :blk null;
                        if (remote_statuses.lookupByUri(&app_state.conn, allocator, with_slash) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" }) |found|
                        {
                            break :blk found;
                        }
                    }
                }

                break :blk null;
            };
            if (remote_status == null) return .{ .status = .accepted, .body = "ignored\n" };
            if (!std.mem.eql(u8, remote_status.?.remote_actor_id, remote_actor.?.id)) {
                return .{ .status = .accepted, .body = "ignored\n" };
            }

            const safe_content_html = util_html.safeHtmlFromRemoteHtmlAlloc(allocator, content_val.string) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };

            var attachments_json: ?[]const u8 = remote_status.?.attachments_json;
            if (obj_val.object.get("attachment") != null) {
                attachments_json = remoteAttachmentsJsonAlloc(allocator, obj_val.object) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" };
            }

            const visibility: []const u8 = blk: {
                const has_recipients =
                    (parsed.value.object.get("to") != null) or
                    (parsed.value.object.get("cc") != null) or
                    (obj_val.object.get("to") != null) or
                    (obj_val.object.get("cc") != null);
                if (!has_recipients) break :blk remote_status.?.visibility;

                const public_iri = "https://www.w3.org/ns/activitystreams#Public";

                const public_in_to =
                    jsonContainsIri(parsed.value.object.get("to"), public_iri) or
                    jsonContainsIri(obj_val.object.get("to"), public_iri);
                if (public_in_to) break :blk "public";

                const public_in_cc =
                    jsonContainsIri(parsed.value.object.get("cc"), public_iri) or
                    jsonContainsIri(obj_val.object.get("cc"), public_iri);
                if (public_in_cc) break :blk "unlisted";

                break :blk "direct";
            };

            const updated = remote_statuses.updateByUri(
                &app_state.conn,
                remote_status.?.remote_uri,
                safe_content_html,
                attachments_json,
                visibility,
            ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

            if (updated) {
                if (std.mem.eql(u8, visibility, "direct")) {
                    conversations.upsertDirect(
                        &app_state.conn,
                        user.?.id,
                        remote_actor.?.id,
                        remote_status.?.id,
                        received_at_ms,
                    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                }

                const st = (remote_statuses.lookupByUri(&app_state.conn, allocator, remote_status.?.remote_uri) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" }).?;
                const st_resp = remoteStatusResponse(app_state, allocator, remote_actor.?, st);
                app_state.streaming.publishUpdate(user.?.id, st_resp.body);
            }

            dedupe_keep = true;
            return .{ .status = .accepted, .body = "ok\n" };
        }

        return .{ .status = .accepted, .body = "ignored\n" };
    }

    if (std.mem.eql(u8, typ.string, "Like") or std.mem.eql(u8, typ.string, "Announce")) {
        const actor_val = parsed.value.object.get("actor") orelse
            return .{ .status = .bad_request, .body = "missing actor\n" };
        if (actor_val != .string) return .{ .status = .bad_request, .body = "invalid actor\n" };

        const obj_val = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };

        const object_iri: []const u8 = switch (obj_val) {
            .string => |s| s,
            .object => |o| blk: {
                const id_val = o.get("id") orelse break :blk "";
                if (id_val != .string) break :blk "";
                break :blk id_val.string;
            },
            else => "",
        };
        if (object_iri.len == 0) return .{ .status = .bad_request, .body = "invalid object\n" };

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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_val.string, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch null;
        if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?, now_sec, max_clock_skew_sec)) |resp| return resp;

        const trimmed = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(object_iri));
        if (!util_url.isHttpOrHttpsUrl(trimmed)) return .{ .status = .accepted, .body = "ignored\n" };

        const status_id_opt = localStatusIdFromIri(app_state, trimmed);
        if (status_id_opt == null) {
            const f = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, user.?.id, remote_actor.?.id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (f == null or f.?.state != .accepted) return .{ .status = .accepted, .body = "ignored\n" };

            background.ingestRemoteNote(app_state, allocator, user.?.id, trimmed);
            dedupe_keep = true;
            return .{ .status = .accepted, .body = "ok\n" };
        }

        const status_id = status_id_opt.?;

        const st = statuses.lookup(&app_state.conn, allocator, status_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .accepted, .body = "ignored\n" };
        if (st.?.user_id != user.?.id) return .{ .status = .accepted, .body = "ignored\n" };

        const kind = if (std.mem.eql(u8, typ.string, "Like")) "favourite" else "reblog";
        const activated = status_reactions.activate(
            &app_state.conn,
            st.?.id,
            remote_actor.?.id,
            kind,
            activity_id,
            received_at_ms,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (activated) {
            const notif_id = notifications.create(&app_state.conn, user.?.id, kind, remote_actor.?.id, st.?.id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };

            if (notifications_api.notificationJsonByIdAlloc(app_state, allocator, user.?.id, notif_id)) |notif_json| {
                app_state.streaming.publishNotification(user.?.id, notif_json);
            }
        }

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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_val.string, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

        const remote_actor = remote_actors.lookupByIdAny(&app_state.conn, allocator, actor_val.string) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
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

            const trimmed = util_url.trimTrailingSlash(object_id);
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

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?, now_sec, max_clock_skew_sec)) |resp| return resp;

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

        const follow_activity_id = util_url.trimTrailingSlash(id_val.string);
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

        const base = util_url.baseUrlAlloc(app_state, allocator) catch
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

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor, now_sec, max_clock_skew_sec)) |resp| return resp;

        background.acceptInboundFollow(app_state, allocator, user.?.id, username, actor_val.string, follow_activity_id);

        dedupe_keep = true;
        return .{ .status = .accepted, .body = "ok\n" };
    }

    if (std.mem.eql(u8, typ.string, "Undo")) {
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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_val.string, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_val.string, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_val.string) catch null;
        if (remote_actor == null) return .{ .status = .accepted, .body = "ignored\n" };

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?, now_sec, max_clock_skew_sec)) |resp| return resp;

        const obj_val = parsed.value.object.get("object") orelse
            return .{ .status = .bad_request, .body = "missing object\n" };

        const base = util_url.baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const expected_actor_id = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const trimSlash = struct {
            fn f(s: []const u8) []const u8 {
                if (s.len == 0) return s;
                if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
                return s;
            }
        }.f;

        var is_undo_follow: bool = false;
        var handled_reaction: bool = false;
        switch (obj_val) {
            .string => |undo_object_id| {
                const existing = followers.lookupByRemoteActorId(&app_state.conn, allocator, user.?.id, remote_actor.?.id) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" };
                if (existing) |f| {
                    is_undo_follow = std.mem.eql(u8, trimSlash(f.follow_activity_id), trimSlash(undo_object_id));
                }

                if (!is_undo_follow) {
                    const trimmed_id = util_url.trimTrailingSlash(undo_object_id);
                    if (trimmed_id.len > 0) {
                        _ = status_reactions.undoByActivityId(&app_state.conn, remote_actor.?.id, trimmed_id, received_at_ms) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" };
                        handled_reaction = true;
                    }
                }
            },
            .object => |o| {
                const t = o.get("type") orelse return .{ .status = .accepted, .body = "ignored\n" };
                if (t != .string) return .{ .status = .accepted, .body = "ignored\n" };
                if (std.mem.eql(u8, t.string, "Follow")) {
                    const inner_actor_val = o.get("actor") orelse return .{ .status = .accepted, .body = "ignored\n" };
                    const inner_object_val = o.get("object") orelse return .{ .status = .accepted, .body = "ignored\n" };
                    if (inner_actor_val != .string) return .{ .status = .accepted, .body = "ignored\n" };
                    if (inner_object_val != .string) return .{ .status = .accepted, .body = "ignored\n" };

                    if (!std.mem.eql(u8, trimSlash(inner_actor_val.string), trimSlash(remote_actor.?.id))) {
                        return .{ .status = .accepted, .body = "ignored\n" };
                    }
                    if (!std.mem.eql(u8, trimSlash(inner_object_val.string), trimSlash(expected_actor_id))) {
                        return .{ .status = .accepted, .body = "ignored\n" };
                    }

                    is_undo_follow = true;
                } else if (std.mem.eql(u8, t.string, "Like") or std.mem.eql(u8, t.string, "Announce")) {
                    const inner_actor_val = o.get("actor") orelse return .{ .status = .accepted, .body = "ignored\n" };
                    if (inner_actor_val != .string) return .{ .status = .accepted, .body = "ignored\n" };
                    if (!std.mem.eql(u8, trimSlash(inner_actor_val.string), trimSlash(remote_actor.?.id))) {
                        return .{ .status = .accepted, .body = "ignored\n" };
                    }

                    const inner_object_val = o.get("object") orelse return .{ .status = .accepted, .body = "ignored\n" };
                    const inner_object_iri: []const u8 = switch (inner_object_val) {
                        .string => |s| s,
                        .object => |io| blk: {
                            const id_val = io.get("id") orelse break :blk "";
                            if (id_val != .string) break :blk "";
                            break :blk id_val.string;
                        },
                        else => "",
                    };
                    if (inner_object_iri.len == 0) return .{ .status = .accepted, .body = "ignored\n" };

                    const trimmed = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(inner_object_iri));
                    if (!util_url.isHttpOrHttpsUrl(trimmed)) return .{ .status = .accepted, .body = "ignored\n" };

                    const status_id = localStatusIdFromIri(app_state, trimmed) orelse return .{ .status = .accepted, .body = "ignored\n" };
                    const st = statuses.lookup(&app_state.conn, allocator, status_id) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    if (st == null) return .{ .status = .accepted, .body = "ignored\n" };
                    if (st.?.user_id != user.?.id) return .{ .status = .accepted, .body = "ignored\n" };

                    const kind = if (std.mem.eql(u8, t.string, "Like")) "favourite" else "reblog";
                    _ = status_reactions.undo(&app_state.conn, st.?.id, remote_actor.?.id, kind, received_at_ms) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    handled_reaction = true;
                } else {
                    return .{ .status = .accepted, .body = "ignored\n" };
                }
            },
            else => return .{ .status = .bad_request, .body = "invalid object\n" },
        }

        if (is_undo_follow) {
            _ = followers.deleteByRemoteActorId(&app_state.conn, user.?.id, remote_actor.?.id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };

            dedupe_keep = true;
            return .{ .status = .accepted, .body = "ok\n" };
        }

        if (!handled_reaction) return .{ .status = .accepted, .body = "ignored\n" };

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
            break :blk util_url.trimTrailingSlash(id_val.string);
        };
        const actor_id = blk: {
            const actor_val = parsed.value.object.get("actor") orelse break :blk null;
            if (actor_val != .string) break :blk null;
            if (actor_val.string.len == 0) break :blk null;
            break :blk actor_val.string;
        };

        if (actor_id == null) return .{ .status = .bad_request, .body = "missing actor\n" };

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_id.?) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const now_sec: i64 = std.time.timestamp();
        const max_clock_skew_sec: i64 = @intCast(app_state.cfg.signature_max_clock_skew_sec);
        if (verifyInboxSignatureOrReject(allocator, req, remote_actor, now_sec, max_clock_skew_sec)) |resp| return resp;

        const dedupe_id = activity_id orelse inbox_dedupe.fallbackKeyAlloc(allocator, actor_id.?, req.body) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const inserted = inbox_dedupe.begin(&app_state.conn, dedupe_id, user.?.id, actor_id.?, received_at_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (!inserted) return .{ .status = .accepted, .body = "duplicate\n" };
        dedupe_activity_id = dedupe_id;

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

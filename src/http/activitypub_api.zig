const std = @import("std");

const app = @import("../app.zig");
const actor_keys = @import("../actor_keys.zig");
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
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const statuses = @import("../statuses.zig");
const urls = @import("urls.zig");
const users = @import("../users.zig");
const util_html = @import("../util/html.zig");
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

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

const VerifyInboxError = error{ Unauthorized, Internal };

fn verifyInboxSignature(
    allocator: std.mem.Allocator,
    req: http_types.Request,
    actor: remote_actors.RemoteActor,
) VerifyInboxError!void {
    const sig_hdr = req.signature orelse return error.Unauthorized;
    const host_hdr = req.host orelse return error.Unauthorized;
    const date_hdr = req.date orelse return error.Unauthorized;
    const digest_hdr = req.digest orelse return error.Unauthorized;

    if (!http_signatures.digestHeaderHasSha256(req.body, digest_hdr)) return error.Unauthorized;

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
) ?http_types.Response {
    verifyInboxSignature(allocator, req, actor) catch |err| switch (err) {
        error.Unauthorized => return unauthorizedResponse(),
        error.Internal => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };
    return null;
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
    const val = note.get("attachment") orelse return null;

    const Attachment = struct {
        url: []const u8,
        kind: ?[]const u8 = null,
        media_type: ?[]const u8 = null,
        description: ?[]const u8 = null,
        blurhash: ?[]const u8 = null,
    };

    var list: std.ArrayListUnmanaged(Attachment) = .empty;
    defer list.deinit(allocator);

    const helper = struct {
        fn pushOne(
            alloc: std.mem.Allocator,
            out: *std.ArrayListUnmanaged(Attachment),
            item: std.json.Value,
        ) !void {
            const url = jsonFirstUrl(item) orelse return;

            var kind: ?[]const u8 = null;
            var media_type: ?[]const u8 = null;
            var description: ?[]const u8 = null;
            var blurhash: ?[]const u8 = null;

            if (item == .object) {
                if (item.object.get("type")) |t| {
                    if (t == .string and t.string.len > 0) kind = t.string;
                }
                if (item.object.get("mediaType")) |t| {
                    if (t == .string and t.string.len > 0) media_type = t.string;
                }
                if (item.object.get("name")) |t| {
                    if (t == .string and t.string.len > 0) description = t.string;
                }
                if (item.object.get("blurhash")) |t| {
                    if (t == .string and t.string.len > 0) blurhash = t.string;
                }
            }

            try out.append(alloc, .{
                .url = url,
                .kind = kind,
                .media_type = media_type,
                .description = description,
                .blurhash = blurhash,
            });
        }
    };

    switch (val) {
        .array => |arr| for (arr.items) |item| try helper.pushOne(allocator, &list, item),
        else => try helper.pushOne(allocator, &list, val),
    }

    if (list.items.len == 0) return null;
    const json = try std.json.Stringify.valueAlloc(allocator, list.items, .{});
    return json;
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

        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?)) |resp| return resp;

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

        const attachments_json = remoteAttachmentsJsonAlloc(allocator, obj.object) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        const created = remote_statuses.createIfNotExists(
            &app_state.conn,
            allocator,
            note_id_val.string,
            remote_actor.?.id,
            content_val.string,
            attachments_json,
            visibility,
            created_at,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

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

        if (verifyInboxSignatureOrReject(allocator, req, remote_actor.?)) |resp| return resp;

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

        if (verifyInboxSignatureOrReject(allocator, req, remote_actor)) |resp| return resp;

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

        if (actor_id == null) return .{ .status = .bad_request, .body = "missing actor\n" };

        const remote_actor = federation.ensureRemoteActorById(app_state, allocator, actor_id.?) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        if (verifyInboxSignatureOrReject(allocator, req, remote_actor)) |resp| return resp;

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

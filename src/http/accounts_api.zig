const std = @import("std");

const app = @import("../app.zig");
const background = @import("../background.zig");
const common = @import("common.zig");
const federation = @import("../federation.zig");
const followers = @import("../followers.zig");
const form = @import("../form.zig");
const follows = @import("../follows.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const media = @import("../media.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const statuses = @import("../statuses.zig");
const urls = @import("urls.zig");
const util_ids = @import("../util/ids.zig");
const users = @import("../users.zig");
const util_html = @import("../util/html.zig");
const util_url = @import("../util/url.zig");

const AccountPayload = masto.AccountPayload;
const AccountCredentialsPayload = masto.AccountCredentialsPayload;
const StatusPayload = masto.StatusPayload;

const remote_actor_id_base: i64 = util_ids.remote_actor_id_base;

fn remoteAccountApiIdAlloc(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) []const u8 {
    return util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor_id);
}

fn makeRemoteAccountPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    api_id: []const u8,
    actor: remote_actors.RemoteActor,
) AccountPayload {
    return masto.makeRemoteAccountPayload(app_state, allocator, api_id, actor);
}

fn isPubliclyVisibleVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}

pub fn verifyCredentials(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    return accountCredentialsByUser(app_state, allocator, user.?);
}

pub fn updateCredentials(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    var display_name = user.?.display_name;
    var note = user.?.note;
    var avatar_media_id = user.?.avatar_media_id;
    var header_media_id = user.?.header_media_id;

    var avatar_file: ?form.MultipartFilePart = null;
    var header_file: ?form.MultipartFilePart = null;

    var clear_avatar = false;
    var clear_header = false;

    if (common.isMultipart(req.content_type)) {
        var parsed = form.parseMultipartWithFiles(allocator, req.content_type.?, req.body) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };
        defer parsed.deinit(allocator);

        if (parsed.form.get("display_name")) |v| {
            display_name = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
        if (parsed.form.get("note")) |v| {
            note = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        if (parsed.form.get("avatar")) |v| clear_avatar = v.len == 0;
        if (parsed.form.get("header")) |v| clear_header = v.len == 0;

        for (parsed.files) |f| {
            if (std.mem.eql(u8, f.name, "avatar")) avatar_file = f;
            if (std.mem.eql(u8, f.name, "header")) header_file = f;
        }
    } else {
        var parsed = common.parseBodyParams(allocator, req) catch
            return .{ .status = .bad_request, .body = "invalid form\n" };
        defer parsed.deinit(allocator);

        if (parsed.get("display_name")) |v| {
            display_name = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
        if (parsed.get("note")) |v| {
            note = allocator.dupe(u8, v) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        if (parsed.get("avatar")) |v| clear_avatar = v.len == 0;
        if (parsed.get("header")) |v| clear_header = v.len == 0;
    }

    if (clear_avatar) avatar_media_id = null;
    if (clear_header) header_media_id = null;

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const now_ms: i64 = std.time.milliTimestamp();

    if (avatar_file) |f| {
        var meta = media.create(
            &app_state.conn,
            allocator,
            info.?.user_id,
            f.content_type orelse "application/octet-stream",
            f.data,
            null,
            now_ms,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        defer meta.deinit(allocator);
        avatar_media_id = meta.id;
    }

    if (header_file) |f| {
        var meta = media.create(
            &app_state.conn,
            allocator,
            info.?.user_id,
            f.content_type orelse "application/octet-stream",
            f.data,
            null,
            now_ms,
        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        defer meta.deinit(allocator);
        header_media_id = meta.id;
    }

    const profile_changed =
        !std.mem.eql(u8, display_name, user.?.display_name) or
        !std.mem.eql(u8, note, user.?.note) or
        avatar_media_id != user.?.avatar_media_id or
        header_media_id != user.?.header_media_id;

    const updated = users.updateProfile(
        &app_state.conn,
        info.?.user_id,
        display_name,
        note,
        avatar_media_id,
        header_media_id,
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!updated) return common.unauthorized(allocator);

    app_state.conn.execZ("COMMIT;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    committed = true;

    const one_day_ms: i64 = 24 * 60 * 60 * 1000;
    _ = media.pruneOrphansOlderThan(&app_state.conn, now_ms - one_day_ms) catch 0;

    if (profile_changed) {
        background.deliverActorUpdate(app_state, allocator, info.?.user_id);
    }

    const updated_user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (updated_user == null) return common.unauthorized(allocator);

    return accountCredentialsByUser(app_state, allocator, updated_user.?);
}

pub fn lookup(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    const acct_param = common.parseQueryParam(allocator, q, "acct") catch
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

pub fn accountCredentialsByUser(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) http_types.Response {
    const payload: AccountCredentialsPayload = masto.makeAccountCredentialsPayload(app_state, allocator, user);

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn accountByUser(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) http_types.Response {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const user_url = urls.userUrlAlloc(app_state, allocator, user.username) catch "";
    const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, user);
    const header_url = urls.userHeaderUrlAlloc(app_state, allocator, user);
    const note_html = util_html.textToHtmlAlloc(allocator, user.note) catch user.note;

    const payload: masto.AccountPayload = .{
        .id = id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = user.display_name,
        .note = note_html,
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

pub fn apiV2Search(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    const q_param = common.parseQueryParam(allocator, q, "q") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };

    const query_raw = q_param orelse return common.jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    const query_trimmed = std.mem.trim(u8, query_raw, " \t\r\n");
    if (query_trimmed.len == 0) return common.jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    var accounts: std.ArrayListUnmanaged(masto.AccountPayload) = .empty;
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

    return common.jsonOk(allocator, .{
        .accounts = accounts.items,
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });
}

pub fn accountGet(app_state: *app.App, allocator: std.mem.Allocator, path: []const u8) http_types.Response {
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

        return common.jsonOk(allocator, makeRemoteAccountPayload(app_state, allocator, id_str, actor.?));
    }

    const user = users.lookupUserById(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    return accountByUser(app_state, allocator, user.?);
}

pub fn accountRelationships(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const q = common.queryString(req.target);

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

    return common.jsonOk(allocator, rels.items);
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

pub fn accountFollow(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

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
        return common.jsonOk(allocator, relationshipPayload(id_part, null));
    }

    const rowid = account_id - remote_actor_id_base;
    if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

    const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

    const existing = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (existing) |f| {
        return common.jsonOk(allocator, relationshipPayload(id_part, f.state));
    }

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
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
                return common.jsonOk(allocator, relationshipPayload(id_part, existing_follow.state));
            }
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        },
    };

    background.sendFollow(app_state, allocator, info.?.user_id, actor.?.id, follow_activity_id);

    return common.jsonOk(allocator, relationshipPayload(id_part, .pending));
}

pub fn accountUnfollow(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

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
        return common.jsonOk(allocator, relationshipPayload(id_part, null));
    }

    const rowid = account_id - remote_actor_id_base;
    if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

    const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

    const existing = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (existing == null) {
        return common.jsonOk(allocator, relationshipPayload(id_part, null));
    }

    _ = follows.deleteByUserAndRemoteActorId(&app_state.conn, info.?.user_id, actor.?.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    background.sendUndoFollow(app_state, allocator, info.?.user_id, actor.?.id, existing.?.follow_activity_id);

    return common.jsonOk(allocator, relationshipPayload(id_part, null));
}

pub fn accountStatuses(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
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
        return common.jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = common.queryString(req.target);
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
        return common.jsonOk(allocator, [_]i32{});
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
        const token = common.bearerToken(req.authorization) orelse break :blk false;
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch break :blk false;
        if (info == null) break :blk false;
        break :blk info.?.user_id == user.?.id;
    };

    const list = statuses.listByUser(&app_state.conn, allocator, user.?.id, limit, max_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads: std.ArrayListUnmanaged(masto.StatusPayload) = .empty;
    defer payloads.deinit(allocator);

    for (list) |st| {
        if (!include_all and !isPubliclyVisibleVisibility(st.visibility)) continue;
        payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, user.?, st)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    const body = std.json.Stringify.valueAlloc(allocator, payloads.items, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn accountFollowers(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
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
        return common.jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = common.queryString(req.target);
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

    return common.jsonOk(allocator, accounts.items);
}

pub fn accountFollowing(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
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
        return common.jsonOk(allocator, [_]i32{});
    }

    const user = users.lookupUserById(&app_state.conn, allocator, account_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const q = common.queryString(req.target);
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

    return common.jsonOk(allocator, accounts.items);
}

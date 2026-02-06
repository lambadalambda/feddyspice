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
const remote_statuses = @import("../remote_statuses.zig");
const status_interactions = @import("../status_interactions.zig");
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

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn parseLimit(query: *const form.Form, default_value: usize) usize {
    const raw = query.get("limit") orelse return default_value;
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return default_value;
    return @min(@max(parsed, 1), 40);
}

fn parseOffset(query: *const form.Form) usize {
    const raw = query.get("offset") orelse return 0;
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return 0;
    return parsed;
}

fn wantsType(query: *const form.Form, typ: []const u8) bool {
    const raw = query.get("type") orelse return true;
    if (raw.len == 0) return true;
    return std.mem.eql(u8, raw, typ);
}

fn isResolveEnabled(query: *const form.Form) bool {
    const raw = query.get("resolve") orelse return false;
    if (raw.len == 0) return false;
    return std.ascii.eqlIgnoreCase(raw, "true") or std.ascii.eqlIgnoreCase(raw, "1") or std.ascii.eqlIgnoreCase(raw, "yes");
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
    const viewer_user_id: ?i64 = blk: {
        if (req.authorization == null) break :blk null;
        const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (info == null) return common.unauthorized(allocator);
        break :blk info.?.user_id;
    };

    const q = common.queryString(req.target);
    var query = form.parse(allocator, q) catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    defer query.deinit(allocator);

    const query_raw = query.get("q") orelse return common.jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    const query_trimmed = std.mem.trim(u8, query_raw, " \t\r\n");
    const query_norm = if (query_trimmed.len > 0 and query_trimmed[0] == '@') query_trimmed[1..] else query_trimmed;
    if (query_trimmed.len == 0) return common.jsonOk(allocator, .{
        .accounts = [_]i32{},
        .statuses = [_]i32{},
        .hashtags = [_]i32{},
    });

    const limit = parseLimit(&query, 20);
    const offset = parseOffset(&query);
    const resolve = isResolveEnabled(&query);

    var accounts_all: std.ArrayListUnmanaged(AccountPayload) = .empty;
    defer accounts_all.deinit(allocator);

    if (wantsType(&query, "accounts")) {
        const user = users.lookupFirstUser(&app_state.conn, allocator) catch null;
        if (user) |u| {
            var matches = containsAsciiIgnoreCase(u.username, query_norm) or
                containsAsciiIgnoreCase(u.display_name, query_norm);

            if (!matches) {
                if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| {
                    const name = query_norm[0..at];
                    const dom = query_norm[at + 1 ..];
                    if (dom.len > 0 and std.ascii.eqlIgnoreCase(dom, app_state.cfg.domain)) {
                        matches = containsAsciiIgnoreCase(u.username, name);
                    }
                }
            }

            if (matches) {
                const user_url = urls.userUrlAlloc(app_state, allocator, u.username) catch "";
                const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, u);
                const header_url = urls.userHeaderUrlAlloc(app_state, allocator, u);
                const note_html = util_html.textToHtmlAlloc(allocator, u.note) catch u.note;

                const id_str = std.fmt.allocPrint(allocator, "{d}", .{u.id}) catch "0";
                accounts_all.append(allocator, .{
                    .id = id_str,
                    .username = u.username,
                    .acct = u.username,
                    .display_name = u.display_name,
                    .note = note_html,
                    .url = user_url,
                    .locked = false,
                    .bot = false,
                    .group = false,
                    .discoverable = true,
                    .created_at = u.created_at,
                    .followers_count = 0,
                    .following_count = 0,
                    .statuses_count = 0,
                    .avatar = avatar_url,
                    .avatar_static = avatar_url,
                    .header = header_url,
                    .header_static = header_url,
                }) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            }
        }

        // If it looks like an acct handle and resolve is enabled (or a likely full domain), try WebFinger.
        if (!std.mem.startsWith(u8, query_norm, "http://") and !std.mem.startsWith(u8, query_norm, "https://")) {
            if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| {
                const name = query_norm[0..at];
                const dom = query_norm[at + 1 ..];
                if (name.len > 0 and dom.len > 0 and !std.ascii.eqlIgnoreCase(dom, app_state.cfg.domain)) {
                    if (resolve or std.mem.indexOfScalar(u8, dom, '.') != null) {
                        const actor = federation.resolveRemoteActorByHandle(app_state, allocator, query_norm) catch null;
                        if (actor) |a| {
                            const api_id = remoteAccountApiIdAlloc(app_state, allocator, a.id);
                            accounts_all.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, a)) catch
                                return .{ .status = .internal_server_error, .body = "internal server error\n" };
                        }
                    }
                }
            }
        }

        // Partial search over known remote actors.
        const max_fetch: i64 = @intCast(@min(offset + limit + 4, 200));
        if (max_fetch > 0) {
            const user_part: []const u8 = blk: {
                if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| break :blk query_norm[0..at];
                break :blk query_norm;
            };
            const dom_part: ?[]const u8 = blk: {
                if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| {
                    const rest = query_norm[at + 1 ..];
                    if (rest.len > 0) break :blk rest;
                }
                break :blk null;
            };

            const p_user = std.fmt.allocPrint(allocator, "%{s}%", .{user_part}) catch "%";
            const p_dom = if (dom_part) |d| std.fmt.allocPrint(allocator, "%{s}%", .{d}) catch "%" else null;

            var stmt = blk: {
                if (dom_part != null and user_part.len > 0) {
                    break :blk app_state.conn.prepareZ(
                        "SELECT id FROM remote_actors WHERE preferred_username LIKE ?1 AND domain LIKE ?2 ORDER BY preferred_username ASC, domain ASC LIMIT ?3;\x00",
                    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                }
                break :blk app_state.conn.prepareZ(
                    "SELECT id FROM remote_actors WHERE preferred_username LIKE ?1 OR domain LIKE ?1 ORDER BY preferred_username ASC, domain ASC LIMIT ?2;\x00",
                ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            };
            defer stmt.finalize();

            if (dom_part != null and user_part.len > 0) {
                stmt.bindText(1, p_user) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                stmt.bindText(2, p_dom.?) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                stmt.bindInt64(3, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            } else {
                stmt.bindText(1, p_user) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                stmt.bindInt64(2, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            }

            while (true) {
                switch (stmt.step() catch return .{ .status = .internal_server_error, .body = "internal server error\n" }) {
                    .done => break,
                    .row => {
                        const actor_id = stmt.columnText(0);
                        var seen = false;
                        for (accounts_all.items) |acct| {
                            if (std.mem.eql(u8, acct.url, actor_id)) {
                                seen = true;
                                break;
                            }
                        }
                        if (seen) continue;

                        const actor = remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" };
                        if (actor == null) continue;

                        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
                        accounts_all.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, actor.?)) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    },
                }
            }
        }

        std.sort.block(AccountPayload, accounts_all.items, {}, struct {
            fn lessThan(_: void, a: AccountPayload, b: AccountPayload) bool {
                if (std.ascii.lessThanIgnoreCase(a.acct, b.acct)) return true;
                if (std.ascii.lessThanIgnoreCase(b.acct, a.acct)) return false;
                return std.ascii.lessThanIgnoreCase(a.id, b.id);
            }
        }.lessThan);
    }

    const accounts_slice = blk: {
        if (!wantsType(&query, "accounts")) break :blk accounts_all.items[0..0];
        const start = @min(offset, accounts_all.items.len);
        const end = @min(start + limit, accounts_all.items.len);
        break :blk accounts_all.items[start..end];
    };

    var statuses_all: std.ArrayListUnmanaged(StatusPayload) = .empty;
    defer statuses_all.deinit(allocator);

    if (wantsType(&query, "statuses")) {
        const max_fetch: i64 = @intCast(@min(offset + limit + 4, 200));
        if (max_fetch > 0) {
            const user = blk: {
                if (viewer_user_id) |uid| {
                    const u = users.lookupUserById(&app_state.conn, allocator, uid) catch null;
                    break :blk u;
                }
                break :blk users.lookupFirstUser(&app_state.conn, allocator) catch null;
            };

            if (user) |u| {
                const pattern = std.fmt.allocPrint(allocator, "%{s}%", .{query_trimmed}) catch "%";

                var stmt = blk: {
                    if (viewer_user_id != null) {
                        break :blk app_state.conn.prepareZ(
                            "SELECT id, user_id, in_reply_to_id, text, visibility, created_at\n" ++
                                "FROM statuses\n" ++
                                "WHERE user_id = ?1 AND deleted_at IS NULL AND text LIKE ?2\n" ++
                                "ORDER BY created_at DESC, id DESC\n" ++
                                "LIMIT ?3;\x00",
                        ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    }

                    break :blk app_state.conn.prepareZ(
                        "SELECT id, user_id, in_reply_to_id, text, visibility, created_at\n" ++
                            "FROM statuses\n" ++
                            "WHERE user_id = ?1 AND deleted_at IS NULL AND visibility = 'public' AND text LIKE ?2\n" ++
                            "ORDER BY created_at DESC, id DESC\n" ++
                            "LIMIT ?3;\x00",
                    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                };
                defer stmt.finalize();

                stmt.bindInt64(1, u.id) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                stmt.bindText(2, pattern) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                stmt.bindInt64(3, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

                while (true) {
                    switch (stmt.step() catch return .{ .status = .internal_server_error, .body = "internal server error\n" }) {
                        .done => break,
                        .row => {
                            const st: statuses.Status = .{
                                .id = stmt.columnInt64(0),
                                .user_id = stmt.columnInt64(1),
                                .in_reply_to_id = if (stmt.columnType(2) == .null) null else stmt.columnInt64(2),
                                .text = allocator.dupe(u8, stmt.columnText(3)) catch "",
                                .visibility = allocator.dupe(u8, stmt.columnText(4)) catch "public",
                                .created_at = allocator.dupe(u8, stmt.columnText(5)) catch "1970-01-01T00:00:00.000Z",
                                .deleted_at = null,
                            };

                            const p = if (viewer_user_id) |vid|
                                masto.makeStatusPayloadForViewer(app_state, allocator, u, st, vid)
                            else
                                masto.makeStatusPayload(app_state, allocator, u, st);
                            statuses_all.append(allocator, p) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                        },
                    }
                }
            }

            const pattern_html = std.fmt.allocPrint(allocator, "%{s}%", .{query_trimmed}) catch "%";

            var stmt_remote = blk: {
                if (viewer_user_id != null) {
                    break :blk app_state.conn.prepareZ(
                        "SELECT id, remote_uri, remote_actor_id, in_reply_to_id, content_html, attachments_json, visibility, created_at\n" ++
                            "FROM remote_statuses\n" ++
                            "WHERE deleted_at IS NULL AND content_html LIKE ?1\n" ++
                            "ORDER BY created_at DESC, id DESC\n" ++
                            "LIMIT ?2;\x00",
                    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                }

                break :blk app_state.conn.prepareZ(
                    "SELECT id, remote_uri, remote_actor_id, in_reply_to_id, content_html, attachments_json, visibility, created_at\n" ++
                        "FROM remote_statuses\n" ++
                        "WHERE deleted_at IS NULL AND visibility = 'public' AND content_html LIKE ?1\n" ++
                        "ORDER BY created_at DESC, id DESC\n" ++
                        "LIMIT ?2;\x00",
                ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            };
            defer stmt_remote.finalize();

            stmt_remote.bindText(1, pattern_html) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            stmt_remote.bindInt64(2, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

            while (true) {
                switch (stmt_remote.step() catch return .{ .status = .internal_server_error, .body = "internal server error\n" }) {
                    .done => break,
                    .row => {
                        const st: remote_statuses.RemoteStatus = .{
                            .id = stmt_remote.columnInt64(0),
                            .remote_uri = allocator.dupe(u8, stmt_remote.columnText(1)) catch "",
                            .remote_actor_id = allocator.dupe(u8, stmt_remote.columnText(2)) catch "",
                            .in_reply_to_id = if (stmt_remote.columnType(3) == .null) null else stmt_remote.columnInt64(3),
                            .content_html = allocator.dupe(u8, stmt_remote.columnText(4)) catch "",
                            .attachments_json = if (stmt_remote.columnType(5) == .null) null else allocator.dupe(u8, stmt_remote.columnText(5)) catch null,
                            .visibility = allocator.dupe(u8, stmt_remote.columnText(6)) catch "public",
                            .created_at = allocator.dupe(u8, stmt_remote.columnText(7)) catch "1970-01-01T00:00:00.000Z",
                            .deleted_at = null,
                        };

                        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.remote_actor_id) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" };
                        if (actor == null) continue;

                        const p = if (viewer_user_id) |vid|
                            masto.makeRemoteStatusPayloadForViewer(app_state, allocator, actor.?, st, vid)
                        else
                            masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st);
                        statuses_all.append(allocator, p) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    },
                }
            }
        }

        std.sort.block(StatusPayload, statuses_all.items, {}, masto.statusPayloadNewerFirst);
    }

    const statuses_slice = blk: {
        if (!wantsType(&query, "statuses")) break :blk statuses_all.items[0..0];
        const start = @min(offset, statuses_all.items.len);
        const end = @min(start + limit, statuses_all.items.len);
        break :blk statuses_all.items[start..end];
    };

    return common.jsonOk(allocator, .{
        .accounts = accounts_slice,
        .statuses = statuses_slice,
        .hashtags = [_]i32{},
    });
}

pub fn apiV1Search(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    return apiV2Search(app_state, allocator, req);
}

pub fn apiV1AccountsSearch(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    var query = form.parse(allocator, q) catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    defer query.deinit(allocator);

    const query_raw = query.get("q") orelse return common.jsonOk(allocator, [_]i32{});
    const query_trimmed = std.mem.trim(u8, query_raw, " \t\r\n");
    if (query_trimmed.len == 0) return common.jsonOk(allocator, [_]i32{});

    const query_norm = if (query_trimmed.len > 0 and query_trimmed[0] == '@') query_trimmed[1..] else query_trimmed;
    const limit = parseLimit(&query, 40);
    const offset = parseOffset(&query);
    const resolve = isResolveEnabled(&query);

    var accounts_all: std.ArrayListUnmanaged(AccountPayload) = .empty;
    defer accounts_all.deinit(allocator);

    const user = users.lookupFirstUser(&app_state.conn, allocator) catch null;
    if (user) |u| {
        if (containsAsciiIgnoreCase(u.username, query_norm) or containsAsciiIgnoreCase(u.display_name, query_norm)) {
            const user_url = urls.userUrlAlloc(app_state, allocator, u.username) catch "";
            const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, u);
            const header_url = urls.userHeaderUrlAlloc(app_state, allocator, u);
            const note_html = util_html.textToHtmlAlloc(allocator, u.note) catch u.note;

            const id_str = std.fmt.allocPrint(allocator, "{d}", .{u.id}) catch "0";
            accounts_all.append(allocator, .{
                .id = id_str,
                .username = u.username,
                .acct = u.username,
                .display_name = u.display_name,
                .note = note_html,
                .url = user_url,
                .locked = false,
                .bot = false,
                .group = false,
                .discoverable = true,
                .created_at = u.created_at,
                .followers_count = 0,
                .following_count = 0,
                .statuses_count = 0,
                .avatar = avatar_url,
                .avatar_static = avatar_url,
                .header = header_url,
                .header_static = header_url,
            }) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    if (!std.mem.startsWith(u8, query_norm, "http://") and !std.mem.startsWith(u8, query_norm, "https://")) {
        if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| {
            const name = query_norm[0..at];
            const dom = query_norm[at + 1 ..];
            if (name.len > 0 and dom.len > 0 and !std.ascii.eqlIgnoreCase(dom, app_state.cfg.domain)) {
                if (resolve or std.mem.indexOfScalar(u8, dom, '.') != null) {
                    const actor = federation.resolveRemoteActorByHandle(app_state, allocator, query_norm) catch null;
                    if (actor) |a| {
                        const api_id = remoteAccountApiIdAlloc(app_state, allocator, a.id);
                        accounts_all.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, a)) catch
                            return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    }
                }
            }
        }
    }

    const max_fetch: i64 = @intCast(@min(offset + limit + 4, 200));
    if (max_fetch > 0) {
        const user_part: []const u8 = blk: {
            if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| break :blk query_norm[0..at];
            break :blk query_norm;
        };
        const dom_part: ?[]const u8 = blk: {
            if (std.mem.indexOfScalar(u8, query_norm, '@')) |at| {
                const rest = query_norm[at + 1 ..];
                if (rest.len > 0) break :blk rest;
            }
            break :blk null;
        };

        const p_user = std.fmt.allocPrint(allocator, "%{s}%", .{user_part}) catch "%";
        const p_dom = if (dom_part) |d| std.fmt.allocPrint(allocator, "%{s}%", .{d}) catch "%" else null;

        var stmt = blk: {
            if (dom_part != null and user_part.len > 0) {
                break :blk app_state.conn.prepareZ(
                    "SELECT id FROM remote_actors WHERE preferred_username LIKE ?1 AND domain LIKE ?2 ORDER BY preferred_username ASC, domain ASC LIMIT ?3;\x00",
                ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            }
            break :blk app_state.conn.prepareZ(
                "SELECT id FROM remote_actors WHERE preferred_username LIKE ?1 OR domain LIKE ?1 ORDER BY preferred_username ASC, domain ASC LIMIT ?2;\x00",
            ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        };
        defer stmt.finalize();

        if (dom_part != null and user_part.len > 0) {
            stmt.bindText(1, p_user) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            stmt.bindText(2, p_dom.?) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            stmt.bindInt64(3, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else {
            stmt.bindText(1, p_user) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
            stmt.bindInt64(2, max_fetch) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        while (true) {
            switch (stmt.step() catch return .{ .status = .internal_server_error, .body = "internal server error\n" }) {
                .done => break,
                .row => {
                    const actor_id = stmt.columnText(0);
                    var seen = false;
                    for (accounts_all.items) |acct| {
                        if (std.mem.eql(u8, acct.url, actor_id)) {
                            seen = true;
                            break;
                        }
                    }
                    if (seen) continue;

                    const actor = remote_actors.lookupById(&app_state.conn, allocator, actor_id) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" };
                    if (actor == null) continue;

                    const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.?.id);
                    accounts_all.append(allocator, makeRemoteAccountPayload(app_state, allocator, api_id, actor.?)) catch
                        return .{ .status = .internal_server_error, .body = "internal server error\n" };
                },
            }
        }
    }

    std.sort.block(AccountPayload, accounts_all.items, {}, struct {
        fn lessThan(_: void, a: AccountPayload, b: AccountPayload) bool {
            if (std.ascii.lessThanIgnoreCase(a.acct, b.acct)) return true;
            if (std.ascii.lessThanIgnoreCase(b.acct, a.acct)) return false;
            return std.ascii.lessThanIgnoreCase(a.id, b.id);
        }
    }.lessThan);

    const start = @min(offset, accounts_all.items.len);
    const end = @min(start + limit, accounts_all.items.len);
    return common.jsonOk(allocator, accounts_all.items[start..end]);
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
    const key_aliases = [_][]const u8{ "id", "id[]", "id%5B%5D" };
    const ids = common.collectQueryValuesForKeys(allocator, q, &key_aliases) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    defer allocator.free(ids);

    var rels: std.ArrayListUnmanaged(RelationshipPayload) = .empty;
    defer rels.deinit(allocator);

    for (ids) |id_str| {
        var state: ?follows.FollowState = null;

        const id_num = std.fmt.parseInt(i64, id_str, 10) catch null;
        if (id_num != null and id_num.? >= remote_actor_id_base) {
            const rowid = id_num.? - remote_actor_id_base;
            if (rowid > 0) {
                const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch null;
                if (actor) |a| {
                    const f = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, a.id) catch null;
                    if (f) |follow| {
                        state = follow.state;
                    }
                }
            }
        }

        rels.append(allocator, relationshipPayload(id_str, state)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, rels.items);
}

const RelationshipPayload = struct {
    id: []const u8,
    following: bool,
    followed_by: bool = false,
    requested: bool,
    blocking: bool = false,
    muting: bool = false,
};

fn relationshipPayload(id: []const u8, state: ?follows.FollowState) RelationshipPayload {
    const following = state != null and state.? == .accepted;
    const requested = state != null and state.? == .pending;
    return .{ .id = id, .following = following, .requested = requested };
}

pub fn accountBlockMuteNoop(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    req: http_types.Request,
    path: []const u8,
    suffix: []const u8,
) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/accounts/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    if (id_part.len == 0) return .{ .status = .not_found, .body = "not found\n" };
    if (std.mem.indexOfScalar(u8, id_part, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const account_id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    var state: ?follows.FollowState = null;
    if (account_id >= remote_actor_id_base) {
        const rowid = account_id - remote_actor_id_base;
        if (rowid <= 0) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupByRowId(&app_state.conn, allocator, rowid) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        const f = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.?.id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (f) |follow| state = follow.state;
    }

    var rel = relationshipPayload(id_part, state);
    if (std.mem.eql(u8, suffix, "/block")) rel.blocking = true;
    if (std.mem.eql(u8, suffix, "/mute")) rel.muting = true;
    return common.jsonOk(allocator, rel);
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

    if (pinned) {
        const pinned_ids = status_interactions.listPinnedStatusIds(&app_state.conn, allocator, user.?.id, limit) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        var payloads: std.ArrayListUnmanaged(masto.StatusPayload) = .empty;
        defer payloads.deinit(allocator);

        for (pinned_ids) |sid| {
            if (max_id != null and sid >= max_id.?) continue;

            const st = statuses.lookup(&app_state.conn, allocator, sid) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (st == null) continue;

            if (!include_all and !isPubliclyVisibleVisibility(st.?.visibility)) continue;

            payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, user.?, st.?)) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }

        const body = std.json.Stringify.valueAlloc(allocator, payloads.items, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        return .{
            .content_type = "application/json; charset=utf-8",
            .body = body,
        };
    }

    if (only_media) {
        return common.jsonOk(allocator, [_]i32{});
    }

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

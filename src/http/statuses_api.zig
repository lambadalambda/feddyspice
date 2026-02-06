const std = @import("std");

const app = @import("../app.zig");
const background = @import("../background.zig");
const common = @import("common.zig");
const db = @import("../db.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const media = @import("../media.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const status_interactions = @import("../status_interactions.zig");
const status_reactions = @import("../status_reactions.zig");
const statuses = @import("../statuses.zig");
const util_ids = @import("../util/ids.zig");
const util_html = @import("../util/html.zig");
const util_url = @import("../util/url.zig");
const users = @import("../users.zig");

const StatusPayload = masto.StatusPayload;

fn isPublicishVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}

pub fn statusesBulkGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const viewer_user_id: ?i64 = blk: {
        if (req.authorization == null) break :blk null;
        const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (info == null) return common.unauthorized(allocator);
        break :blk info.?.user_id;
    };

    const q = common.queryString(req.target);
    const key_aliases = [_][]const u8{ "ids", "ids[]", "ids%5B%5D" };
    const ids = common.collectQueryValuesForKeys(allocator, q, &key_aliases) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    defer allocator.free(ids);

    var payloads: std.ArrayListUnmanaged(StatusPayload) = .empty;
    defer payloads.deinit(allocator);

    for (ids) |id_str| {
        const id = std.fmt.parseInt(i64, id_str, 10) catch continue;

        if (id < 0) {
            const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (st == null) continue;

            const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (actor == null) continue;
            if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) continue;

            const payload = if (viewer_user_id) |vid|
                masto.makeRemoteStatusPayloadForViewer(app_state, allocator, actor.?, st.?, vid)
            else
                masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st.?);
            payloads.append(allocator, payload) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else {
            const st = statuses.lookup(&app_state.conn, allocator, id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (st == null) continue;
            if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) continue;

            const author = users.lookupUserById(&app_state.conn, allocator, st.?.user_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (author == null) continue;

            const payload = if (viewer_user_id) |vid|
                masto.makeStatusPayloadForViewer(app_state, allocator, author.?, st.?, vid)
            else
                masto.makeStatusPayload(app_state, allocator, author.?, st.?);
            payloads.append(allocator, payload) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        }
    }

    return common.jsonOk(allocator, payloads.items);
}

fn listThreadDescendantIds(
    conn: *db.Db,
    allocator: std.mem.Allocator,
    root_id: i64,
    limit: usize,
) (db.Error || std.mem.Allocator.Error)![]i64 {
    const lim: i64 = @intCast(@min(limit, 200));

    var stmt = try conn.prepareZ(
        \\WITH RECURSIVE descendants(id, created_at) AS (
        \\  SELECT id, created_at FROM statuses WHERE in_reply_to_id = ?1 AND deleted_at IS NULL
        \\  UNION ALL
        \\  SELECT id, created_at FROM remote_statuses WHERE in_reply_to_id = ?1 AND deleted_at IS NULL
        \\  UNION ALL
        \\  SELECT s.id, s.created_at FROM statuses s JOIN descendants d ON s.in_reply_to_id = d.id WHERE s.deleted_at IS NULL
        \\  UNION ALL
        \\  SELECT r.id, r.created_at FROM remote_statuses r JOIN descendants d ON r.in_reply_to_id = d.id WHERE r.deleted_at IS NULL
        \\)
        \\SELECT id FROM descendants ORDER BY created_at ASC, id ASC LIMIT ?2;
    ++ "\x00",
    );
    defer stmt.finalize();

    try stmt.bindInt64(1, root_id);
    try stmt.bindInt64(2, lim);

    var out: std.ArrayListUnmanaged(i64) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        switch (try stmt.step()) {
            .done => break,
            .row => {
                out.append(allocator, stmt.columnInt64(0)) catch
                    return error.OutOfMemory;
            },
        }
    }

    return out.toOwnedSlice(allocator);
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
    const max_attachments: usize = 4;

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
            if (!util_url.isHttpOrHttpsUrl(url)) return;

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
        .array => |arr| {
            for (arr.items) |item| {
                if (list.items.len >= max_attachments) break;
                try helper.pushOne(allocator, &list, item);
            }
        },
        else => try helper.pushOne(allocator, &list, val),
    }

    if (list.items.len == 0) return null;
    const json = try std.json.Stringify.valueAlloc(allocator, list.items, .{});
    return json;
}

pub fn statusAccountsListEmpty(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const suffix = if (std.mem.endsWith(u8, path, "/reblogged_by"))
        "/reblogged_by"
    else if (std.mem.endsWith(u8, path, "/favourited_by"))
        "/favourited_by"
    else
        return .{ .status = .not_found, .body = "not found\n" };

    const kind = if (std.mem.eql(u8, suffix, "/reblogged_by")) "reblog" else "favourite";

    const id_part = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        return common.jsonOk(allocator, [_]i32{});
    } else {
        const st = statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
        if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };
    }

    const actors = status_reactions.listActiveRemoteActors(&app_state.conn, allocator, id, kind, 80) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var accounts: std.ArrayListUnmanaged(masto.AccountPayload) = .empty;
    defer accounts.deinit(allocator);

    for (actors) |actor| {
        const api_id = util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor.id);
        accounts.append(allocator, masto.makeRemoteAccountPayload(app_state, allocator, api_id, actor)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, accounts.items);
}

pub fn statusHistoryEmpty(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    const suffix = "/history";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    } else {
        const st = statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    }

    return common.jsonOk(allocator, [_]i32{});
}

pub fn statusSource(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/statuses/";
    const suffix = "/source";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_part = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) return .{ .status = .not_found, .body = "not found\n" };

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };

    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const payload = .{
        .id = id_part,
        .text = st.?.text,
        .spoiler_text = "",
    };
    return common.jsonOk(allocator, payload);
}

pub fn createStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const max_media_attachments: i64 = 4;

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const text_opt = parsed.get("status");
    const text = text_opt orelse "";
    const visibility = parsed.get("visibility") orelse "public";
    const media_ids_raw = parsed.get("media_ids[]") orelse parsed.get("media_ids");
    const in_reply_to_raw = parsed.get("in_reply_to_id");

    const in_reply_to_id: ?i64 = blk: {
        const raw = in_reply_to_raw orelse break :blk null;
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) break :blk null;

        const rid = std.fmt.parseInt(i64, trimmed, 10) catch
            return .{ .status = .unprocessable_entity, .body = "invalid in_reply_to_id\n" };
        if (rid == 0) return .{ .status = .unprocessable_entity, .body = "invalid in_reply_to_id\n" };

        if (rid < 0) {
            const parent = remote_statuses.lookup(&app_state.conn, allocator, rid) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (parent == null) return .{ .status = .unprocessable_entity, .body = "invalid in_reply_to_id\n" };
        } else {
            const parent = statuses.lookup(&app_state.conn, allocator, rid) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (parent == null) return .{ .status = .unprocessable_entity, .body = "invalid in_reply_to_id\n" };
        }

        break :blk rid;
    };

    const has_media = blk: {
        const raw = media_ids_raw orelse break :blk false;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |id_str| {
            if (id_str.len == 0) continue;
            break :blk true;
        }
        break :blk false;
    };

    const has_text = std.mem.trim(u8, text, " \t\r\n").len > 0;
    if (text_opt == null and !has_media) return .{ .status = .bad_request, .body = "missing status\n" };
    if (!has_text and !has_media) return .{ .status = .unprocessable_entity, .body = "invalid status\n" };

    app_state.conn.execZ("BEGIN IMMEDIATE;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    var committed = false;
    defer if (!committed) {
        app_state.conn.execZ("ROLLBACK;\x00") catch {};
    };

    const st = statuses.create(&app_state.conn, allocator, info.?.user_id, text, visibility, in_reply_to_id) catch |err| switch (err) {
        error.InvalidText => return .{ .status = .unprocessable_entity, .body = "invalid status\n" },
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    if (media_ids_raw) |raw| {
        var pos: i64 = 0;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |id_str| {
            if (id_str.len == 0) continue;
            if (pos >= max_media_attachments) {
                return .{ .status = .unprocessable_entity, .body = "too many media\n" };
            }
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
    if (user == null) return common.unauthorized(allocator);

    background.deliverStatusToFollowers(app_state, allocator, info.?.user_id, st.id);

    const resp = statusResponse(app_state, allocator, info.?.user_id, user.?, st);
    app_state.streaming.publishUpdate(info.?.user_id, resp.body);
    return resp;
}

pub fn getStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const viewer_user_id: ?i64 = blk: {
        if (req.authorization == null) break :blk null;
        const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (info == null) return common.unauthorized(allocator);
        break :blk info.?.user_id;
    };

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };
        if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) return .{ .status = .not_found, .body = "not found\n" };

        return remoteStatusResponse(app_state, allocator, viewer_user_id, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) return .{ .status = .not_found, .body = "not found\n" };

    const author = users.lookupUserById(&app_state.conn, allocator, st.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (author == null) return .{ .status = .not_found, .body = "not found\n" };

    return statusResponse(app_state, allocator, viewer_user_id, author.?, st.?);
}

pub fn statusContext(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const viewer_user_id: ?i64 = blk: {
        if (req.authorization == null) break :blk null;
        const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
        const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (info == null) return common.unauthorized(allocator);
        break :blk info.?.user_id;
    };

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
        if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) return .{ .status = .not_found, .body = "not found\n" };
    } else {
        const st = statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };
        if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) return .{ .status = .not_found, .body = "not found\n" };
    }

    var ancestors: std.ArrayListUnmanaged(StatusPayload) = .empty;
    defer ancestors.deinit(allocator);

    var cur_id: i64 = id;
    var depth: usize = 0;
    while (depth < 50) : (depth += 1) {
        const parent_id_opt: ?i64 = blk: {
            if (cur_id < 0) {
                const cur = remote_statuses.lookup(&app_state.conn, allocator, cur_id) catch
                    return .{ .status = .internal_server_error, .body = "internal server error\n" };
                if (cur == null) break :blk null;
                break :blk cur.?.in_reply_to_id;
            }

            const cur = statuses.lookup(&app_state.conn, allocator, cur_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (cur == null) break :blk null;
            break :blk cur.?.in_reply_to_id;
        };

        const parent_id = parent_id_opt orelse break;

        if (parent_id < 0) {
            const parent_st = remote_statuses.lookup(&app_state.conn, allocator, parent_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (parent_st == null) break;
            if (viewer_user_id == null and !isPublicishVisibility(parent_st.?.visibility)) break;

            const actor = remote_actors.lookupById(&app_state.conn, allocator, parent_st.?.remote_actor_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (actor == null) break;

            const payload = if (viewer_user_id) |vid|
                masto.makeRemoteStatusPayloadForViewer(app_state, allocator, actor.?, parent_st.?, vid)
            else
                masto.makeRemoteStatusPayload(app_state, allocator, actor.?, parent_st.?);
            ancestors.append(allocator, payload) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };

            cur_id = parent_id;
            continue;
        }

        const parent_st = statuses.lookup(&app_state.conn, allocator, parent_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (parent_st == null) break;
        if (viewer_user_id) |vid| {
            if (parent_st.?.user_id != vid) break;
        } else if (!isPublicishVisibility(parent_st.?.visibility)) {
            break;
        }

        const author = users.lookupUserById(&app_state.conn, allocator, parent_st.?.user_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (author == null) break;

        const payload = if (viewer_user_id) |vid|
            masto.makeStatusPayloadForViewer(app_state, allocator, author.?, parent_st.?, vid)
        else
            masto.makeStatusPayload(app_state, allocator, author.?, parent_st.?);
        ancestors.append(allocator, payload) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        cur_id = parent_id;
    }

    std.mem.reverse(StatusPayload, ancestors.items);

    var descendants: std.ArrayListUnmanaged(StatusPayload) = .empty;
    defer descendants.deinit(allocator);

    const desc_ids = listThreadDescendantIds(&app_state.conn, allocator, id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    for (desc_ids) |desc_id| {
        if (desc_id < 0) {
            const st = remote_statuses.lookup(&app_state.conn, allocator, desc_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (st == null) continue;
            if (viewer_user_id == null and !isPublicishVisibility(st.?.visibility)) continue;

            const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (actor == null) continue;

            const payload = if (viewer_user_id) |vid|
                masto.makeRemoteStatusPayloadForViewer(app_state, allocator, actor.?, st.?, vid)
            else
                masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st.?);
            descendants.append(allocator, payload) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            continue;
        }

        const st = statuses.lookup(&app_state.conn, allocator, desc_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) continue;
        if (viewer_user_id) |vid| {
            if (st.?.user_id != vid) continue;
        } else if (!isPublicishVisibility(st.?.visibility)) {
            continue;
        }

        const author = users.lookupUserById(&app_state.conn, allocator, st.?.user_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (author == null) continue;

        const payload = if (viewer_user_id) |vid|
            masto.makeStatusPayloadForViewer(app_state, allocator, author.?, st.?, vid)
        else
            masto.makeStatusPayload(app_state, allocator, author.?, st.?);
        descendants.append(allocator, payload) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, .{
        .ancestors = ancestors.items,
        .descendants = descendants.items,
    });
}

pub fn statusActionNoop(
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

    const prefix = "/api/v1/statuses/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    if (!std.mem.endsWith(u8, path, suffix)) return .{ .status = .not_found, .body = "not found\n" };

    const id_str = path[prefix.len .. path.len - suffix.len];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };

    const now_ms: i64 = std.time.milliTimestamp();

    if (id < 0) {
        const st = remote_statuses.lookup(&app_state.conn, allocator, id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (st == null) return .{ .status = .not_found, .body = "not found\n" };

        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.?.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) return .{ .status = .not_found, .body = "not found\n" };

        if (std.mem.eql(u8, suffix, "/favourite")) {
            status_interactions.setFavourited(&app_state.conn, info.?.user_id, id, true, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            background.sendLike(app_state, allocator, info.?.user_id, actor.?.id, st.?.remote_uri);
        } else if (std.mem.eql(u8, suffix, "/unfavourite")) {
            status_interactions.setFavourited(&app_state.conn, info.?.user_id, id, false, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            background.sendUndoLike(app_state, allocator, info.?.user_id, actor.?.id, st.?.remote_uri);
        } else if (std.mem.eql(u8, suffix, "/reblog")) {
            const publicish = std.mem.eql(u8, st.?.visibility, "public") or std.mem.eql(u8, st.?.visibility, "unlisted");
            if (!publicish) return .{ .status = .unprocessable_entity, .body = "invalid reblog\n" };
            status_interactions.setReblogged(&app_state.conn, info.?.user_id, id, true, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            background.sendAnnounce(app_state, allocator, info.?.user_id, actor.?.id, st.?.remote_uri);
        } else if (std.mem.eql(u8, suffix, "/unreblog")) {
            const publicish = std.mem.eql(u8, st.?.visibility, "public") or std.mem.eql(u8, st.?.visibility, "unlisted");
            if (!publicish) return .{ .status = .unprocessable_entity, .body = "invalid reblog\n" };
            status_interactions.setReblogged(&app_state.conn, info.?.user_id, id, false, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            background.sendUndoAnnounce(app_state, allocator, info.?.user_id, actor.?.id, st.?.remote_uri);
        } else if (std.mem.eql(u8, suffix, "/bookmark")) {
            status_interactions.setBookmarked(&app_state.conn, info.?.user_id, id, true, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else if (std.mem.eql(u8, suffix, "/unbookmark")) {
            status_interactions.setBookmarked(&app_state.conn, info.?.user_id, id, false, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else if (std.mem.eql(u8, suffix, "/mute")) {
            status_interactions.setMuted(&app_state.conn, info.?.user_id, id, true, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else if (std.mem.eql(u8, suffix, "/unmute")) {
            status_interactions.setMuted(&app_state.conn, info.?.user_id, id, false, now_ms) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
        } else if (std.mem.eql(u8, suffix, "/pin")) {
            return .{ .status = .unprocessable_entity, .body = "cannot pin\n" };
        } else if (std.mem.eql(u8, suffix, "/unpin")) {
            return .{ .status = .unprocessable_entity, .body = "cannot pin\n" };
        }

        return remoteStatusResponse(app_state, allocator, info.?.user_id, actor.?, st.?);
    }

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

    if (std.mem.eql(u8, suffix, "/favourite")) {
        status_interactions.setFavourited(&app_state.conn, info.?.user_id, id, true, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/unfavourite")) {
        status_interactions.setFavourited(&app_state.conn, info.?.user_id, id, false, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/reblog")) {
        status_interactions.setReblogged(&app_state.conn, info.?.user_id, id, true, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/unreblog")) {
        status_interactions.setReblogged(&app_state.conn, info.?.user_id, id, false, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/bookmark")) {
        status_interactions.setBookmarked(&app_state.conn, info.?.user_id, id, true, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/unbookmark")) {
        status_interactions.setBookmarked(&app_state.conn, info.?.user_id, id, false, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/pin")) {
        status_interactions.setPinned(&app_state.conn, info.?.user_id, id, true, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/unpin")) {
        status_interactions.setPinned(&app_state.conn, info.?.user_id, id, false, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/mute")) {
        status_interactions.setMuted(&app_state.conn, info.?.user_id, id, true, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    } else if (std.mem.eql(u8, suffix, "/unmute")) {
        status_interactions.setMuted(&app_state.conn, info.?.user_id, id, false, now_ms) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return statusResponse(app_state, allocator, info.?.user_id, user.?, st.?);
}

pub fn deleteStatus(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const id_str = path["/api/v1/statuses/".len..];
    const id = std.fmt.parseInt(i64, id_str, 10) catch return .{ .status = .not_found, .body = "not found\n" };
    if (id < 0) return .{ .status = .not_found, .body = "not found\n" };

    const st = statuses.lookup(&app_state.conn, allocator, id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (st == null) return .{ .status = .not_found, .body = "not found\n" };
    if (st.?.user_id != info.?.user_id) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserById(&app_state.conn, allocator, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return common.unauthorized(allocator);

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

    const resp = statusResponse(app_state, allocator, info.?.user_id, user.?, st.?);
    app_state.streaming.publishDelete(info.?.user_id, id_str);
    return resp;
}

fn statusResponse(app_state: *app.App, allocator: std.mem.Allocator, viewer_user_id: ?i64, user: users.User, st: statuses.Status) http_types.Response {
    const payload = if (viewer_user_id) |vid|
        masto.makeStatusPayloadForViewer(app_state, allocator, user, st, vid)
    else
        masto.makeStatusPayload(app_state, allocator, user, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

fn remoteStatusResponse(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    viewer_user_id: ?i64,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) http_types.Response {
    const payload = if (viewer_user_id) |vid|
        masto.makeRemoteStatusPayloadForViewer(app_state, allocator, actor, st, vid)
    else
        masto.makeRemoteStatusPayload(app_state, allocator, actor, st);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

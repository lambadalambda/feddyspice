const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const statuses = @import("../statuses.zig");
const url = @import("../util/url.zig");
const users = @import("../users.zig");

const StatusPayload = masto.StatusPayload;

fn statusPayloadIdInt(p: StatusPayload) i64 {
    return std.fmt.parseInt(i64, p.id, 10) catch 0;
}

fn isPublicTimelineVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public");
}

fn isDirectTimelineVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "direct");
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

pub fn publicTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
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
            payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, u, st)) catch return .{
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

            payloads.append(allocator, masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
                .status = .internal_server_error,
                .body = "internal server error\n",
            };
        }
    }

    std.sort.block(StatusPayload, payloads.items, {}, masto.statusPayloadNewerFirst);

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
        const base = url.baseUrlAlloc(app_state, allocator) catch
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

pub fn homeTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const q = common.queryString(req.target);
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
    if (user == null) return common.unauthorized(allocator);

    const local_list = statuses.listByUserBeforeCreatedAt(&app_state.conn, allocator, info.?.user_id, limit, before_created_at, before_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads = std.ArrayListUnmanaged(StatusPayload).empty;
    defer payloads.deinit(allocator);

    for (local_list) |st| {
        payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, user.?, st)) catch return .{
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

        payloads.append(allocator, masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
            .status = .internal_server_error,
            .body = "internal server error\n",
        };
    }

    std.sort.block(StatusPayload, payloads.items, {}, masto.statusPayloadNewerFirst);

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
        const base = url.baseUrlAlloc(app_state, allocator) catch
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

pub fn directTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const q = common.queryString(req.target);
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
    if (user == null) return common.unauthorized(allocator);

    const fetch_limit: usize = 200;

    const local_list = statuses.listByUserBeforeCreatedAt(&app_state.conn, allocator, info.?.user_id, fetch_limit, before_created_at, before_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads = std.ArrayListUnmanaged(StatusPayload).empty;
    defer payloads.deinit(allocator);

    for (local_list) |st| {
        if (!isDirectTimelineVisibility(st.visibility)) continue;
        payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, user.?, st)) catch return .{
            .status = .internal_server_error,
            .body = "internal server error\n",
        };
    }

    const remote_list = remote_statuses.listLatestBeforeCreatedAt(&app_state.conn, allocator, fetch_limit, before_created_at, before_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    for (remote_list) |st| {
        if (!isDirectTimelineVisibility(st.visibility)) continue;
        const actor = remote_actors.lookupById(&app_state.conn, allocator, st.remote_actor_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        if (actor == null) continue;

        payloads.append(allocator, masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
            .status = .internal_server_error,
            .body = "internal server error\n",
        };
    }

    std.sort.block(StatusPayload, payloads.items, {}, masto.statusPayloadNewerFirst);

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
        const base = url.baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const newest_id = statusPayloadIdInt(slice[0]);
        const oldest_id = statusPayloadIdInt(slice[slice.len - 1]);

        const next_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/direct?limit={d}&max_id={d}",
            .{ base, limit, oldest_id },
        ) catch "";
        const prev_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/direct?limit={d}&since_id={d}",
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

fn isHashtagChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn containsHashtag(text: []const u8, tag: []const u8) bool {
    if (tag.len == 0) return false;

    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] != '#') continue;
        const start = i + 1;
        if (start + tag.len > text.len) continue;

        var j: usize = 0;
        while (j < tag.len) : (j += 1) {
            if (std.ascii.toLower(text[start + j]) != std.ascii.toLower(tag[j])) break;
        }
        if (j != tag.len) continue;

        const end = start + tag.len;
        if (end < text.len and isHashtagChar(text[end])) continue;
        return true;
    }

    return false;
}

fn percentDecodePathSegmentAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, s.len);
    var o: usize = 0;

    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '%' and i + 2 < s.len) {
            const hi = fromHex(s[i + 1]) orelse return error.InvalidEncoding;
            const lo = fromHex(s[i + 2]) orelse return error.InvalidEncoding;
            out[o] = (hi << 4) | lo;
            o += 1;
            i += 2;
            continue;
        }

        out[o] = c;
        o += 1;
    }

    return out[0..o];
}

fn fromHex(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

pub fn tagTimeline(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const prefix = "/api/v1/timelines/tag/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const tag_enc = path[prefix.len..];
    if (tag_enc.len == 0 or std.mem.indexOfScalar(u8, tag_enc, '/') != null) return .{ .status = .not_found, .body = "not found\n" };

    const tag = percentDecodePathSegmentAlloc(allocator, tag_enc) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const q = common.queryString(req.target);
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

    const fetch_limit: usize = 200;

    if (user) |u| {
        const local_list = statuses.listByUserBeforeCreatedAt(&app_state.conn, allocator, u.id, fetch_limit, before_created_at, before_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        for (local_list) |st| {
            if (!isPublicTimelineVisibility(st.visibility)) continue;
            if (!containsHashtag(st.text, tag)) continue;
            payloads.append(allocator, masto.makeStatusPayload(app_state, allocator, u, st)) catch return .{
                .status = .internal_server_error,
                .body = "internal server error\n",
            };
        }
    }

    if (!local_only) {
        const remote_list = remote_statuses.listLatestBeforeCreatedAt(&app_state.conn, allocator, fetch_limit, before_created_at, before_id) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };

        for (remote_list) |st| {
            if (!isPublicTimelineVisibility(st.visibility)) continue;
            if (!containsHashtag(st.content_html, tag)) continue;

            const actor = remote_actors.lookupById(&app_state.conn, allocator, st.remote_actor_id) catch
                return .{ .status = .internal_server_error, .body = "internal server error\n" };
            if (actor == null) continue;

            payloads.append(allocator, masto.makeRemoteStatusPayload(app_state, allocator, actor.?, st)) catch return .{
                .status = .internal_server_error,
                .body = "internal server error\n",
            };
        }
    }

    std.sort.block(StatusPayload, payloads.items, {}, masto.statusPayloadNewerFirst);

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
        const base = url.baseUrlAlloc(app_state, allocator) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        const newest_id = statusPayloadIdInt(slice[0]);
        const oldest_id = statusPayloadIdInt(slice[slice.len - 1]);

        const local_param: []const u8 = if (local_only) "&local=true" else "";
        const next_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/tag/{s}?limit={d}{s}&max_id={d}",
            .{ base, tag_enc, limit, local_param, oldest_id },
        ) catch "";
        const prev_url = std.fmt.allocPrint(
            allocator,
            "{s}/api/v1/timelines/tag/{s}?limit={d}{s}&since_id={d}",
            .{ base, tag_enc, limit, local_param, newest_id },
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

const std = @import("std");

const app = @import("app.zig");
const federation = @import("federation.zig");
const remote_statuses = @import("remote_statuses.zig");
const statuses = @import("statuses.zig");
const transport = @import("transport.zig");
const util_html = @import("util/html.zig");
const util_json = @import("util/json.zig");
const util_url = @import("util/url.zig");

pub const Error = federation.Error || statuses.Error;

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len == 0) return s;
    if (s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

fn stripQueryAndFragment(s: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, s, '?');
    const h = std.mem.indexOfScalar(u8, s, '#');
    const end = blk: {
        if (q == null and h == null) break :blk s.len;
        if (q != null and h != null) break :blk @min(q.?, h.?);
        break :blk if (q) |qi| qi else h.?;
    };
    return s[0..end];
}

fn stripLocalBase(app_state: *app.App, iri: []const u8) ?[]const u8 {
    const prefix = switch (app_state.cfg.scheme) {
        .http => "http://",
        .https => "https://",
    };
    if (!std.mem.startsWith(u8, iri, prefix)) return null;
    const rest = iri[prefix.len..];
    if (!std.mem.startsWith(u8, rest, app_state.cfg.domain)) return null;
    const after_domain = rest[app_state.cfg.domain.len..];
    if (after_domain.len == 0) return "";
    if (after_domain[0] == '/') return after_domain;
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

fn jsonTruthiness(v: ?std.json.Value) bool {
    const val = v orelse return false;
    return switch (val) {
        .bool => |b| b,
        else => false,
    };
}

fn jsonContainsIri(v: ?std.json.Value, want: []const u8) bool {
    const val = v orelse return false;
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

fn noteFirstActorId(note: std.json.ObjectMap) ?[]const u8 {
    const v = note.get("attributedTo") orelse note.get("actor") orelse return null;
    return switch (v) {
        .string => |s| if (s.len == 0) null else s,
        .object => |o| blk: {
            const id_val = o.get("id") orelse break :blk null;
            if (id_val != .string) break :blk null;
            if (id_val.string.len == 0) break :blk null;
            break :blk id_val.string;
        },
        .array => |arr| blk: {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| if (s.len > 0) break :blk s,
                    .object => |o| {
                        const id_val = o.get("id") orelse continue;
                        if (id_val == .string and id_val.string.len > 0) break :blk id_val.string;
                    },
                    else => continue,
                }
            }
            break :blk null;
        },
        else => null,
    };
}

fn noteInReplyToUri(note: std.json.ObjectMap) ?[]const u8 {
    const raw = note.get("inReplyTo") orelse return null;
    return switch (raw) {
        .string => |s| if (s.len == 0) null else s,
        .object => |o| blk: {
            const id_val = o.get("id") orelse break :blk null;
            if (id_val != .string) break :blk null;
            if (id_val.string.len == 0) break :blk null;
            break :blk id_val.string;
        },
        else => null,
    };
}

fn noteVisibility(note: std.json.ObjectMap) []const u8 {
    if (jsonTruthiness(note.get("directMessage"))) return "direct";

    const has_recipients = (note.get("to") != null) or (note.get("cc") != null);
    if (!has_recipients) return "public";

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    if (jsonContainsIri(note.get("to"), public_iri)) return "public";
    if (jsonContainsIri(note.get("cc"), public_iri)) return "unlisted";
    return "direct";
}

fn hostHeaderAllocForUri(allocator: std.mem.Allocator, uri: std.Uri) ![]u8 {
    var host_buf: [std.Uri.host_name_max]u8 = undefined;
    const host = uri.getHost(&host_buf) catch return error.RemoteFetchFailed;

    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) 80 else 443;

    if (uri.port == null) return allocator.dupe(u8, host);
    const port = uri.port.?;
    if (port == default_port) return allocator.dupe(u8, host);

    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
}

fn fetchActivityPubObjectBodyAlloc(app_state: *app.App, allocator: std.mem.Allocator, url_str: []const u8) Error![]u8 {
    const uri = try std.Uri.parse(url_str);
    const host_header = try hostHeaderAllocForUri(allocator, uri);

    const resp = try app_state.transport.fetch(allocator, .{
        .url = url_str,
        .method = .GET,
        .headers = .{ .host = .{ .override = host_header }, .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "accept", .value = "application/activity+json" }},
    });
    if (resp.status.class() != .success) {
        allocator.free(resp.body);
        return error.RemoteFetchFailed;
    }
    return resp.body;
}

const ParsedNote = struct {
    id: []const u8,
    actor_id: []const u8,
    content_html: []const u8,
    created_at: []const u8,
    visibility: []const u8,
    in_reply_to_uri: ?[]const u8,
};

fn parseNoteDoc(allocator: std.mem.Allocator, body: []const u8) Error!?ParsedNote {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch
        return error.RemoteFetchFailed;
    defer parsed.deinit();

    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const type_val = obj.get("type") orelse return null;
    if (type_val != .string) return null;
    if (!std.mem.eql(u8, type_val.string, "Note") and !std.mem.eql(u8, type_val.string, "Article")) return null;

    const id_val = obj.get("id") orelse return null;
    if (id_val != .string or id_val.string.len == 0) return null;

    const id_norm = stripQueryAndFragment(trimTrailingSlash(id_val.string));
    if (!util_url.isHttpOrHttpsUrl(id_norm)) return null;

    const actor_id_raw = noteFirstActorId(obj) orelse return null;
    const actor_id = stripQueryAndFragment(trimTrailingSlash(actor_id_raw));
    if (!util_url.isHttpOrHttpsUrl(actor_id)) return null;

    const created_at = blk: {
        const p = obj.get("published") orelse break :blk "1970-01-01T00:00:00.000Z";
        if (p != .string) break :blk "1970-01-01T00:00:00.000Z";
        if (p.string.len == 0) break :blk "1970-01-01T00:00:00.000Z";
        break :blk p.string;
    };

    const content_html = blk: {
        const c = obj.get("content") orelse break :blk "";
        if (c != .string) break :blk "";
        break :blk util_html.safeHtmlFromRemoteHtmlAlloc(allocator, c.string) catch "";
    };

    const in_reply_to_uri = blk: {
        const raw = noteInReplyToUri(obj) orelse break :blk null;
        const norm = stripQueryAndFragment(trimTrailingSlash(raw));
        if (!util_url.isHttpOrHttpsUrl(norm)) break :blk null;
        break :blk norm;
    };

    return .{
        .id = id_norm,
        .actor_id = actor_id,
        .content_html = content_html,
        .created_at = created_at,
        .visibility = noteVisibility(obj),
        .in_reply_to_uri = in_reply_to_uri,
    };
}

pub fn backfillRemoteAncestors(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
    in_reply_to_uri_raw: []const u8,
) Error!void {
    _ = user_id;
    if (status_id >= 0) return;

    const child = remote_statuses.lookup(&app_state.conn, allocator, status_id) catch return;
    if (child == null) return;
    if (child.?.in_reply_to_id != null) return;

    var cur_id: i64 = status_id;
    var next_uri_opt: ?[]const u8 = in_reply_to_uri_raw;

    var depth: usize = 0;
    while (depth < 20 and next_uri_opt != null and cur_id < 0) : (depth += 1) {
        const next_uri_norm = stripQueryAndFragment(trimTrailingSlash(next_uri_opt.?));
        if (!util_url.isHttpOrHttpsUrl(next_uri_norm)) break;

        if (localStatusIdFromIri(app_state, next_uri_norm)) |local_id| {
            const local = statuses.lookup(&app_state.conn, allocator, local_id) catch null;
            if (local != null) {
                _ = remote_statuses.updateInReplyToId(&app_state.conn, cur_id, local_id) catch {};
                break;
            }
        }

        const body = fetchActivityPubObjectBodyAlloc(app_state, allocator, next_uri_norm) catch break;
        if (util_json.maxNestingDepth(body) > app_state.cfg.json_max_nesting_depth) break;
        if (util_json.structuralTokenCount(body) > app_state.cfg.json_max_tokens) break;

        const note = (try parseNoteDoc(allocator, body)) orelse break;

        const actor = federation.ensureRemoteActorById(app_state, allocator, note.actor_id) catch break;

        const parent = remote_statuses.createIfNotExists(
            &app_state.conn,
            allocator,
            note.id,
            actor.id,
            null,
            note.content_html,
            null,
            note.visibility,
            note.created_at,
        ) catch break;

        _ = remote_statuses.updateInReplyToId(&app_state.conn, cur_id, parent.id) catch {};

        cur_id = parent.id;
        next_uri_opt = note.in_reply_to_uri;
    }
}

test "parseNoteDoc extracts id, actor, and inReplyTo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","id":"https://remote.test/notes/child","type":"Note","attributedTo":"https://remote.test/users/bob","content":"<p>Hello</p>","published":"2020-01-01T00:00:00.000Z","inReplyTo":"https://remote.test/notes/parent","to":["https://www.w3.org/ns/activitystreams#Public"]}
    ;
    const note = (try parseNoteDoc(a, body)).?;
    try std.testing.expectEqualStrings("https://remote.test/notes/child", note.id);
    try std.testing.expectEqualStrings("https://remote.test/users/bob", note.actor_id);
    try std.testing.expectEqualStrings("2020-01-01T00:00:00.000Z", note.created_at);
    try std.testing.expectEqualStrings("public", note.visibility);
    try std.testing.expect(note.in_reply_to_uri != null);
    try std.testing.expectEqualStrings("https://remote.test/notes/parent", note.in_reply_to_uri.?);
}

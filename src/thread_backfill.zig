const std = @import("std");

const app = @import("app.zig");
const activitypub_json = @import("activitypub_json.zig");
const federation = @import("federation.zig");
const remote_statuses = @import("remote_statuses.zig");
const statuses = @import("statuses.zig");
const transport = @import("transport.zig");
const activitypub_attachments = @import("activitypub_attachments.zig");
const util_html = @import("util/html.zig");
const util_json = @import("util/json.zig");
const util_local_iri = @import("util/local_iri.zig");
const util_url = @import("util/url.zig");

pub const Error = federation.Error || statuses.Error;

pub const IngestResult = struct {
    status: remote_statuses.RemoteStatus,
    was_new: bool,
};

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
    if (activitypub_json.truthiness(note.get("directMessage"))) return "direct";

    const has_recipients = (note.get("to") != null) or (note.get("cc") != null);
    if (!has_recipients) return "public";

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";
    if (activitypub_json.containsIri(note.get("to"), public_iri)) return "public";
    if (activitypub_json.containsIri(note.get("cc"), public_iri)) return "unlisted";
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
    attachments_json: ?[]const u8,
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

    const id_norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(id_val.string));
    if (!util_url.isHttpOrHttpsUrl(id_norm)) return null;

    const actor_id_raw = noteFirstActorId(obj) orelse return null;
    const actor_id = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(actor_id_raw));
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

    const attachments_json = activitypub_attachments.remoteAttachmentsJsonAlloc(allocator, obj) catch null;

    const in_reply_to_uri = blk: {
        const raw = noteInReplyToUri(obj) orelse break :blk null;
        const norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(raw));
        if (!util_url.isHttpOrHttpsUrl(norm)) break :blk null;
        break :blk norm;
    };

    return .{
        .id = id_norm,
        .actor_id = actor_id,
        .content_html = content_html,
        .created_at = created_at,
        .visibility = noteVisibility(obj),
        .attachments_json = attachments_json,
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
        const next_uri_norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(next_uri_opt.?));
        if (!util_url.isHttpOrHttpsUrl(next_uri_norm)) break;

        if (util_local_iri.localStatusIdFromIri(app_state, next_uri_norm)) |local_id| {
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
            note.attachments_json,
            note.visibility,
            note.created_at,
        ) catch break;

        _ = remote_statuses.updateInReplyToId(&app_state.conn, cur_id, parent.id) catch {};

        cur_id = parent.id;
        next_uri_opt = note.in_reply_to_uri;
    }
}

pub fn ingestRemoteNoteByUri(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    note_uri_raw: []const u8,
    require_public: bool,
) Error!?IngestResult {
    const note_uri_norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(note_uri_raw));
    if (!util_url.isHttpOrHttpsUrl(note_uri_norm)) return null;

    if (remote_statuses.lookupByUriAny(&app_state.conn, allocator, note_uri_norm) catch null) |existing| {
        return .{ .status = existing, .was_new = false };
    }

    const body = fetchActivityPubObjectBodyAlloc(app_state, allocator, note_uri_norm) catch return null;
    if (util_json.maxNestingDepth(body) > app_state.cfg.json_max_nesting_depth) return null;
    if (util_json.structuralTokenCount(body) > app_state.cfg.json_max_tokens) return null;

    const note = (try parseNoteDoc(allocator, body)) orelse return null;
    if (require_public and !(std.mem.eql(u8, note.visibility, "public") or std.mem.eql(u8, note.visibility, "unlisted"))) {
        return null;
    }

    const actor = federation.ensureRemoteActorById(app_state, allocator, note.actor_id) catch return null;

    const in_reply_to_id: ?i64 = blk: {
        const raw = note.in_reply_to_uri orelse break :blk null;

        if (util_local_iri.localStatusIdFromIri(app_state, raw)) |local_id| {
            const local = statuses.lookup(&app_state.conn, allocator, local_id) catch break :blk null;
            if (local != null) break :blk local_id;
        }

        const remote = remote_statuses.lookupByUriAny(&app_state.conn, allocator, raw) catch break :blk null;
        if (remote) |p| break :blk p.id;

        break :blk null;
    };

    const created = remote_statuses.createIfNotExists(
        &app_state.conn,
        allocator,
        note.id,
        actor.id,
        in_reply_to_id,
        note.content_html,
        note.attachments_json,
        note.visibility,
        note.created_at,
    ) catch return null;

    if (created.in_reply_to_id == null) {
        if (note.in_reply_to_uri) |puri| {
            try backfillRemoteAncestors(app_state, allocator, user_id, created.id, puri);
        }
    }

    return .{ .status = created, .was_new = true };
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

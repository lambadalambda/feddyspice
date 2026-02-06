const std = @import("std");

const activitypub_attachments = @import("activitypub_attachments.zig");
const activitypub_json = @import("activitypub_json.zig");
const app = @import("app.zig");
const federation = @import("federation.zig");
const remote_actors = @import("remote_actors.zig");
const remote_statuses = @import("remote_statuses.zig");
const statuses = @import("statuses.zig");
const util_html = @import("util/html.zig");
const util_local_iri = @import("util/local_iri.zig");
const util_url = @import("util/url.zig");

pub const Error = federation.Error || remote_statuses.Error || statuses.Error || std.Io.Writer.Error;

pub const Ingested = struct {
    actor: remote_actors.RemoteActor,
    status: remote_statuses.RemoteStatus,
    was_new: bool,
    in_reply_to_uri: ?[]const u8,
    missing_in_reply_to_uri: ?[]const u8,
};

fn isPubliclyVisibleVisibility(visibility: []const u8) bool {
    return std.mem.eql(u8, visibility, "public") or std.mem.eql(u8, visibility, "unlisted");
}

fn firstIdString(val: std.json.Value) ?[]const u8 {
    switch (val) {
        .string => |s| return if (s.len == 0) null else s,
        .object => |o| {
            const id_val = o.get("id") orelse return null;
            if (id_val != .string) return null;
            return if (id_val.string.len == 0) null else id_val.string;
        },
        .array => |arr| {
            for (arr.items) |item| {
                if (firstIdString(item)) |s| return s;
            }
            return null;
        },
        else => return null,
    }
}

fn noteFirstActorId(note: std.json.ObjectMap, activity_obj_opt: ?std.json.ObjectMap) ?[]const u8 {
    if (note.get("attributedTo")) |v| {
        if (firstIdString(v)) |s| return s;
    }
    if (note.get("actor")) |v| {
        if (firstIdString(v)) |s| return s;
    }

    if (activity_obj_opt) |activity_obj| {
        if (activity_obj.get("actor")) |v| {
            if (firstIdString(v)) |s| return s;
        }
    }

    return null;
}

fn noteInReplyToUri(note: std.json.ObjectMap) ?[]const u8 {
    const raw = note.get("inReplyTo") orelse return null;
    return firstIdString(raw);
}

pub fn noteVisibility(activity_obj_opt: ?std.json.ObjectMap, note: std.json.ObjectMap) []const u8 {
    if (activitypub_json.truthiness(note.get("directMessage"))) return "direct";
    if (activity_obj_opt) |a| {
        if (activitypub_json.truthiness(a.get("directMessage"))) return "direct";
    }

    const has_recipients = (note.get("to") != null) or (note.get("cc") != null) or blk: {
        if (activity_obj_opt) |a| break :blk (a.get("to") != null) or (a.get("cc") != null);
        break :blk false;
    };
    if (!has_recipients) return "public";

    const public_iri = "https://www.w3.org/ns/activitystreams#Public";

    const public_in_to =
        activitypub_json.containsIri(note.get("to"), public_iri) or
        (if (activity_obj_opt) |a| activitypub_json.containsIri(a.get("to"), public_iri) else false);
    if (public_in_to) return "public";

    const public_in_cc =
        activitypub_json.containsIri(note.get("cc"), public_iri) or
        (if (activity_obj_opt) |a| activitypub_json.containsIri(a.get("cc"), public_iri) else false);
    if (public_in_cc) return "unlisted";

    const followers_in_recipients = blk: {
        if (jsonContainsFollowersCollection(note.get("to"))) break :blk true;
        if (jsonContainsFollowersCollection(note.get("cc"))) break :blk true;
        if (activity_obj_opt) |a| {
            if (jsonContainsFollowersCollection(a.get("to"))) break :blk true;
            if (jsonContainsFollowersCollection(a.get("cc"))) break :blk true;
        }
        break :blk false;
    };
    if (followers_in_recipients) return "private";

    return "direct";
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

fn jsonContainsFollowersCollection(v_opt: ?std.json.Value) bool {
    const v = v_opt orelse return false;
    switch (v) {
        .string => |s| return isFollowersCollectionIri(s),
        .object => |o| {
            const id_val = o.get("id") orelse return false;
            if (id_val != .string) return false;
            return isFollowersCollectionIri(id_val.string);
        },
        .array => |arr| {
            for (arr.items) |it| {
                switch (it) {
                    .string => |s| if (isFollowersCollectionIri(s)) return true,
                    .object => |o| {
                        const id_val = o.get("id") orelse continue;
                        if (id_val != .string) continue;
                        if (isFollowersCollectionIri(id_val.string)) return true;
                    },
                    else => continue,
                }
            }
            return false;
        },
        else => return false,
    }
}

fn isFollowersCollectionIri(raw: []const u8) bool {
    const norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(raw));
    return std.mem.endsWith(u8, norm, "/followers");
}

fn parseNoteFromObjectMapsAlloc(
    allocator: std.mem.Allocator,
    activity_obj_opt: ?std.json.ObjectMap,
    note: std.json.ObjectMap,
    actor_id_override_opt: ?[]const u8,
) Error!?ParsedNote {
    const type_val = note.get("type") orelse return null;
    if (type_val != .string) return null;
    if (!std.mem.eql(u8, type_val.string, "Note") and !std.mem.eql(u8, type_val.string, "Article")) return null;

    const id_val = note.get("id") orelse return null;
    if (id_val != .string or id_val.string.len == 0) return null;

    const id_norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(id_val.string));
    if (!util_url.isHttpOrHttpsUrl(id_norm)) return null;

    const actor_id_raw = actor_id_override_opt orelse noteFirstActorId(note, activity_obj_opt) orelse return null;
    const actor_id_norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(actor_id_raw));
    if (!util_url.isHttpOrHttpsUrl(actor_id_norm)) return null;

    const created_at = blk: {
        const p = note.get("published") orelse break :blk "1970-01-01T00:00:00.000Z";
        if (p != .string) break :blk "1970-01-01T00:00:00.000Z";
        if (p.string.len == 0) break :blk "1970-01-01T00:00:00.000Z";
        break :blk p.string;
    };

    const content_html = blk: {
        const c = note.get("content") orelse break :blk "";
        if (c != .string) break :blk "";
        break :blk try util_html.safeHtmlFromRemoteHtmlAlloc(allocator, c.string);
    };

    const attachments_json = try activitypub_attachments.remoteAttachmentsJsonAlloc(allocator, note);

    const in_reply_to_uri = blk: {
        const raw = noteInReplyToUri(note) orelse break :blk null;
        const norm = util_url.stripQueryAndFragment(util_url.trimTrailingSlash(raw));
        if (!util_url.isHttpOrHttpsUrl(norm)) break :blk null;
        break :blk norm;
    };

    return .{
        .id = id_norm,
        .actor_id = actor_id_norm,
        .content_html = content_html,
        .created_at = created_at,
        .visibility = noteVisibility(activity_obj_opt, note),
        .attachments_json = attachments_json,
        .in_reply_to_uri = in_reply_to_uri,
    };
}

pub fn ingestFromObjectMaps(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    activity_obj_opt: ?std.json.ObjectMap,
    note_obj: std.json.ObjectMap,
    require_public: bool,
    actor_id_override_opt: ?[]const u8,
) Error!?Ingested {
    _ = user_id;

    const note = (try parseNoteFromObjectMapsAlloc(allocator, activity_obj_opt, note_obj, actor_id_override_opt)) orelse return null;
    if (require_public and !isPubliclyVisibleVisibility(note.visibility)) return null;

    if (try remote_statuses.lookupByUriAny(&app_state.conn, allocator, note.id)) |existing| {
        const actor = try federation.ensureRemoteActorById(app_state, allocator, existing.remote_actor_id);
        return .{
            .actor = actor,
            .status = existing,
            .was_new = false,
            .in_reply_to_uri = note.in_reply_to_uri,
            .missing_in_reply_to_uri = null,
        };
    }

    const actor = try federation.ensureRemoteActorById(app_state, allocator, note.actor_id);

    const in_reply_to_id: ?i64 = blk: {
        const raw = note.in_reply_to_uri orelse break :blk null;

        if (util_local_iri.localStatusIdFromIri(app_state, raw)) |local_id| {
            const local = try statuses.lookup(&app_state.conn, allocator, local_id);
            if (local != null) break :blk local_id;
            break :blk null;
        }

        if (try remote_statuses.lookupByUriAny(&app_state.conn, allocator, raw)) |p| break :blk p.id;

        break :blk null;
    };

    const missing_in_reply_to_uri: ?[]const u8 = blk: {
        if (in_reply_to_id != null) break :blk null;
        const raw = note.in_reply_to_uri orelse break :blk null;
        if (util_local_iri.localStatusIdFromIri(app_state, raw) != null) break :blk null;
        break :blk raw;
    };

    const created = try remote_statuses.createIfNotExists(
        &app_state.conn,
        allocator,
        note.id,
        actor.id,
        in_reply_to_id,
        note.content_html,
        note.attachments_json,
        note.visibility,
        note.created_at,
    );

    return .{
        .actor = actor,
        .status = created,
        .was_new = true,
        .in_reply_to_uri = note.in_reply_to_uri,
        .missing_in_reply_to_uri = missing_in_reply_to_uri,
    };
}

test "ingestFromObjectMaps ingests a public Note and is idempotent" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","id":"https://remote.test/notes/1","type":"Note","attributedTo":"https://remote.test/users/bob","content":"<p>hi</p>","published":"2020-01-01T00:00:00.000Z","to":["https://www.w3.org/ns/activitystreams#Public"]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();

    const first = (try ingestFromObjectMaps(&app_state, a, 1, null, parsed.value.object, true, null)).?;
    try std.testing.expect(first.was_new);
    try std.testing.expectEqualStrings("public", first.status.visibility);

    const second = (try ingestFromObjectMaps(&app_state, a, 1, null, parsed.value.object, true, null)).?;
    try std.testing.expect(!second.was_new);
    try std.testing.expectEqual(first.status.id, second.status.id);
}

test "ingestFromObjectMaps classifies followers-only Note as private" {
    var app_state = try app.App.initMemory(std.testing.allocator, "example.test");
    defer app_state.deinit();

    try remote_actors.upsert(&app_state.conn, .{
        .id = "https://remote.test/users/bob",
        .inbox = "https://remote.test/users/bob/inbox",
        .shared_inbox = null,
        .preferred_username = "bob",
        .domain = "remote.test",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"@context":"https://www.w3.org/ns/activitystreams","id":"https://remote.test/notes/priv1","type":"Note","attributedTo":"https://remote.test/users/bob","content":"<p>hi</p>","published":"2020-01-01T00:00:00.000Z","to":["https://remote.test/users/bob/followers"]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();

    const ingested = (try ingestFromObjectMaps(&app_state, a, 1, null, parsed.value.object, false, null)).?;
    try std.testing.expectEqualStrings("private", ingested.status.visibility);
}

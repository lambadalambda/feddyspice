const std = @import("std");

const app = @import("app.zig");
const federation = @import("federation.zig");
const remote_note_ingest = @import("remote_note_ingest.zig");
const remote_statuses = @import("remote_statuses.zig");
const statuses = @import("statuses.zig");
const util_json = @import("util/json.zig");
const util_local_iri = @import("util/local_iri.zig");
const util_url = @import("util/url.zig");

pub const Error = remote_note_ingest.Error;

pub const IngestResult = struct {
    status: remote_statuses.RemoteStatus,
    was_new: bool,
};

fn fetchActivityPubObjectBodyAlloc(app_state: *app.App, allocator: std.mem.Allocator, url_str: []const u8) Error![]u8 {
    return federation.fetchBodySuccessAlloc(app_state, allocator, .{
        .url = url_str,
        .method = .GET,
        .headers = .{ .accept_encoding = .omit },
        .extra_headers = &.{.{ .name = "accept", .value = "application/activity+json" }},
    });
}

pub fn backfillRemoteAncestors(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    user_id: i64,
    status_id: i64,
    in_reply_to_uri_raw: []const u8,
) Error!void {
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

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch break;
        defer parsed.deinit();
        if (parsed.value != .object) break;

        const ingested = (try remote_note_ingest.ingestFromObjectMaps(
            app_state,
            allocator,
            user_id,
            null,
            parsed.value.object,
            false,
            null,
        )) orelse break;
        const parent = ingested.status;

        _ = remote_statuses.updateInReplyToId(&app_state.conn, cur_id, parent.id) catch {};

        cur_id = parent.id;
        next_uri_opt = ingested.in_reply_to_uri;
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

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const ingested = (try remote_note_ingest.ingestFromObjectMaps(
        app_state,
        allocator,
        user_id,
        null,
        parsed.value.object,
        require_public,
        null,
    )) orelse return null;

    if (ingested.status.in_reply_to_id == null) {
        if (ingested.missing_in_reply_to_uri) |puri| {
            try backfillRemoteAncestors(app_state, allocator, user_id, ingested.status.id, puri);
        }
    }

    return .{ .status = ingested.status, .was_new = ingested.was_new };
}

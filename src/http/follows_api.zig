const std = @import("std");

const app = @import("../app.zig");
const background = @import("../background.zig");
const common = @import("common.zig");
const federation = @import("../federation.zig");
const follows = @import("../follows.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const masto = @import("mastodon.zig");
const oauth = @import("../oauth.zig");
const remote_actors = @import("../remote_actors.zig");
const util_ids = @import("../util/ids.zig");
const util_url = @import("../util/url.zig");

fn remoteAccountApiIdAlloc(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) []const u8 {
    return util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor_id);
}

fn makeRemoteAccountPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    api_id: []const u8,
    actor: remote_actors.RemoteActor,
) masto.AccountPayload {
    return masto.makeRemoteAccountPayload(app_state, allocator, api_id, actor);
}

pub fn followsPost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);

    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const uri = parsed.get("uri") orelse return .{ .status = .bad_request, .body = "missing uri\n" };

    const actor = federation.resolveRemoteActorByHandle(app_state, allocator, uri) catch |err| switch (err) {
        error.InvalidHandle, error.WebfingerNoSelfLink, error.ActorDocMissingFields => return .{
            .status = .bad_request,
            .body = "invalid uri\n",
        },
        else => return .{ .status = .internal_server_error, .body = "internal server error\n" },
    };

    // Idempotent behavior: if the follow already exists, just return the account.
    const existing = follows.lookupByUserAndRemoteActorId(&app_state.conn, allocator, info.?.user_id, actor.id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (existing != null) {
        const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);
        const payload = makeRemoteAccountPayload(app_state, allocator, api_id, actor);
        const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        return .{
            .content_type = "application/json; charset=utf-8",
            .body = body,
        };
    }

    const base = util_url.baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const follow_activity_id = std.fmt.allocPrint(allocator, "{s}/follows/{s}", .{ base, id_hex[0..] }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    _ = follows.createPending(&app_state.conn, info.?.user_id, actor.id, follow_activity_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    background.sendFollow(app_state, allocator, info.?.user_id, actor.id, follow_activity_id);

    const api_id = remoteAccountApiIdAlloc(app_state, allocator, actor.id);
    const payload = makeRemoteAccountPayload(app_state, allocator, api_id, actor);
    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

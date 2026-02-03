const std = @import("std");

const app = @import("../app.zig");
const remote_actors = @import("../remote_actors.zig");

pub const remote_actor_id_base: i64 = 1_000_000_000;

pub fn remoteAccountApiIdAlloc(app_state: *app.App, allocator: std.mem.Allocator, actor_id: []const u8) []const u8 {
    const rowid = remote_actors.lookupRowIdById(&app_state.conn, actor_id) catch return actor_id;
    if (rowid == null) return actor_id;
    return std.fmt.allocPrint(allocator, "{d}", .{remote_actor_id_base + rowid.?}) catch actor_id;
}

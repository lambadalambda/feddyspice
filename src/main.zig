const std = @import("std");
const feddyspice = @import("feddyspice");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cfg = try feddyspice.config.Config.load(allocator);
    const app_state = try feddyspice.app.App.initFromConfig(allocator, cfg);
    defer app_state.deinitAndDestroy();

    try feddyspice.server.serve(app_state, app_state.cfg.listen_address);
}

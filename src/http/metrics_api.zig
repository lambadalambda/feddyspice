const std = @import("std");

const app = @import("../app.zig");
const db = @import("../db.zig");
const http_types = @import("../http_types.zig");
const version = @import("../version.zig");

pub fn metricsGet(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const CountError = db.Error || std.mem.Allocator.Error;
    const count: *const fn (conn: *db.Db, sql: [:0]const u8) CountError!i64 = struct {
        fn f(conn: *db.Db, sql: [:0]const u8) CountError!i64 {
            var stmt = try conn.prepareZ(sql);
            defer stmt.finalize();
            switch (try stmt.step()) {
                .row => return stmt.columnInt64(0),
                .done => return 0,
            }
        }
    }.f;

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    const jobs_queued = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='queued';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const jobs_running = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='running';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const jobs_dead = count(&app_state.conn, "SELECT COUNT(*) FROM jobs WHERE state='dead';\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const inbox_dedupe_total = count(&app_state.conn, "SELECT COUNT(*) FROM inbox_dedupe;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const statuses_local = count(&app_state.conn, "SELECT COUNT(*) FROM statuses WHERE deleted_at IS NULL;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    const statuses_remote = count(&app_state.conn, "SELECT COUNT(*) FROM remote_statuses WHERE deleted_at IS NULL;\x00") catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    aw.writer.print("# HELP feddyspice_build_info Build info.\n", .{}) catch {};
    aw.writer.print("# TYPE feddyspice_build_info gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_build_info{{version=\"{s}\"}} 1\n", .{version.version}) catch {};

    aw.writer.print("# TYPE feddyspice_jobs_queued gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_queued {d}\n", .{jobs_queued}) catch {};
    aw.writer.print("# TYPE feddyspice_jobs_running gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_running {d}\n", .{jobs_running}) catch {};
    aw.writer.print("# TYPE feddyspice_jobs_dead gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_jobs_dead {d}\n", .{jobs_dead}) catch {};

    aw.writer.print("# TYPE feddyspice_inbox_dedupe_total gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_inbox_dedupe_total {d}\n", .{inbox_dedupe_total}) catch {};

    aw.writer.print("# TYPE feddyspice_statuses_local gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_statuses_local {d}\n", .{statuses_local}) catch {};
    aw.writer.print("# TYPE feddyspice_statuses_remote gauge\n", .{}) catch {};
    aw.writer.print("feddyspice_statuses_remote {d}\n", .{statuses_remote}) catch {};

    const body = aw.toOwnedSlice() catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    aw.deinit();

    return .{
        .content_type = "text/plain; version=0.0.4; charset=utf-8",
        .body = body,
    };
}

const std = @import("std");

pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
};

pub const SafeString = struct {
    s: []const u8,

    pub fn format(self: SafeString, writer: anytype) !void {
        for (self.s) |c| {
            switch (c) {
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                else => {
                    if (c < 0x20 or c == 0x7f) {
                        try writer.print("\\x{X:0>2}", .{c});
                    } else {
                        try writer.writeByte(c);
                    }
                },
            }
        }
    }
};

pub fn safe(s: []const u8) SafeString {
    return .{ .s = s };
}

pub fn levelFromString(s: []const u8) Level {
    if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
    if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(s, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
    if (std.ascii.eqlIgnoreCase(s, "err")) return .err;
    if (std.ascii.eqlIgnoreCase(s, "error")) return .err;
    return .info;
}

fn levelName(level: Level) []const u8 {
    return switch (level) {
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
    };
}

pub const Options = struct {
    to_stderr: bool = true,
    min_level: Level = .info,
};

pub const Logger = struct {
    mutex: std.Thread.Mutex = .{},
    file: ?std.fs.File = null,
    opts: Options = .{},

    pub fn initNull() Logger {
        return .{ .opts = .{ .to_stderr = false, .min_level = .err } };
    }

    pub fn initWithFile(file: std.fs.File, opts: Options) !Logger {
        var f = file;
        try f.seekFromEnd(0);
        return .{ .file = f, .opts = opts };
    }

    pub fn initFile(path: []const u8, opts: Options) !Logger {
        var f = try openAppendFile(path);
        errdefer f.close();
        return try initWithFile(f, opts);
    }

    pub fn deinit(self: *Logger) void {
        self.mutex.lock();
        if (self.file) |f| f.close();
        self.mutex.unlock();
        self.* = undefined;
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn warn(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    pub fn log(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.opts.min_level)) return;
        if (!self.opts.to_stderr and self.file == null) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const ts_ms: i64 = std.time.milliTimestamp();
        const prefix_fmt = "{d} {s} ";
        const prefix_args = .{ ts_ms, levelName(level) };

        if (self.file) |f| {
            var buf: [4096]u8 = undefined;
            var w = f.writerStreaming(&buf);
            w.interface.print(prefix_fmt, prefix_args) catch {};
            w.interface.print(fmt, args) catch {};
            w.interface.writeByte('\n') catch {};
            w.interface.flush() catch {};
        }

        if (self.opts.to_stderr) {
            var buf: [4096]u8 = undefined;
            var w = std.fs.File.stderr().writerStreaming(&buf);
            w.interface.print(prefix_fmt, prefix_args) catch {};
            w.interface.print(fmt, args) catch {};
            w.interface.writeByte('\n') catch {};
            w.interface.flush() catch {};
        }
    }
};

fn openAppendFile(path: []const u8) !std.fs.File {
    if (path.len == 0) return error.InvalidPath;
    if (std.fs.path.isAbsolute(path)) {
        return try std.fs.createFileAbsolute(path, .{ .truncate = false });
    }
    return try std.fs.cwd().createFile(path, .{ .truncate = false });
}

test "Logger writes to file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const f = try tmp.dir.createFile("test.log", .{ .truncate = true });

    var logger = try Logger.initWithFile(f, .{ .to_stderr = false, .min_level = .debug });
    defer logger.deinit();

    logger.info("hello {s}", .{"world"});
    logger.warn("test {d}", .{@as(u32, 123)});

    const rf = try tmp.dir.openFile("test.log", .{});
    defer rf.close();

    const got = try rf.readToEndAlloc(std.testing.allocator, 8 * 1024);
    defer std.testing.allocator.free(got);

    try std.testing.expect(std.mem.indexOf(u8, got, "hello world") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "test 123") != null);
}

test "safe escapes control characters" {
    const allocator = std.testing.allocator;
    const got = try std.fmt.allocPrint(allocator, "a{f}b", .{safe("\n\r\t\x01")});
    defer allocator.free(got);
    try std.testing.expectEqualStrings("a\\n\\r\\t\\x01b", got);
}

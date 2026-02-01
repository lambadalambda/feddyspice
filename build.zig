const std = @import("std");

fn addIncludePathIfExists(module: *std.Build.Module, path: []const u8) void {
    std.fs.accessAbsolute(path, .{}) catch return;
    module.addIncludePath(.{ .cwd_relative = path });
}

fn addLibraryPathIfExists(module: *std.Build.Module, path: []const u8) void {
    std.fs.accessAbsolute(path, .{}) catch return;
    module.addLibraryPath(.{ .cwd_relative = path });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Only run tests matching this substring");

    const c_flags = &[_][]const u8{
        "-std=c99",
        "-I/opt/homebrew/include",
        "-I/usr/local/include",
    };

    const sqlite_bind_c: std.Build.Module.CSourceFile = .{
        .file = b.path("src/sqlite_bind.c"),
        .flags = c_flags,
    };

    const mod = b.addModule("feddyspice", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addCSourceFile(sqlite_bind_c);
    mod.linkSystemLibrary("c", .{});
    mod.linkSystemLibrary("sqlite3", .{});
    mod.linkSystemLibrary("crypto", .{});
    mod.linkSystemLibrary("ssl", .{});

    if (target.result.os.tag == .macos) {
        addIncludePathIfExists(mod, "/opt/homebrew/include");
        addLibraryPathIfExists(mod, "/opt/homebrew/lib");
        addIncludePathIfExists(mod, "/usr/local/include");
        addLibraryPathIfExists(mod, "/usr/local/lib");
    }

    const exe = b.addExecutable(.{
        .name = "feddyspice",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "feddyspice", .module = mod },
            },
        }),
    });
    exe.root_module.linkSystemLibrary("c", .{});
    exe.root_module.linkSystemLibrary("sqlite3", .{});
    exe.root_module.linkSystemLibrary("crypto", .{});
    exe.root_module.linkSystemLibrary("ssl", .{});

    if (target.result.os.tag == .macos) {
        addIncludePathIfExists(exe.root_module, "/opt/homebrew/include");
        addLibraryPathIfExists(exe.root_module, "/opt/homebrew/lib");
        addIncludePathIfExists(exe.root_module, "/usr/local/include");
        addLibraryPathIfExists(exe.root_module, "/usr/local/lib");
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the server");
    run_step.dependOn(&run_cmd.step);

    const filters = if (test_filter) |f| &.{f} else &.{};

    const mod_tests = b.addTest(.{ .root_module = mod, .filters = filters });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module, .filters = filters });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}

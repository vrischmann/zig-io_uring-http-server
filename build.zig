const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const debug_callback_internals = b.option(bool, "debug-callback-internals", "Enable callback debugging") orelse false;
    const debug_accepts = b.option(bool, "debug-accepts", "Enable debugging for accepts") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "debug_callback_internals", debug_callback_internals);
    build_options.addOption(bool, "debug_accepts", debug_accepts);

    //

    const picohttp_flags: []const []const u8 = switch (optimize) {
        .Debug => &.{},
        .ReleaseFast, .ReleaseSafe => &.{
            "-O3",
        },
        .ReleaseSmall => &.{
            "-O0",
        },
    };

    const picohttp = b.addStaticLibrary(.{
        .name = "picohttp",
        .target = target,
        .optimize = optimize,
    });
    picohttp.addCSourceFile(.{
        .file = .{ .path = "src/picohttpparser.c" },
        .flags = picohttp_flags,
    });
    picohttp.linkLibC();

    //

    const args = b.dependency("args", .{});

    const exe = b.addExecutable(.{
        .name = "httpserver",
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .path = "src/main.zig" },
    });
    exe.addModule("args", args.module("args"));
    exe.addIncludePath(.{ .path = "src" });
    exe.linkLibrary(picohttp);
    exe.addOptions("build_options", build_options);
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .name = "test",
        .root_source_file = .{ .path = "src/test.zig" },
        .target = target,
        .optimize = optimize,
    });
    tests.addIncludePath(.{ .path = "src" });
    tests.linkSystemLibrary("curl");
    tests.linkLibrary(picohttp);
    tests.addOptions("build_options", build_options);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}

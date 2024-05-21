const std = @import("std");

pub fn build(b: *std.Build) void {
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
        .file = b.path("src/picohttpparser.c"),
        .flags = picohttp_flags,
    });
    picohttp.linkLibC();

    //

    const args = b.dependency("args", .{});

    const exe = b.addExecutable(.{
        .name = "httpserver",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/main.zig"),
    });
    exe.root_module.addImport("args", args.module("args"));
    exe.addIncludePath(b.path("src"));
    exe.linkLibrary(picohttp);
    exe.root_module.addImport("build_options", build_options.createModule());
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.addIncludePath(b.path("src"));
    tests.linkSystemLibrary("curl");
    tests.linkLibrary(picohttp);
    tests.root_module.addImport("build_options", build_options.createModule());
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);
}

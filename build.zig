const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const debug_callback_internals = b.option(bool, "debug-callback-internals", "Enable callback debugging") orelse false;
    const debug_accepts = b.option(bool, "debug-accepts", "Enable debugging for accepts") orelse false;

    const picohttp_flags: []const []const u8 = switch (mode) {
        .Debug => &.{},
        .ReleaseFast, .ReleaseSafe => &.{
            "-O3",
        },
        .ReleaseSmall => &.{
            "-O0",
        },
    };

    const picohttp = b.addStaticLibrary("picohttp", null);
    picohttp.addCSourceFile("src/picohttpparser.c", picohttp_flags);
    picohttp.setTarget(target);
    picohttp.setBuildMode(mode);
    picohttp.linkLibC();

    const build_options = b.addOptions();
    build_options.addOption(bool, "debug_callback_internals", debug_callback_internals);
    build_options.addOption(bool, "debug_accepts", debug_accepts);

    const exe = b.addExecutable("httpserver", "src/main.zig");
    exe.addPackagePath("args", "third_party/zig-args/args.zig");
    exe.addIncludeDir("src");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.linkLibrary(picohttp);
    exe.addOptions("build_options", build_options);
    exe.install();

    const tests = b.addTest("src/test.zig");
    tests.addIncludeDir("src");
    tests.setTarget(target);
    tests.setBuildMode(mode);
    tests.linkSystemLibrary("curl");
    tests.linkLibrary(picohttp);
    tests.addOptions("build_options", build_options);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}

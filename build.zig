const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const picohttp_flags = switch (mode) {
        .Debug => &[_][]const u8{},
        .ReleaseFast, .ReleaseSafe => &[_][]const u8{
            "-O3",
        },
        .ReleaseSmall => &[_][]const u8{
            "-O0",
        },
    };

    const picohttp = b.addStaticLibrary("picohttp", null);
    picohttp.addCSourceFile("src/picohttpparser.c", picohttp_flags);
    picohttp.setTarget(target);
    picohttp.setBuildMode(mode);
    picohttp.linkLibC();

    const exe = b.addExecutable("httpserver", "src/main.zig");
    exe.addIncludeDir("src");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.linkLibrary(picohttp);
    exe.install();

    const tests = b.addTest("src/test.zig");
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}

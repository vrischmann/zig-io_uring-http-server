const std = @import("std");

const TinyCurlBuilder = @import("third_party/curl/TinyCurlBuilder.zig");

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

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

    const exe = b.addExecutable("httpserver", "src/main.zig");
    exe.addPackagePath("httpserver", "src/lib.zig");
    exe.addIncludeDir("src");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.linkLibrary(picohttp);
    exe.install();

    var tinycurl_builder = try TinyCurlBuilder.init(b, "third_party/curl/", target, mode, .{
        .link_type = .static,
    });

    const tests = b.addTest("src/test.zig");
    tests.addIncludeDir("src");
    tests.setTarget(target);
    tests.setBuildMode(mode);
    tests.linkLibrary(picohttp);
    tinycurl_builder.addIncludeDirTo(tests);
    tinycurl_builder.linkTo(tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}

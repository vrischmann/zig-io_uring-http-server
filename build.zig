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
    picohttp.linkLibC();

    const exe = b.addExecutable("zig-io_uring-test", "src/main.zig");
    exe.addIncludeDir("src");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.linkLibrary(picohttp);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

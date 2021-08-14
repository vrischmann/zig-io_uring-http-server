const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const picohttp = b.addStaticLibrary("picohttp", "src/picohttpparser.c");
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

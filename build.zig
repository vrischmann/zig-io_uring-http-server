const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const debug_callback_internals = b.option(bool, "debug-callback-internals", "Enable callback debugging") orelse false;
    const debug_accepts = b.option(bool, "debug-accepts", "Enable debugging for accepts") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "debug_callback_internals", debug_callback_internals);
    build_options.addOption(bool, "debug_accepts", debug_accepts);

    if (target.result.os.tag != .linux) {
        b.default_step.dependOn(&b.addFail("io_uring is only available on linux").step);
        return;
    }

    //

    const picohttpparser_dep = b.dependency("picohttpparser", .{});
    const picohttpparser_mod = picohttpparser_dep.module("picohttpparser");

    const args_dep = b.dependency("args", .{});
    const args_mod = args_dep.module("args");

    //

    const exe = b.addExecutable(.{
        .name = "httpserver",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();
    exe.root_module.addImport("args", args_mod);
    exe.root_module.addImport("picohttpparser", picohttpparser_mod);
    exe.root_module.addImport("build_options", build_options.createModule());
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.linkSystemLibrary("curl");
    tests.linkLibC();
    tests.root_module.addImport("picohttpparser", picohttpparser_mod);
    tests.root_module.addImport("build_options", build_options.createModule());
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);
}

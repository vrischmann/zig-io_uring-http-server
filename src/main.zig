const std = @import("std");
const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const Atomic = std.atomic.Atomic;
const assert = std.debug.assert;

const IO_Uring = std.os.linux.IO_Uring;
const io_uring_cqe = std.os.linux.io_uring_cqe;
const io_uring_sqe = std.os.linux.io_uring_sqe;

const httpserver = @import("httpserver");

const max_ring_entries = 512;
const max_buffer_size = 4096;
const max_connections = 128;
const max_serve_threads = 8;

const logger = std.log.scoped(.main);

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };
    var allocator = gpa.allocator();

    // NOTE(vincent): for debugging
    // var logging_allocator = heap.loggingAllocator(gpa.allocator());
    // var allocator = logging_allocator.allocator();

    //
    // Ignore broken pipes
    var act = os.Sigaction{
        .handler = .{
            .sigaction = os.SIG.IGN,
        },
        .mask = os.empty_sigset,
        .flags = 0,
    };
    os.sigaction(os.SIG.PIPE, &act, null);

    // Create the server socket
    const server_fd = try httpserver.createSocket(3405);

    logger.info("listening on :3405\n", .{});

    // Create the servers

    var servers = try allocator.alloc(httpserver.Server, max_serve_threads);
    for (servers) |*server, i| {
        try server.init(allocator, i, server_fd);
    }
    defer {
        for (servers) |*server| server.deinit();
        allocator.free(servers);
    }

    for (servers) |*v| {
        v.thread = try std.Thread.spawn(
            .{},
            struct {
                fn worker(server: *httpserver.Server) !void {
                    return server.run(30 * time.ns_per_s);
                }
            }.worker,
            .{v},
        );
    }

    for (servers) |*v| v.thread.join();
}

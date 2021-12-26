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

const max_serve_threads = 1;

const logger = std.log.scoped(.main);

var global_running: Atomic(bool) = Atomic(bool).init(true);

fn addSignalHandlers() void {
    // Ignore broken pipes
    {
        var act = os.Sigaction{
            .handler = .{
                .sigaction = os.SIG.IGN,
            },
            .mask = os.empty_sigset,
            .flags = 0,
        };
        os.sigaction(os.SIG.PIPE, &act, null);
    }

    // Catch SIGINT/SIGTERM for proper shutdown
    {
        var act = os.Sigaction{
            .handler = .{
                .handler = struct {
                    fn wrapper(sig: c_int) callconv(.C) void {
                        logger.info("caught signal {d}", .{sig});

                        global_running.store(false, .SeqCst);
                    }
                }.wrapper,
            },
            .mask = os.empty_sigset,
            .flags = 0,
        };
        os.sigaction(os.SIG.TERM, &act, null);
        os.sigaction(os.SIG.INT, &act, null);
    }
}

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
    addSignalHandlers();

    // Create the server socket
    const server_fd = try httpserver.createSocket(3405);

    logger.info("listening on :3405\n", .{});

    // Create the servers

    const ServerWithThread = struct {
        server: httpserver.Server(usize),
        thread: std.Thread,
    };

    var servers = try allocator.alloc(ServerWithThread, max_serve_threads);
    for (servers) |*item, i| {
        try item.server.init(
            allocator,
            i,
            &global_running,
            server_fd,
            i,
            struct {
                fn handle(per_request_allocator: mem.Allocator, ctx: usize, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                    _ = per_request_allocator;

                    logger.debug("ctx#{d:<4} IN HANDLER addr={s} method: {s}, path: {s}, minor version: {d}, body: \"{s}\"", .{
                        ctx,
                        peer.addr,
                        req.method.toString(),
                        req.path,
                        req.minor_version,
                        req.body,
                    });

                    if (mem.startsWith(u8, req.path, "/static")) {
                        return httpserver.Response{
                            .send_file = .{
                                .status_code = .ok,
                                .headers = &[_]httpserver.Header{},
                                .path = req.path[1..],
                            },
                        };
                    } else {
                        return httpserver.Response{
                            .response = .{
                                .status_code = .ok,
                                .headers = &[_]httpserver.Header{},
                                .data = "Hello, World in handler!",
                            },
                        };
                    }
                }
            }.handle,
        );
    }
    defer {
        for (servers) |*item| item.server.deinit();
        allocator.free(servers);
    }

    for (servers) |*item| {
        item.thread = try std.Thread.spawn(
            .{},
            struct {
                fn worker(server: *httpserver.Server(usize)) !void {
                    return server.run(1 * time.ns_per_s);
                }
            }.worker,
            .{&item.server},
        );
    }

    for (servers) |*item| item.thread.join();
}

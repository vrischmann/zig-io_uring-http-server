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

const httpserver = @import("lib.zig");

const argsParser = @import("args");

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

const ServerContext = struct {
    const Self = @This();

    id: usize,
    server: httpserver.Server(*Self),
    thread: std.Thread,

    pub fn format(self: *const Self, comptime fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;

        if (comptime !mem.eql(u8, "s", fmt_string)) @compileError("format string must be s");
        try writer.print("{d}", .{self.id});
    }

    fn handleRequest(self: *Self, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
        _ = per_request_allocator;

        logger.debug("ctx#{d:<4} IN HANDLER addr={s} method: {s}, path: {s}, minor version: {d}, body: \"{s}\"", .{
            self.id,
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
};

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };
    var allocator = gpa.allocator();

    //

    const options = try argsParser.parseForCurrentProcess(struct {
        @"listen-port": u16 = 3405,

        @"max-server-threads": usize = 1,
        @"max-ring-entries": u13 = 512,
        @"max-buffer-size": usize = 4096,
        @"max-connections": usize = 128,
    }, allocator, .print);
    defer options.deinit();

    const listen_port = options.options.@"listen-port";
    const max_server_threads = options.options.@"max-server-threads";
    const max_ring_entries = options.options.@"max-ring-entries";
    const max_buffer_size = options.options.@"max-buffer-size";
    const max_connections = options.options.@"max-connections";

    // NOTE(vincent): for debugging
    // var logging_allocator = heap.loggingAllocator(gpa.allocator());
    // var allocator = logging_allocator.allocator();

    addSignalHandlers();

    // Create the server socket
    const server_fd = try httpserver.createSocket(listen_port);

    logger.info("listening on :{d}", .{listen_port});
    logger.info("max server threads: {d}, max ring entries: {d}, max buffer size: {d}, max connections: {d}", .{
        max_server_threads,
        max_ring_entries,
        max_buffer_size,
        max_connections,
    });

    // Create the servers

    var servers = try allocator.alloc(ServerContext, max_server_threads);
    for (servers) |*item, i| {
        item.id = i;
        try item.server.init(
            allocator,
            .{
                .max_ring_entries = max_ring_entries,
                .max_buffer_size = max_buffer_size,
                .max_connections = max_connections,
            },
            &global_running,
            server_fd,
            item,
            ServerContext.handleRequest,
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
                fn worker(server: *httpserver.Server(*ServerContext)) !void {
                    return server.run(1 * time.ns_per_s);
                }
            }.worker,
            .{&item.server},
        );
    }

    for (servers) |*item| item.thread.join();
}

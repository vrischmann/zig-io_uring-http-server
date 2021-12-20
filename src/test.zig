const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const mem = std.mem;
const net = std.net;
const os = std.os;
const testing = std.testing;
const time = std.time;

const Atomic = std.atomic.Atomic;

const curl = @import("curl.zig");

const Server = @import("main.zig").Server;

const port = 34450;

const TestHarness = struct {
    root_allocator: mem.Allocator,
    arena: heap.ArenaAllocator,
    socket: os.socket_t,
    server: Server,
    running: Atomic(bool) = Atomic(bool).init(true),

    fn create(allocator: mem.Allocator) !*TestHarness {
        const socket = blk: {
            const sockfd = try os.socket(os.AF.INET6, os.SOCK.STREAM, 0);
            errdefer os.close(sockfd);

            os.setsockopt(
                sockfd,
                os.SOL.SOCKET,
                os.SO.REUSEADDR,
                &mem.toBytes(@as(c_int, 1)),
            ) catch {};

            const addr = try net.Address.parseIp6("::0", port);

            try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in6));
            try os.listen(sockfd, std.math.maxInt(u31));

            break :blk sockfd;
        };

        var res = try allocator.create(TestHarness);
        res.* = .{
            .root_allocator = allocator,
            .arena = heap.ArenaAllocator.init(allocator),
            .socket = socket,
            .server = undefined,
        };
        try res.server.init(allocator, 0, socket);

        // Start thread

        res.server.thread = try std.Thread.spawn(
            .{},
            struct {
                fn worker(running: *Atomic(bool), server: *Server) !void {
                    while (running.load(.SeqCst)) {
                        try server.ctx.maybeAccept(100 * time.ns_per_ms);
                        try server.ctx.submit();
                        try server.ctx.processCompletions();
                    }
                    // There might be more completions not processed
                    try server.ctx.processCompletions();
                }
            }.worker,
            .{ &res.running, &res.server },
        );

        return res;
    }

    fn deinit(self: *TestHarness) void {
        // Wait for the server to finish
        self.running.store(false, .SeqCst);
        self.server.thread.join();

        // Clean up the server
        self.server.deinit();
        os.close(self.socket);

        // Clean up our own data
        self.arena.deinit();
        self.root_allocator.destroy(self);
    }

    fn do(self: *TestHarness, method: []const u8, path: []const u8) !curl.Response {
        var buf: [1024]u8 = undefined;
        const url = try fmt.bufPrintZ(&buf, "http://localhost:{d}{s}", .{
            port,
            path,
        });

        return curl.do(self.root_allocator, method, url);
    }
};

test "GET 200 OK" {
    var th = try TestHarness.create(testing.allocator);
    defer th.deinit();

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var resp = try th.do("GET", "/plaintext");
        defer resp.deinit();

        try testing.expectEqual(@as(usize, 200), resp.response_code);
        try testing.expectEqualStrings("Hello, World!", resp.data);
    }
}

test "GET 404 Not Found" {
    var th = try TestHarness.create(testing.allocator);
    defer th.deinit();

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var resp = try th.do("GET", "/static/notfound.txt");
        defer resp.deinit();

        try testing.expectEqual(@as(usize, 404), resp.response_code);
        try testing.expectEqual(@as(usize, 0), resp.data.len);
    }
}

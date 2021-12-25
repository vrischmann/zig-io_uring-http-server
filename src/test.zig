const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const mem = std.mem;
const net = std.net;
const os = std.os;
const testing = std.testing;
const time = std.time;

const Atomic = std.atomic.Atomic;
const assert = std.debug.assert;

const curl = @import("curl.zig");
const httpserver = @import("httpserver");

const port = 34450;

const TestHarness = struct {
    const Self = @This();

    root_allocator: mem.Allocator,
    arena: heap.ArenaAllocator,
    socket: os.socket_t,
    running: Atomic(bool) = Atomic(bool).init(true),
    server: httpserver.Server(*Self),
    thread: std.Thread,

    fn create(allocator: mem.Allocator, comptime handler: httpserver.RequestHandler(*Self)) !*TestHarness {
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
            .thread = undefined,
        };
        try res.server.init(allocator, 0, &res.running, socket, res, handler);

        // Start thread

        res.thread = try std.Thread.spawn(
            .{},
            struct {
                fn worker(server: *httpserver.Server(*Self)) !void {
                    return server.run(10 * time.ns_per_ms);
                }
            }.worker,
            .{&res.server},
        );

        return res;
    }

    fn deinit(self: *TestHarness) void {
        // Wait for the server to finish
        self.running.store(false, .SeqCst);
        self.thread.join();

        // Clean up the server
        self.server.deinit();
        os.close(self.socket);

        // Clean up our own data
        self.arena.deinit();
        self.root_allocator.destroy(self);
    }

    fn do(self: *TestHarness, method: []const u8, path: []const u8, body_opt: ?[]const u8) !curl.Response {
        var buf: [1024]u8 = undefined;
        const url = try fmt.bufPrintZ(&buf, "http://localhost:{d}{s}", .{
            port,
            path,
        });

        return curl.do(self.root_allocator, method, url, body_opt);
    }
};

test "GET 200 OK" {
    // Try to test multiple end conditions for the serving loop

    var i: usize = 1;
    while (i < 20) : (i += 1) {
        var th = try TestHarness.create(
            testing.allocator,
            struct {
                fn handle(ctx: *TestHarness, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.HandlerAction {
                    _ = ctx;
                    _ = peer;
                    _ = req;

                    try testing.expectEqualStrings("GET", req.method);
                    try testing.expect(req.body == null);

                    return httpserver.HandlerAction{
                        .respond = .{
                            .status_code = .ok,
                            .data = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!",
                        },
                    };
                }
            }.handle,
        );
        defer th.deinit();

        var j: usize = 0;
        while (j < i) : (j += 1) {
            var resp = try th.do("GET", "/plaintext", null);
            defer resp.deinit();

            try testing.expectEqual(@as(usize, 200), resp.response_code);
            try testing.expectEqualStrings("Hello, World!", resp.data);
        }
    }
}

test "POST 200 OK" {
    const body =
        \\Perspiciatis eligendi aspernatur iste delectus et et quo repudiandae. Iusto repellat tempora nisi alias. Autem inventore rerum magnam sunt voluptatem aspernatur.
        \\Consequuntur quae non fugit dignissimos at quis. Mollitia nisi minus voluptatem voluptatem sed sunt dolore. Expedita ullam ut ex voluptatem delectus. Fuga quos asperiores consequatur similique voluptatem provident vel. Repudiandae rerum quia dolorem totam.
    ;

    var th = try TestHarness.create(
        testing.allocator,
        struct {
            fn handle(ctx: *TestHarness, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.HandlerAction {
                _ = ctx;
                _ = peer;
                _ = req;

                try testing.expectEqualStrings("POST", req.method);
                try testing.expectEqualStrings(body, req.body.?);

                return httpserver.HandlerAction{
                    .respond = .{
                        .status_code = .ok,
                        .data = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!",
                    },
                };
            }
        }.handle,
    );
    defer th.deinit();

    var i: usize = 1;
    while (i < 20) : (i += 1) {
        var j: usize = 0;
        while (j < i) : (j += 1) {
            var resp = try th.do("POST", "/foobar", body);
            defer resp.deinit();

            try testing.expectEqual(@as(usize, 200), resp.response_code);
            try testing.expectEqualStrings("Hello, World!", resp.data);
        }
    }
}

test "GET files" {
    var th = try TestHarness.create(
        testing.allocator,
        struct {
            fn handle(ctx: *TestHarness, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.HandlerAction {
                _ = ctx;
                _ = peer;
                _ = req;

                try testing.expect(req.body == null);
                try testing.expect(mem.startsWith(u8, req.path, "/static"));

                const path = req.path[1..];

                return httpserver.HandlerAction{
                    .send_file = .{
                        .status_code = .ok,
                        .path = path,
                    },
                };
            }
        }.handle,
    );
    defer th.deinit();

    const test_cases = &[_]struct {
        path: []const u8,
        exp_data: []const u8,
        exp_response_code: usize,
    }{
        .{ .path = "/static/foobar.txt", .exp_data = "foobar content\n", .exp_response_code = 200 },
        .{ .path = "/static/notfound.txt", .exp_data = "", .exp_response_code = 404 },
    };

    inline for (test_cases) |tc| {
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            var resp = try th.do("GET", tc.path, null);
            defer resp.deinit();

            try testing.expectEqual(tc.exp_response_code, resp.response_code);
            try testing.expectEqualStrings(tc.exp_data, resp.data);
        }
    }
}

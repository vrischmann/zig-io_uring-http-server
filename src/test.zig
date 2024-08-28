const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const mem = std.mem;
const net = std.net;
const os = std.os;
const testing = std.testing;
const time = std.time;
const posix = std.posix;

const Atomic = std.atomic.Value;
const assert = std.debug.assert;

const httpserver = @import("lib.zig");

const curl = @import("curl.zig");

const port = 34450;

const TestHarness = struct {
    const Self = @This();

    root_allocator: mem.Allocator,
    arena: heap.ArenaAllocator,
    socket: posix.socket_t,
    running: Atomic(bool) = Atomic(bool).init(true),
    server: httpserver.Server(*Self),
    thread: std.Thread,

    pub fn format(self: *const Self, comptime fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt_string;
        _ = options;
        try writer.writeAll("0");
    }

    fn create(allocator: mem.Allocator, comptime handler: httpserver.RequestHandler(*Self)) !*TestHarness {
        const socket = blk: {
            const sockfd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, 0);
            errdefer posix.close(sockfd);

            posix.setsockopt(
                sockfd,
                posix.SOL.SOCKET,
                posix.SO.REUSEADDR,
                &mem.toBytes(@as(c_int, 1)),
            ) catch {};

            const addr = try net.Address.parseIp6("::0", port);

            try posix.bind(sockfd, &addr.any, @sizeOf(posix.sockaddr.in6));
            try posix.listen(sockfd, std.math.maxInt(u31));

            break :blk sockfd;
        };

        var res = try allocator.create(TestHarness);
        errdefer allocator.destroy(res);

        res.* = .{
            .root_allocator = allocator,
            .arena = heap.ArenaAllocator.init(allocator),
            .socket = socket,
            .server = undefined,
            .thread = undefined,
        };
        try res.server.init(
            allocator,
            .{},
            &res.running,
            socket,
            res,
            handler,
        );

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
        self.running.store(false, .seq_cst);
        self.thread.join();

        // Clean up the server
        self.server.deinit();
        posix.close(self.socket);

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
                fn handle(ctx: *TestHarness, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                    _ = ctx;
                    _ = per_request_allocator;
                    _ = peer;

                    try testing.expectEqualStrings("/plaintext", req.path);
                    try testing.expectEqual(httpserver.Method.get, req.method);
                    try testing.expect(req.headers.get("Host") != null);
                    try testing.expectEqualStrings("*/*", req.headers.get("Accept").?.value);
                    try testing.expect(req.headers.get("Content-Length") == null);
                    try testing.expect(req.headers.get("Content-Type") == null);
                    try testing.expect(req.body == null);

                    return httpserver.Response{
                        .response = .{
                            .status_code = .ok,
                            .headers = &[_]httpserver.Header{},
                            .data = "Hello, World!",
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
            fn handle(ctx: *TestHarness, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                _ = ctx;
                _ = per_request_allocator;
                _ = peer;

                try testing.expectEqualStrings("/foobar", req.path);
                try testing.expectEqual(httpserver.Method.post, req.method);
                try testing.expect(req.headers.get("Host") != null);
                try testing.expectEqualStrings("*/*", req.headers.get("Accept").?.value);
                try testing.expectEqualStrings("application/json", req.headers.get("Content-Type").?.value);
                try testing.expectEqual(body.len, try fmt.parseInt(usize, req.headers.get("Content-Length").?.value, 10));
                try testing.expectEqualStrings(body, req.body.?);

                return httpserver.Response{
                    .response = .{
                        .status_code = .ok,
                        .headers = &[_]httpserver.Header{},
                        .data = "Hello, World!",
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
            fn handle(ctx: *TestHarness, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                _ = ctx;
                _ = per_request_allocator;
                _ = peer;

                try testing.expect(mem.startsWith(u8, req.path, "/static"));
                try testing.expect(req.headers.get("Host") != null);
                try testing.expectEqualStrings("*/*", req.headers.get("Accept").?.value);
                try testing.expect(req.headers.get("Content-Length") == null);
                try testing.expect(req.headers.get("Content-Type") == null);
                try testing.expect(req.body == null);

                const path = req.path[1..];

                return httpserver.Response{
                    .send_file = .{
                        .status_code = .ok,
                        .headers = &[_]httpserver.Header{},
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
        .{ .path = "/static/notfound.txt", .exp_data = "Not Found", .exp_response_code = 404 },
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

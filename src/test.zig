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

const IO_Uring = std.os.linux.IO_Uring;
const io_uring_cqe = std.os.linux.io_uring_cqe;
const io_uring_sqe = std.os.linux.io_uring_sqe;

const httpserver = @import("lib.zig");

const curl = @import("curl.zig");

const port = 34450;
const addr = net.Address.parseIp6("::0", port) catch unreachable;

fn createTestSocket() !os.socket_t {
    const sockfd = try os.socket(os.AF.INET6, os.SOCK.STREAM, 0);
    errdefer os.close(sockfd);

    os.setsockopt(
        sockfd,
        os.SOL.SOCKET,
        os.SO.REUSEADDR,
        &mem.toBytes(@as(c_int, 1)),
    ) catch {};

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in6));
    try os.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

const TestHarness = struct {
    const HTTP = struct {
        const Self = @This();

        root_allocator: mem.Allocator,
        arena: heap.ArenaAllocator,
        socket: os.socket_t,
        running: Atomic(bool) = Atomic(bool).init(true),

        server: httpserver.Server(*Self),
        thread: std.Thread,

        pub fn format(self: *const Self, comptime fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = self;
            _ = fmt_string;
            _ = options;
            try writer.writeAll("0");
        }

        fn create(allocator: mem.Allocator, comptime handler: httpserver.RequestHandler(*Self)) !*Self {
            var res = try allocator.create(Self);
            res.* = .{
                .root_allocator = allocator,
                .arena = heap.ArenaAllocator.init(allocator),
                .socket = try createTestSocket(),
                .server = undefined,
                .thread = undefined,
            };
            try res.server.init(allocator, .{}, &res.running, res.socket, res, handler);

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

        fn deinit(self: *Self) void {
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

        fn do(self: *Self, method: []const u8, path: []const u8, body_opt: ?[]const u8) !curl.Response {
            var buf: [1024]u8 = undefined;
            const url = try fmt.bufPrintZ(&buf, "http://localhost:{d}{s}", .{
                port,
                path,
            });

            return curl.do(self.root_allocator, method, url, body_opt);
        }
    };

    const TCP = struct {
        const Self = @This();

        root_allocator: mem.Allocator,
        arena: heap.ArenaAllocator,
        socket: os.socket_t,
        running: Atomic(bool) = Atomic(bool).init(true),

        server: httpserver.TCPServer(*Self),
        thread: std.Thread,

        conn: net.Stream,

        pub fn format(self: *const Self, comptime fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = self;
            _ = fmt_string;
            _ = options;
            try writer.writeAll("0");
        }

        fn create(allocator: mem.Allocator) !*Self {
            var res = try allocator.create(Self);
            res.* = .{
                .root_allocator = allocator,
                .arena = heap.ArenaAllocator.init(allocator),
                .socket = try createTestSocket(),
                .server = undefined,
                .thread = undefined,
                .conn = undefined,
            };
            try res.server.init(allocator, .{}, &res.running, res.socket, res);

            // Start thread
            res.thread = try std.Thread.spawn(
                .{},
                struct {
                    fn worker(server: *httpserver.TCPServer(*Self)) !void {
                        try server.run(10 * time.ns_per_ms, onAccept);
                    }
                }.worker,
                .{&res.server},
            );

            time.sleep(10 * time.ns_per_ms);

            res.conn = try net.tcpConnectToAddress(addr);

            return res;
        }

        fn deinit(self: *Self) void {
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

        fn onAccept(server: *httpserver.TCPServer(*Self), client: *httpserver.TCPClientState) anyerror!void {
            const self = @fieldParentPtr(TestHarness.TCP, "server", server);

            std.debug.print("ctx#{s:<4} ON ACCEPT accepted connection\n", .{self});

            _ = try server.read(client, client.fd, 0, onRead);
        }

        fn onRead(server: *httpserver.TCPServer(*Self), client: *httpserver.TCPClientState, cqe: io_uring_cqe) !void {
            const self = @fieldParentPtr(TestHarness.TCP, "server", server);

            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    std.debug.panic("ctx#{s:<4} addr={s} broken pipe", .{ self, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    std.debug.panic("ctx#{s:<4} addr={s} connection reset by peer", .{ self, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    std.debug.panic("ctx#{s:<4} addr={s} unexpected errno={}", .{ self, client.peer.addr, err });
                    return error.Unexpected;
                },
            }
            if (cqe.res <= 0) {
                return error.UnexpectedEOF;
            }

            const read = @intCast(usize, cqe.res);

            std.debug.print("ctx#{s:<4} addr={s} ON READ read of {d} bytes succeeded\n", .{ self, client.peer.addr, read });

            try client.buffer.appendSlice(client.temp_buffer[0..read]);

            _ = try server.write(client, client.fd, 0, onWrite);
        }

        fn onWrite(server: *httpserver.TCPServer(*Self), client: *httpserver.TCPClientState, cqe: io_uring_cqe) !void {
            const self = @fieldParentPtr(TestHarness.TCP, "server", server);

            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    std.debug.panic("ctx#{s:<4} addr={s} broken pipe", .{ self, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    std.debug.panic("ctx#{s:<4} addr={s} connection reset by peer", .{ self, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    std.debug.panic("ctx#{s:<4} addr={s} unexpected errno={}", .{ self, client.peer.addr, err });
                    return error.Unexpected;
                },
            }

            const written = @intCast(usize, cqe.res);

            if (written < client.buffer.items.len) {
                // Short write, write the remaining data

                // Remove the already written data
                try client.buffer.replaceRange(0, written, &[0]u8{});

                _ = try server.write(client, client.fd, 0, onWrite);
                return;
            }

            std.debug.print("ctx#{s:<4} addr={s} ON WRITE RESPONSE done\n", .{ self, client.peer.addr });

            client.reset();

            if (!server.running.load(.SeqCst)) return;
            _ = try server.read(client, client.fd, 0, onRead);
        }
    };
};

test "GET 200 OK" {
    // Try to test multiple end conditions for the serving loop

    var i: usize = 1;
    while (i < 20) : (i += 1) {
        var th = try TestHarness.HTTP.create(
            testing.allocator,
            struct {
                fn handle(ctx: *TestHarness.HTTP, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                    _ = ctx;
                    _ = per_request_allocator;
                    _ = peer;
                    _ = req;

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

    var th = try TestHarness.HTTP.create(
        testing.allocator,
        struct {
            fn handle(ctx: *TestHarness.HTTP, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                _ = ctx;
                _ = per_request_allocator;
                _ = peer;
                _ = req;

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
    var th = try TestHarness.HTTP.create(
        testing.allocator,
        struct {
            fn handle(ctx: *TestHarness.HTTP, per_request_allocator: mem.Allocator, peer: httpserver.Peer, req: httpserver.Request) anyerror!httpserver.Response {
                _ = ctx;
                _ = per_request_allocator;
                _ = peer;
                _ = req;

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

test "TCP echo" {
    var th = try TestHarness.TCP.create(testing.allocator);
    defer th.deinit();

    const data = "foobar";

    const written = try th.conn.write(data);
    try testing.expectEqual(data.len, written);

    var buf: [128]u8 = undefined;
    const read = try th.conn.read(&buf);
    try testing.expectEqual(data.len, read);
    try testing.expectEqualStrings(data, buf[0..read]);
}

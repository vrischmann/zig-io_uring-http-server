const std = @import("std");
const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const assert = std.debug.assert;

const IO_Uring = std.os.linux.IO_Uring;
const io_uring_cqe = std.os.linux.io_uring_cqe;

const max_ring_entries = 512;
const max_buffer_size = 4096;

const c = @cImport({
    @cInclude("picohttpparser.h");
});

const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Request type contains fields populated by picohttpparser and provides
/// helpers methods for easier use with Zig.
const Request = struct {
    const max_headers = 100;

    method: [*c]u8 = undefined,
    method_len: usize = undefined,
    path: [*c]u8 = undefined,
    path_len: usize = undefined,
    minor_version: c_int = 0,
    headers: [max_headers]c.phr_header = undefined,
    num_headers: usize = max_headers,

    pub fn getMethod(self: @This()) []const u8 {
        return self.method[0..self.method_len];
    }

    pub fn getPath(self: @This()) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn getMinorVersion(self: @This()) usize {
        return @intCast(usize, self.minor_version);
    }

    pub fn getHeaders(self: @This(), allocator: *mem.Allocator) ![]const Header {
        var res = try allocator.alloc(Header, self.num_headers);

        var i: usize = 0;
        while (i < self.num_headers) : (i += 1) {
            const hdr = self.headers[i];

            res[i] = .{
                .name = hdr.name[0..hdr.name_len],
                .value = hdr.value[0..hdr.value_len],
            };
        }

        return res;
    }
};

const ParseRequestResult = struct {
    req: Request,
    consumed: usize,
};

fn parseRequest(previous_buffer_len: usize, buffer: []const u8) !?ParseRequestResult {
    var req = Request{};

    const res = c.phr_parse_request(
        buffer.ptr,
        buffer.len,
        &req.method,
        &req.method_len,
        &req.path,
        &req.path_len,
        &req.minor_version,
        &req.headers,
        &req.num_headers,
        previous_buffer_len,
    );
    if (res == -1) {
        std.debug.panic("parse error\n", .{});
    }
    if (res == -2) {
        return null;
    }

    return ParseRequestResult{
        .req = req,
        .consumed = @intCast(usize, res),
    };
}

const Completion = struct {
    const Self = @This();

    ring: *IO_Uring,
    operation: Operation,
    parent: enum {
        global,
        connection,
    } = .global,

    fn prep(self: *Self) !void {
        switch (self.operation) {
            .accept => |*op| {
                _ = try self.ring.accept(
                    @ptrToInt(self),
                    op.socket,
                    &op.addr,
                    &op.addr_len,
                    0,
                );
            },
            .recv => |*op| {
                _ = try self.ring.recv(
                    @ptrToInt(self),
                    op.socket,
                    op.buffer,
                    0,
                );
            },
            .close => |*op| {
                _ = try self.ring.close(
                    @ptrToInt(self),
                    op.socket,
                );
            },
            .send => |*op| {
                _ = try self.ring.send(
                    @ptrToInt(self),
                    op.socket,
                    op.buffer,
                    0,
                );
            },
        }
    }

    fn prepAccept(self: *Self, ring: *IO_Uring, socket: os.socket_t) !void {
        self.* = .{
            .ring = ring,
            .operation = .{
                .accept = .{
                    .socket = socket,
                    .addr = undefined,
                },
            },
        };
        try self.prep();
    }
};

const Operation = union(enum) {
    accept: struct {
        socket: os.socket_t,
        addr: os.sockaddr,
        addr_len: os.socklen_t = @sizeOf(os.sockaddr),
    },
    recv: struct {
        socket: os.socket_t,
        buffer: []u8,
    },
    close: struct {
        socket: os.socket_t,
    },
    send: struct {
        socket: os.socket_t,
        buffer: []const u8,
    },
};

const Connection = struct {
    const Self = @This();

    // Holds the connection state.
    state: enum {
        free,
        connected,
        terminating,
    } = .free,

    // The socket used for all operations.
    socket: os.socket_t = -1,
    // Holds the remote endpoint address.
    addr: net.Address = net.Address{
        .any = .{
            .family = os.AF_INET,
            .data = [_]u8{0} ** 14,
        },
    },

    // Completions used for submitting operations to io_uring
    recv_completion: Completion = undefined,
    send_completion: Completion = undefined,
    close_completion: Completion = undefined,

    // Temporary buffer used for reading data
    temp_buffer: [max_buffer_size]u8 = undefined,
    // Dynamic buffer used to hold data across multiple read or write calls.
    // For example, a complete HTTP request.
    buffer: std.ArrayList(u8),

    // Holds state for HTTP request parsing.
    http_request: struct {
        // The current state in request parsing.
        state: enum {
            reading_request,
            reading_body,
            write_response,
        } = .reading_request,

        content_length: usize = 0,
        remaining_body_to_read: usize = 0,
    } = .{},

    // Holds low-level statistics.
    statistics: struct {
        connect_time: i64 = 0,
        bytes_recv: usize = 0,
        bytes_sent: usize = 0,
    } = .{},

    fn prepRecv(self: *Self, ring: *IO_Uring) !void {
        self.recv_completion = .{
            .ring = ring,
            .operation = .{
                .recv = .{
                    .socket = self.socket,
                    .buffer = &self.temp_buffer,
                },
            },
            .parent = .connection,
        };
        try self.recv_completion.prep();
    }

    fn prepSend(self: *Self, ring: *IO_Uring, data: []const u8) !void {
        self.send_completion = .{
            .ring = ring,
            .operation = .{
                .send = .{
                    .socket = self.socket,
                    .buffer = data,
                },
            },
            .parent = .connection,
        };
        try self.send_completion.prep();
    }

    fn prepClose(self: *Self, ring: *IO_Uring) !void {
        self.close_completion = .{
            .ring = ring,
            .operation = .{
                .close = .{
                    .socket = self.socket,
                },
            },
            .parent = .connection,
        };
        try self.close_completion.prep();
    }
};

fn createServer(port: u16) !os.socket_t {
    const sockfd = try os.socket(os.AF_INET6, os.SOCK_STREAM, 0);
    errdefer os.close(sockfd);

    // Enable reuseaddr if possible
    os.setsockopt(
        sockfd,
        os.SOL_SOCKET,
        os.SO_REUSEADDR,
        &mem.toBytes(@as(c_int, 1)),
    ) catch {};

    // Disable IPv6 only
    try os.setsockopt(
        sockfd,
        os.IPPROTO_IPV6,
        os.linux.IPV6_V6ONLY,
        &mem.toBytes(@as(c_int, 0)),
    );

    const addr = try net.Address.parseIp6("::0", port);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr_in6));
    try os.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

const AcceptState = struct {
    completion: Completion = undefined,
};

const logger = std.log.scoped(.main);

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };

    var allocator = &gpa.allocator;

    var connections = try allocator.alloc(Connection, 8);
    for (connections) |*connection| {
        connection.* = .{
            .buffer = std.ArrayList(u8).init(allocator),
        };
    }
    defer {
        for (connections) |connection| {
            connection.buffer.deinit();
        }
        allocator.free(connections);
    }

    //
    // Ignore broken pipes
    var act = os.Sigaction{
        .handler = .{
            .sigaction = os.SIG_IGN,
        },
        .mask = os.empty_sigset,
        .flags = 0,
    };
    os.sigaction(os.SIGPIPE, &act, null);

    // Create the server
    const server_fd = try createServer(3405);

    // Create the ring
    var cqes: [max_ring_entries]io_uring_cqe = undefined;

    var ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0);
    defer ring.deinit();

    // Accept connections indefinitely
    var global_accept: AcceptState = undefined;
    try global_accept.completion.prepAccept(&ring, server_fd);

    while (true) {
        // Process CQEs
        const count = try ring.copy_cqes(cqes[0..], 0);

        for (cqes[0..count]) |cqe| {
            if (cqe.user_data == 0) {
                logger.err("received completion with no user data", .{});
                os.exit(1);
            }

            const completion = @intToPtr(*Completion, cqe.user_data);
            switch (completion.operation) {
                .accept => |*op| {
                    assert(completion.parent == .global);

                    if (cqe.res < 0) {
                        switch (-cqe.res) {
                            os.EPIPE => logger.warn("ACCEPT broken pipe", .{}),
                            os.ECONNRESET => logger.warn("ACCEPT connection reset by peer", .{}),
                            os.EMFILE => logger.warn("ACCEPT too many open files", .{}),
                            else => {
                                logger.err("ERROR {}\n", .{cqe});
                                os.exit(1);
                            },
                        }
                    } else {
                        // Get a connection object and initialize all state.
                        //
                        // If no connection is free we don't do anything.
                        var connection = for (connections) |*conn| {
                            if (conn.state == .free) {
                                conn.state = .connected;
                                break conn;
                            }
                        } else {
                            logger.warn("no free connection available", .{});

                            try global_accept.completion.prepAccept(&ring, server_fd);
                            continue;
                        };

                        connection.addr = net.Address{ .any = op.addr };
                        connection.socket = @intCast(os.socket_t, cqe.res);
                        connection.statistics.connect_time = time.milliTimestamp();

                        logger.info("ACCEPT fd={} host={}", .{
                            connection.socket,
                            connection.addr,
                        });

                        // Enqueue a new recv request
                        try connection.prepRecv(&ring);
                        // Enqueue a new accept request
                        try global_accept.completion.prepAccept(&ring, server_fd);
                    }
                },
                .recv => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "recv_completion", completion);
                    assert(connection.state == .connected);

                    // handle errors
                    if (cqe.res <= 0) {
                        switch (-cqe.res) {
                            os.EPIPE => logger.info("RECV host={} fd={} broken pipe", .{
                                connection.addr,
                                op.socket,
                            }),
                            os.ECONNRESET => logger.info("RECV host={} fd={} reset by peer", .{
                                connection.addr,
                                op.socket,
                            }),
                            0 => logger.info("RECV host={} fd={} end of file", .{
                                connection.addr,
                                op.socket,
                            }),
                            else => logger.warn("RECV host={} fd={} errno {d}", .{
                                connection.addr,
                                op.socket,
                                cqe.res,
                            }),
                        }

                        connection.state = .terminating;
                        try connection.prepClose(&ring);
                    } else {
                        const recv = @intCast(usize, cqe.res);
                        connection.statistics.bytes_recv += recv;

                        const data = connection.temp_buffer[0..recv];

                        const previous_buffer_len = connection.buffer.items.len;

                        // Append data to complete request buffer
                        try connection.buffer.appendSlice(data);

                        logger.info("RECV host={} fd={} data={s} fulldata={s} ({s})", .{
                            connection.addr,
                            connection.socket,
                            fmt.fmtSliceEscapeLower(data),
                            fmt.fmtSliceEscapeLower(connection.buffer.items),
                            fmt.fmtIntSizeBin(data.len),
                        });

                        // Try to parse the request
                        if (try parseRequest(previous_buffer_len, connection.buffer.items)) |result| {
                            const req = result.req;
                            _ = req;
                        }

                        // Enqueue a new recv request
                        try connection.prepRecv(&ring);
                    }
                },
                .close => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "close_completion", completion);
                    assert(connection.state == .terminating);

                    const elapsed = time.milliTimestamp() - connection.statistics.connect_time;

                    logger.info("CLOSE host={} fd={} totalrecv={s} totalsent={s} elapsed={s}", .{
                        connection.addr,
                        op.socket,
                        fmt.fmtIntSizeBin(@intCast(u64, connection.statistics.bytes_recv)),
                        fmt.fmtIntSizeBin(@intCast(u64, connection.statistics.bytes_sent)),
                        fmt.fmtDuration(@intCast(u64, elapsed * time.ns_per_ms)),
                    });

                    const buffer = connection.buffer;
                    connection.* = .{
                        .buffer = buffer,
                    };
                },
                .send => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "send_completion", completion);
                    assert(connection.state == .connected);

                    // handle errors
                    if (cqe.res <= 0) {
                        switch (-cqe.res) {
                            os.EPIPE => logger.info("SEND host={} fd={} broken pipe", .{
                                connection.addr,
                                op.socket,
                            }),
                            os.ECONNRESET => logger.info("SEND host={} fd={} reset by peer", .{
                                connection.addr,
                                op.socket,
                            }),
                            0 => logger.info("SEND host={} fd={} end of file", .{
                                connection.addr,
                                op.socket,
                            }),
                            else => logger.warn("SEND host={} fd={} errno {d}", .{
                                connection.addr,
                                op.socket,
                                cqe.res,
                            }),
                        }

                        connection.state = .terminating;
                        try connection.prepClose(&ring);
                    } else {
                        const sent = @intCast(usize, cqe.res);
                        connection.statistics.bytes_sent += sent;

                        logger.debug("SENT host={} fd={} ({s})", .{
                            connection.addr,
                            connection.socket,
                            fmt.fmtIntSizeBin(sent),
                        });
                    }
                },
            }
        }

        _ = try ring.submit_and_wait(1);
    }
}

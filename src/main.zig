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
const max_connections = 2;

const logger = std.log.scoped(.main);

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
    const Self = @This();

    const max_headers = 100;

    method: [*c]u8 = undefined,
    method_len: usize = undefined,
    path: [*c]u8 = undefined,
    path_len: usize = undefined,
    minor_version: c_int = 0,
    headers: [max_headers]c.phr_header = undefined,
    num_headers: usize = max_headers,

    pub fn getMethod(self: Self) []const u8 {
        return self.method[0..self.method_len];
    }

    pub fn getPath(self: Self) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn getMinorVersion(self: Self) usize {
        return @intCast(usize, self.minor_version);
    }

    pub fn iterateHeaders(self: Self, comptime f: anytype) blk: {
        const ReturnType = @typeInfo(@TypeOf(f)).Fn.return_type.?;
        break :blk ReturnType;
    } {
        var i: usize = 0;
        while (i < self.num_headers) : (i += 1) {
            const hdr = self.headers[i];

            const name = hdr.name[0..hdr.name_len];
            const value = hdr.value[0..hdr.value_len];

            const result_or_null = try @call(.{}, f, .{ name, value });
            if (result_or_null) |result| {
                return result;
            }
        }
        return null;
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

const CompletionParent = enum {
    global,
    connection,
};

const Completion = struct {
    const Self = @This();

    ring: *IO_Uring = undefined,
    operation: Operation = undefined,
    parent: CompletionParent = undefined,

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
            .parent = .global,
        };
        try self.prep();
    }

    fn prepClose(self: *Self, ring: *IO_Uring, socket: os.socket_t) !void {
        self.* = .{
            .ring = ring,
            .operation = .{
                .close = .{
                    .socket = socket,
                },
            },
            .parent = .global,
        };
        try self.prep();
    }
};

const Operation = union(enum) {
    const Accept = struct {
        socket: os.socket_t,
        addr: os.sockaddr,
        addr_len: os.socklen_t = @sizeOf(os.sockaddr),
    };

    const Close = struct {
        socket: os.socket_t,
    };

    const Recv = struct {
        socket: os.socket_t,
        buffer: []u8,
    };

    const Send = struct {
        socket: os.socket_t,
        buffer: []const u8,
    };

    accept: Accept,
    recv: Recv,
    close: Close,
    send: Send,
};

const HTTPHandlingState = struct {
    const Self = @This();

    // The current state in request handling.
    state: enum {
        reading_request,
        reading_body,
        write_response,
    } = .reading_request,

    request_body: union(enum) {
        fixed_size: struct {
            size: usize,
            current_data: []const u8,
        },
        none,
    } = .none,

    // TODO(vincent): split response headers and stuff from actual body ?
    response_body: []const u8 = "",

    pub fn resetBodies(self: *Self) void {
        self.request_body = .none;
        self.response_body = "";
    }
};

const Connection = struct {
    const Self = @This();

    // Holds low-level statistics.
    statistics: struct {
        connect_time: i64 = 0,
        bytes_recv: usize = 0,
        bytes_sent: usize = 0,
    } = .{},

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

    // TODO(vincent): make this request specific ? and add other state for the response ?
    // Temporary buffer used for reading data
    temp_buffer: [max_buffer_size]u8 = undefined,
    // Dynamic buffer used to hold data across multiple read or write calls.
    // For example, a complete HTTP request.
    buffer: std.ArrayList(u8),

    // Holds state for HTTP handling.
    http_handling: HTTPHandlingState = .{},

    // Resets both temporary buffer and dynamic buffer.
    // TODO(vincent): better naming ?
    fn resetBuffer(self: *Self) void {
        mem.set(u8, &self.temp_buffer, undefined);
        self.buffer.clearRetainingCapacity();
    }

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

const AcceptError = error{
    // from IO_Uring.get_sqe
    SubmissionQueueFull,

    NoFreeConnection,
};

fn handleAccept(ring: *IO_Uring, res: i32, op: *Operation.Accept, connections: []Connection) AcceptError!void {
    // Handle errors
    if (res < 0) {
        switch (@intToEnum(os.E, -res)) {
            .PIPE => logger.warn("ACCEPT broken pipe", .{}),
            .CONNRESET => logger.warn("ACCEPT connection reset by peer", .{}),
            .MFILE => logger.warn("ACCEPT too many open files", .{}),
            else => {
                logger.err("ERROR {}\n", .{res});
                os.exit(1);
            },
        }
        return;
    }

    const socket = @intCast(os.socket_t, res);

    // Get a connection object and initialize all state.
    //
    // If no connection is free we don't do anything.
    var connection = for (connections) |*conn| {
        if (conn.state == .free) {
            conn.state = .connected;
            break conn;
        }
    } else {
        global_close.addr.any = op.addr;
        try global_close.completion.prepClose(ring, socket);

        return error.NoFreeConnection;
    };

    connection.statistics.connect_time = time.milliTimestamp();

    connection.socket = socket;
    connection.addr.any = op.addr;
    connection.resetBuffer();

    logger.info("ACCEPT fd={} host={}", .{
        connection.socket,
        connection.addr,
    });

    // Enqueue a new recv request
    try connection.prepRecv(ring);
}

const CloseError = error{
    // from IO_Uring.get_sqe
    SubmissionQueueFull,
};

fn handleClose(completion: *Completion, op: *Operation.Close) CloseError!void {
    switch (completion.parent) {
        .connection => {
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
        .global => {
            const state = @fieldParentPtr(GlobalCloseState, "completion", completion);

            logger.info("CLOSE ORPHANED SOCKET host={} fd={}", .{
                state.addr,
                op.socket,
            });
        },
    }
}

const RecvError = error{
    // from IO_Uring.get_sqe
    SubmissionQueueFull,

    OutOfMemory,
} || std.fmt.ParseIntError;

fn handleRecv(ring: *IO_Uring, completion: *Completion, res: i32, op: *Operation.Recv) RecvError!void {
    var connection = @fieldParentPtr(Connection, "recv_completion", completion);
    assert(connection.state == .connected);

    // handle errors
    if (res <= 0) {
        if (res == 0) {
            logger.info("RECV host={} fd={} end of file", .{
                connection.addr,
                op.socket,
            });
        } else {
            switch (@intToEnum(os.E, -res)) {
                .PIPE => logger.info("RECV host={} fd={} broken pipe", .{
                    connection.addr,
                    op.socket,
                }),
                .CONNRESET => logger.info("RECV host={} fd={} reset by peer", .{
                    connection.addr,
                    op.socket,
                }),
                else => logger.warn("RECV host={} fd={} errno {d}", .{
                    connection.addr,
                    op.socket,
                    res,
                }),
            }
        }

        connection.state = .terminating;
        try connection.prepClose(ring);

        return;
    }

    // If not an error this is the number of bytes received.
    const recv = @intCast(usize, res);
    connection.statistics.bytes_recv += recv;

    // Get a slice of the received data.
    const data = connection.temp_buffer[0..recv];

    // Used by picohttpparser.
    const previous_buffer_len = connection.buffer.items.len;

    // Append the received data to the full data buffer.
    try connection.buffer.appendSlice(data);

    logger.info("RECV host={} fd={} data={s} fulldata={s} ({s})", .{
        connection.addr,
        connection.socket,
        fmt.fmtSliceEscapeLower(data[0..std.math.min(data.len, 8)]),
        fmt.fmtSliceEscapeLower(connection.buffer.items[0..std.math.min(connection.buffer.items.len, 16)]),
        fmt.fmtIntSizeBin(data.len),
    });

    // Start handling the received data.
    //
    // The HTTP handling can be in two states currently:
    // * reading a request
    // * reading the body of a request
    //
    // The handler starts by reading a request; it stays in this state until a request has been parsed
    // or the buffer gets too big.
    //
    // When parsing a request successfully, the next step is to read the body if there is one.
    // TODO(vincent): currently only body defined by a Content-Length header are handled; chunked encoding doesn't work.

    switch (connection.http_handling.state) {
        .reading_request => if (try parseRequest(previous_buffer_len, connection.buffer.items)) |result| {
            logger.info("got request, method={s} path={s}", .{
                result.req.getMethod(),
                result.req.getPath(),
            });

            // Get the Content-Length if it exists.
            // TODO(vincent): also handle chunked encoding ?
            const content_length_or_null = try result.req.iterateHeaders(
                struct {
                    fn do(name: []const u8, value: []const u8) !?usize {
                        if (!mem.eql(u8, "Content-Length", name)) return null;

                        return try fmt.parseInt(usize, value, 10);
                    }
                }.do,
            );

            // Trim the request data consumed by the parser
            try connection.buffer.replaceRange(0, result.consumed, &[0]u8{});

            if (content_length_or_null) |content_length| {
                logger.debug("content length: {d}", .{content_length});

                connection.http_handling.request_body = .{
                    .fixed_size = .{
                        .size = content_length,
                        .current_data = connection.buffer.items,
                    },
                };

                // Switch to reading the remaining body data.
                connection.http_handling.state = .reading_body;

                // Enqueue a new recv request
                try connection.prepRecv(ring);
            } else {
                // No body expected: switch to writing the response
                // TODO(vincent): get the response somewhere ?

                connection.http_handling.response_body = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                connection.http_handling.state = .write_response;

                // Enqueue a new send request
                try connection.prepSend(ring, connection.http_handling.response_body);
            }
        } else {
            // Incomplete request, expect more data

            // Enqueue a new recv request
            try connection.prepRecv(ring);
        },
        .reading_body => {
            // We're reading the body, defined what to do based on the type of body we're handling.
            //
            // A body can be:
            // * a blob of data of a fixed size, defined by the Content-Length header
            // * data chunked using the chunked encoding
            // TODO(vincent): currently only fixed size body is handled.

            switch (connection.http_handling.request_body) {
                .fixed_size => |*body| {
                    body.current_data = connection.buffer.items;

                    if (body.current_data.len < body.size) {
                        // Not done, keep reading data

                        // Enqueue a new recv request
                        try connection.prepRecv(ring);
                    } else {
                        logger.info("BODY COMPLETE data={s}", .{
                            fmt.fmtSliceEscapeLower(body.current_data),
                        });

                        // Switch to writing the response
                        // TODO(vincent): get the response somewhere ?

                        connection.http_handling.response_body = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                        connection.http_handling.state = .write_response;

                        // Clear the request data.
                        connection.resetBuffer();

                        // Enqueue a new send request
                        try connection.prepSend(ring, connection.http_handling.response_body);
                    }
                },
                .none => {
                    // Switch to reading a new request.
                    connection.http_handling.state = .reading_request;

                    // Enqueue a new recv request
                    try connection.prepRecv(ring);
                },
            }
        },
        else => {
            std.debug.panic("invalid state {}\n", .{connection.http_handling.state});
        },
    }
}

const SendError = error{
    // from IO_Uring.get_sqe
    SubmissionQueueFull,
};

fn handleSend(ring: *IO_Uring, completion: *Completion, res: i32, op: *Operation.Send) SendError!void {
    var connection = @fieldParentPtr(Connection, "send_completion", completion);
    assert(connection.state == .connected);

    // handle errors
    if (res <= 0) {
        if (res == 0) {
            logger.info("SEND host={} fd={} end of file", .{
                connection.addr,
                op.socket,
            });
        } else {
            switch (@intToEnum(os.E, -res)) {
                .PIPE => logger.info("SEND host={} fd={} broken pipe", .{
                    connection.addr,
                    op.socket,
                }),
                .CONNRESET => logger.info("SEND host={} fd={} reset by peer", .{
                    connection.addr,
                    op.socket,
                }),
                else => logger.warn("SEND host={} fd={} errno {d}", .{
                    connection.addr,
                    op.socket,
                    res,
                }),
            }
        }

        connection.state = .terminating;
        try connection.prepClose(ring);

        return;
    }

    // If not an error this is the number of bytes received.
    const sent = @intCast(usize, res);
    connection.statistics.bytes_sent += sent;

    // Can only ever send data if we're in the write_response state.
    assert(connection.http_handling.state == .write_response);

    logger.info("SENT host={} fd={} ({s})", .{
        connection.addr,
        connection.socket,
        fmt.fmtIntSizeBin(sent),
    });

    //

    // It's possible we sent less data than the slice we need to write.
    // If that is the case, get the remaining data slice and enqueue a new send request.
    if (sent < connection.http_handling.response_body.len) {
        const remaining_data = connection.http_handling.response_body[sent..];

        connection.http_handling.response_body = remaining_data;

        // Enqueue a new send request
        try connection.prepSend(ring, connection.http_handling.response_body);
    } else {
        // Switch to reading a new request.
        connection.http_handling.state = .reading_request;

        // Enqueue a new recv request
        try connection.prepRecv(ring);
    }
}

// State for accepting new connections on a listener socket.
var global_accept: struct {
    completion: Completion = undefined,
} = undefined;

const GlobalCloseState = struct {
    completion: Completion = undefined,

    // Holds the remote endpoint address of the socket to be closed.
    addr: net.Address = net.Address{
        .any = .{
            .family = os.AF_INET,
            .data = [_]u8{0} ** 14,
        },
    },
};

// State for closing sockets not yet associated with a connection.
var global_close: GlobalCloseState = undefined;

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };

    var allocator = &gpa.allocator;

    var connections = try allocator.alloc(Connection, max_connections);
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

    logger.info("listening on :3405\n", .{});

    // Create the ring
    var cqes: [max_ring_entries]io_uring_cqe = undefined;

    var ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0);
    defer ring.deinit();

    // Accept connections indefinitely
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

                    handleAccept(&ring, cqe.res, op, connections) catch |err| switch (err) {
                        error.NoFreeConnection => {
                            logger.warn("no free connection available", .{});
                        },
                        else => return err,
                    };
                    try global_accept.completion.prepAccept(&ring, server_fd);
                },
                .recv => |*op| {
                    assert(completion.parent == .connection);

                    try handleRecv(&ring, completion, cqe.res, op);
                },
                .close => |*op| {
                    try handleClose(completion, op);
                },
                .send => |*op| {
                    assert(completion.parent == .connection);

                    try handleSend(&ring, completion, cqe.res, op);
                },
            }
        }

        _ = try ring.submit_and_wait(1);
    }
}

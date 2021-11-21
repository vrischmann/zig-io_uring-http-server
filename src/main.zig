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
const io_uring_sqe = std.os.linux.io_uring_sqe;

const max_ring_entries = 512;
const max_buffer_size = 4096;
const max_connections = 2;

const logger = std.log.scoped(.main);

const c = @cImport({
    @cInclude("picohttpparser.h");
});

const StatusCode = enum(u16) {
    OK = @as(u16, 200),
};

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

fn createServer(port: u16) !os.socket_t {
    const sockfd = try os.socket(os.AF.INET6, os.SOCK.STREAM, 0);
    errdefer os.close(sockfd);

    // Enable reuseaddr if possible
    os.setsockopt(
        sockfd,
        os.SOL.SOCKET,
        os.SO.REUSEADDR,
        &mem.toBytes(@as(c_int, 1)),
    ) catch {};

    // Disable IPv6 only
    try os.setsockopt(
        sockfd,
        os.IPPROTO.IPV6,
        os.linux.IPV6.V6ONLY,
        &mem.toBytes(@as(c_int, 0)),
    );

    const addr = try net.Address.parseIp6("::0", port);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in6));
    try os.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

/// Manages a set of registered file descriptors.
/// The set size is fixed at compile time.
///
/// A client must acquire a file descriptor to use it, and release it when it disconnects.
const RegisteredFileDescriptors = struct {
    const Self = @This();

    const State = enum {
        used,
        free,
    };

    fds: [max_connections]os.fd_t = [_]os.fd_t{-1} ** max_connections,
    states: [max_connections]State = [_]State{.free} ** max_connections,

    pub fn register(self: *Self, ring: *IO_Uring) !void {
        logger.debug("REGISTERED FILE DESCRIPTORS, fds={d}", .{
            self.fds,
        });

        try ring.register_files(self.fds[0..]);
    }

    pub fn update(self: *Self, ring: *IO_Uring) !void {
        logger.debug("UPDATE FILE DESCRIPTORS, fds={d}", .{
            self.fds,
        });

        try ring.register_files_update(0, self.fds[0..]);
    }

    pub fn acquire(self: *Self, fd: os.fd_t) ?i32 {
        // Find a free slot in the states array
        for (self.states) |*state, i| {
            if (state.* == .free) {
                // Slot is free, change its state and set the file descriptor.

                state.* = .used;
                self.fds[i] = fd;

                return @intCast(i32, i);
            }
        } else {
            return null;
        }
    }

    pub fn release(self: *Self, index: i32) void {
        const idx = @intCast(usize, index);

        debug.assert(self.states[idx] == .used);
        debug.assert(self.fds[idx] != -1);

        self.states[idx] = .free;
        self.fds[idx] = -1;
    }
};

const ServerContext = struct {
    const Self = @This();

    root_allocator: *mem.Allocator,
    ring: *IO_Uring,
    clients: std.ArrayList(Client),
    registered_fds: RegisteredFileDescriptors,

    pub fn init(allocator: *mem.Allocator, ring: *IO_Uring) !Self {
        var res = Self{
            .root_allocator = allocator,
            .ring = ring,
            .clients = try std.ArrayList(Client).initCapacity(allocator, max_connections),
            .registered_fds = .{},
        };
        return res;
    }

    pub fn deinit(self: *Self) void {
        self.clients.deinit();
    }

    pub fn handleAccept(self: *Self, cqe: os.linux.io_uring_cqe, remote_addr: *net.Address) !void {
        logger.debug("HANDLE ACCEPT accepting connection from {s}", .{remote_addr});

        switch (cqe.err()) {
            .SUCCESS => {},
            else => |err| {
                logger.err("unexpected errno={}", .{err});
                return error.Unexpected;
            },
        }

        const client_fd = @intCast(os.socket_t, cqe.res);

        var client = try self.clients.addOne();
        try client.init(self.root_allocator, remote_addr.*, client_fd);

        _ = try submitRead(self, client, client_fd, 0);
    }

    pub fn disconnectClient(self: *Self, client: *Client) void {
        _ = self.ring.close(0, client.fd) catch {};

        // Cleanup resources
        releaseRegisteredFileDescriptor(self, client);
        client.deinit();

        var pos = for (self.clients.items) |*item, i| {
            if (item == client) {
                break i;
            }
        } else blk: {
            break :blk null;
        };

        if (pos) |i| {
            logger.debug("DISCONNECT CLIENT removing client {d}", .{i});

            _ = self.clients.orderedRemove(i);
        }
    }
};

fn releaseRegisteredFileDescriptor(ctx: *ServerContext, client: *Client) void {
    if (client.registered_fd) |registered_fd| {
        ctx.registered_fds.release(registered_fd);
        ctx.registered_fds.update(ctx.ring) catch |err| {
            logger.err("unable to update registered file descriptors, err={}", .{err});
        };
        client.registered_fd = null;
    }
}

const Client = struct {
    const Self = @This();

    const State = enum {
        read_request,
        read_body,
        write_response_buffer,
        open_response_file,
        statx_response_file,
        read_response_file,
        write_response_file,
    };

    const Response = struct {
        written: usize = 0,

        status_code: StatusCode = .OK,

        file: struct {
            path: [:0]u8 = undefined,
            fd: os.fd_t = -1,
            statx_buf: os.linux.Statx = undefined,
        } = .{},

        pub fn reset(self: *Response) void {
            const headers = self.headers;
            self.* = .{
                .headers = headers,
            };
        }
    };

    gpa: *mem.Allocator,

    addr: net.Address,
    fd: os.socket_t,

    // Buffer and allocator used for small allocations (nul-terminated path, integer to int conversions etc).
    temp_buffer: [128]u8 = undefined,
    temp_buffer_fba: heap.FixedBufferAllocator = undefined,

    buffer: std.ArrayList(u8),

    state: State = .read_request,

    request: struct {
        result: ParseRequestResult = undefined,
        body: []const u8 = "",
        content_length: ?usize = null,
    } = .{},

    response: Response = .{},

    // non-null if the client was able to acquire a registered file descriptor.
    registered_fd: ?i32 = null,

    pub fn init(self: *Self, allocator: *mem.Allocator, remote_addr: net.Address, client_fd: os.socket_t) !void {
        self.* = .{
            .gpa = allocator,
            .addr = remote_addr,
            .fd = client_fd,
            .buffer = undefined,
        };
        self.temp_buffer_fba = heap.FixedBufferAllocator.init(&self.temp_buffer);

        self.buffer = try std.ArrayList(u8).initCapacity(self.gpa, 128);
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }

    pub fn setBuffer(self: *Self, data: []const u8) void {
        self.buffer.items = self.buffer.items[0..data.len];
        mem.copy(u8, self.buffer.items, data);
    }
};

pub fn dispatch(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) void {
    var res = switch (client.state) {
        .read_request => handleReadRequest(ctx, client, cqe),
        .read_body => handleReadBody(ctx, client, cqe),
        .open_response_file => handleOpenResponseFile(ctx, client, cqe),
        .statx_response_file => handleStatxResponseFile(ctx, client, cqe),
        .read_response_file => handleReadResponseFile(ctx, client, cqe),
        .write_response_file => handleWriteResponseFile(ctx, client, cqe),
        .write_response_buffer => handleWriteResponseBuffer(ctx, client, cqe),
    };

    res catch |err| {
        switch (err) {
            // TODO(vincent): interpret error
            error.UnexpectedEOF => {
                logger.debug("read request failed, err: {}", .{err});
            },
            else => {
                logger.err("read request failed, err: {}", .{err});
            },
        }

        ctx.disconnectClient(client);
    };
}

fn handleReadRequest(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .read_request);

    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("addr={s} broken pipe", .{client.addr});
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("addr={s} connection reset by peer", .{client.addr});
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("addr={s} unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("addr={s} HANDLE READ REQUEST read of {d} bytes succeeded", .{ client.addr, read });

    const previous_len = client.buffer.items.len;
    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    if (try parseRequest(previous_len, client.buffer.items)) |result| {
        client.request.result = result;
        try processRequest(ctx, client);
    } else {
        // Not enough data, read more.

        logger.debug("addr={s} HTTP request incomplete, submitting read", .{client.addr});

        _ = try submitRead(ctx, client, client.fd, 0);
    }
}

fn handleReadBody(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .read_body);

    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("addr={s} broken pipe", .{client.addr});
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("addr={s} connection reset by peer", .{client.addr});
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("addr={s} unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("addr={s} HANDLE READ BODY read of {d} bytes succeeded", .{ client.addr, read });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    const content_length = client.request.content_length.?;

    if (client.buffer.items.len < content_length) {
        logger.debug("addr={s} buffer len={d} bytes, content length={d} bytes", .{
            client.addr,
            client.buffer.items.len,
            content_length,
        });

        // Not enough data, read more.
        _ = try submitRead(ctx, client, client.fd, 0);
        return;
    }

    try processRequestWithBody(ctx, client);
}

fn handleOpenResponseFile(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .open_response_file);
    debug.assert(client.buffer.items.len == 0);

    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        .NOENT => {
            client.temp_buffer_fba.reset();

            logger.err("addr={s} no such file or directory, path=\"{s}\"", .{
                client.addr,
                fmt.fmtSliceEscapeLower(client.response.file.path),
            });

            try submitWriteNotFound(ctx, client);
            return;
        },
        else => |err| {
            logger.err("addr={s} unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }

    client.response.file.fd = @intCast(os.fd_t, cqe.res);

    logger.debug("addr={s} HANDLE OPEN FILE fd={}", .{ client.addr, client.response.file.fd });

    client.temp_buffer_fba.reset();

    // Try to acquire a registered file descriptor.
    client.registered_fd = ctx.registered_fds.acquire(client.response.file.fd);
    if (client.registered_fd != null) {
        try ctx.registered_fds.update(ctx.ring);
    }

    client.state = .statx_response_file;

    try submitStatxFile(
        ctx,
        client,
        client.response.file.fd,
        os.linux.AT.EMPTY_PATH,
        os.linux.STATX_SIZE,
        &client.response.file.statx_buf,
    );
}

fn handleStatxResponseFile(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .statx_response_file);
    debug.assert(client.buffer.items.len == 0);

    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("addr={s} unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }

    logger.debug("addr={s} HANDLE STATX FILE path=\"{s}\" fd={}, size={s}", .{
        client.addr,
        client.response.file.path,
        client.response.file.fd,
        fmt.fmtIntSizeBin(client.response.file.statx_buf.size),
    });

    // Prepare the preambule + headers

    client.response.status_code = .OK;

    var w = client.buffer.writer();

    try w.print("HTTP/1.1 {d} {s}\n", .{
        @enumToInt(client.response.status_code),
        @tagName(client.response.status_code),
    });
    try w.print("Content-Length: {d}\n", .{
        client.response.file.statx_buf.size,
    });
    try w.print("\n", .{});

    //

    client.state = .read_response_file;

    if (client.registered_fd) |registered_fd| {
        var sqe = try submitRead(ctx, client, registered_fd, 0);
        sqe.flags |= os.linux.IOSQE_FIXED_FILE;
    } else {
        _ = try submitRead(ctx, client, client.response.file.fd, 0);
    }
}

fn handleReadResponseFile(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .read_response_file);
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("addr={s} HANDLE READ RESPONSE FILE unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("addr={s} HANDLE READ RESPONSE FILE read of {d} bytes from {d} succeeded", .{
        client.addr,
        read,
        client.response.file.fd,
    });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    client.state = .write_response_file;

    try submitWrite(ctx, client, client.fd, 0);
}

fn handleWriteResponseFile(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .write_response_file);
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("addr={s} HANDLE WRITE RESPONSE FILE unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const written = @intCast(usize, cqe.res);

    logger.debug("addr={s} HANDLE WRITE RESPONSE FILE write of {d} bytes to {d} succeeded", .{
        client.addr,
        written,
        client.fd,
    });

    client.response.written += written;

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        try submitWrite(ctx, client, client.fd, 0);
        return;
    }

    if (client.response.written < client.response.file.statx_buf.size) {
        // More data to read from the file, submit another read

        client.buffer.clearRetainingCapacity();
        client.state = .read_response_file;

        if (client.registered_fd) |registered_fd| {
            var sqe = try submitRead(ctx, client, registered_fd, 0);
            sqe.flags |= os.linux.IOSQE_FIXED_FILE;
        } else {
            _ = try submitRead(ctx, client, client.response.file.fd, 0);
        }
        return;
    }

    logger.debug("addr={s} HANDLE WRITE RESPONSE FILE done", .{
        client.addr,
    });

    // Response file written, read the next request

    releaseRegisteredFileDescriptor(ctx, client);
    // Close the response file descriptor
    try submitClose(ctx, client, client.response.file.fd);
    client.response.file.fd = -1;

    // Reset the client state
    client.request = .{};
    client.response = .{};
    client.buffer.clearRetainingCapacity();
    client.state = .read_request;

    _ = try submitRead(ctx, client, client.fd, 0);
}

fn handleWriteResponseBuffer(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .write_response_buffer);

    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("addr={s} broken pipe", .{client.addr});
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("addr={s} connection reset by peer", .{client.addr});
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("addr={s} unexpected errno={}", .{ client.addr, err });
            return error.Unexpected;
        },
    }

    const written = @intCast(usize, cqe.res);

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        try submitWrite(ctx, client, client.fd, 0);
        return;
    }

    logger.debug("HANDLE WRITE RESPONSE done", .{});

    // Response written, read the next request
    client.request = .{};
    client.buffer.clearRetainingCapacity();
    client.state = .read_request;

    _ = try submitRead(ctx, client, client.fd, 0);
}

fn submitWriteNotFound(ctx: *ServerContext, client: *Client) !void {
    _ = ctx;

    logger.debug("addr={s} returning 404 Not Found", .{
        client.addr,
    });

    const static_response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    client.setBuffer(static_response);
    client.state = .write_response_buffer;

    try submitWrite(ctx, client, client.fd, 0);
}

fn processRequestWithBody(ctx: *ServerContext, client: *Client) !void {
    _ = ctx;

    logger.debug("addr={s} body data=\"{s}\" size={s}", .{
        client.addr,
        fmt.fmtSliceEscapeLower(client.buffer.items),
        fmt.fmtIntSizeBin(@intCast(u64, client.buffer.items.len)),
    });

    // TODO(vincent): actually do something

    const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    client.setBuffer(static_response);
    client.state = .write_response_buffer;

    try submitWrite(ctx, client, client.fd, 0);
}

fn processRequest(ctx: *ServerContext, client: *Client) !void {
    const req = client.request.result.req;

    logger.debug("addr={s} parsed HTTP request", .{client.addr});

    logger.debug("addr={s} method: {s}, path: {s}, minor version: {d}", .{
        client.addr,
        req.getMethod(),
        req.getPath(),
        req.getMinorVersion(),
    });

    const content_length = try req.iterateHeaders(
        struct {
            fn do(name: []const u8, value: []const u8) !?usize {
                if (mem.eql(u8, name, "Content-Length")) {
                    return try fmt.parseUnsigned(usize, value, 10);
                }
                return null;
            }
        }.do,
    );

    logger.debug("addr={s} content length: {d}", .{ client.addr, content_length });

    // If there's a content length we switch to reading the body.
    if (content_length) |n| {
        try client.buffer.replaceRange(0, client.request.result.consumed, &[0]u8{});

        if (n > client.buffer.items.len) {
            logger.debug("addr={s} body incomplete, usable={d} bytes, body data=\"{s}\", content length: {d} bytes", .{
                client.addr,
                client.buffer.items.len,
                fmt.fmtSliceEscapeLower(client.buffer.items),
                n,
            });

            client.state = .read_body;
            client.request.content_length = n;

            _ = try submitRead(ctx, client, client.fd, 0);
            return;
        }

        try processRequestWithBody(ctx, client);
        return;
    }

    // If the request is for a static file, submit an open
    if (mem.startsWith(u8, client.request.result.req.getPath(), "/static/")) {
        const path = client.request.result.req.getPath()[1..];
        if (mem.eql(u8, path, "static/")) {
            return error.InvalidFilePath;
        }

        client.response.file.path = try client.temp_buffer_fba.allocator.dupeZ(u8, path);

        client.buffer.clearRetainingCapacity();
        client.state = .open_response_file;

        try submitOpenFile(
            ctx,
            client,
            client.response.file.path,
            os.linux.O.RDONLY | os.linux.O.NOFOLLOW,
            0644,
        );
        return;
    }

    logger.debug("path: {s}", .{client.request.result.req.getPath()});

    // TODO(vincent): actually do something

    const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    client.setBuffer(static_response);
    client.state = .write_response_buffer;

    try submitWrite(ctx, client, client.fd, 0);
}

fn submitClose(ctx: *ServerContext, client: *Client, fd: os.fd_t) !void {
    logger.debug("addr={s} submitting close of {d}", .{
        client.addr,
        fd,
    });

    // NOTE(vincent): should we also handle close CQEs ?
    var sqe = try ctx.ring.close(0, fd);
    _ = sqe;
}

fn submitRead(ctx: *ServerContext, client: *Client, fd: os.socket_t, offset: u64) !*io_uring_sqe {
    logger.debug("addr={s} submitting read from {d}, offset {d}", .{
        client.addr,
        fd,
        offset,
    });

    return ctx.ring.read(
        @ptrToInt(client),
        fd,
        &client.temp_buffer,
        offset,
    );
}

fn submitWrite(ctx: *ServerContext, client: *Client, fd: os.fd_t, offset: u64) !void {
    logger.debug("addr={s} submitting write of {s} to {d}, offset {d}, data=\"{s}\"", .{
        client.addr,
        fmt.fmtIntSizeBin(client.buffer.items.len),
        fd,
        offset,
        fmt.fmtSliceEscapeLower(client.buffer.items),
    });

    var sqe = try ctx.ring.write(
        @ptrToInt(client),
        fd,
        client.buffer.items,
        offset,
    );
    _ = sqe;
}

fn submitOpenFile(ctx: *ServerContext, client: *Client, path: [:0]const u8, flags: u32, mode: os.mode_t) !void {
    logger.debug("addr={s} submitting open, path=\"{s}\"", .{
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    var sqe = try ctx.ring.openat(
        @ptrToInt(client),
        os.linux.AT.FDCWD,
        path,
        flags,
        mode,
    );
    _ = sqe;
}

fn submitStatxFile(ctx: *ServerContext, client: *Client, fd: os.fd_t, flags: u32, mask: u32, buf: *os.linux.Statx) !void {
    logger.debug("addr={s} submitting statx, fd={d}", .{
        client.addr,
        fd,
    });

    var sqe = try ctx.ring.statx(
        @ptrToInt(client),
        fd,
        "",
        flags,
        mask,
        buf,
    );
    _ = sqe;
}

const StandaloneCQE = enum {
    close,
};
const max_int_standalone_cqe = @enumToInt(StandaloneCQE.close);

fn handleStandaloneCQE(cqe: io_uring_cqe) void {
    const typ = @intToEnum(StandaloneCQE, cqe.user_data);
    switch (typ) {
        .close => {
            switch (cqe.err()) {
                .SUCCESS => {
                    logger.debug("closed file descriptor", .{});
                },
                else => |err| {
                    logger.err("unable to close file descriptor, unexpected errno={}", .{err});
                },
            }
        },
    }
}

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };

    var allocator = &gpa.allocator;

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

    // Create the server
    const server_fd = try createServer(3405);

    logger.info("listening on :3405\n", .{});

    // Create the ring
    // var cqes: [max_ring_entries]io_uring_cqe = undefined;

    var ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0);
    defer ring.deinit();

    // Initialize server context
    var ctx = try ServerContext.init(allocator, &ring);
    defer ctx.deinit();
    try ctx.registered_fds.register(&ring);

    var remote_addr = net.Address{
        .any = undefined,
    };
    var remote_addr_size: u32 = @sizeOf(os.sockaddr);

    var accept_waiting: bool = false;
    var iteration: usize = 0;

    while (true) : (iteration += 1) {
        // std.time.sleep(300 * std.time.ns_per_ms);

        if (!accept_waiting and ctx.clients.items.len < max_connections) {
            const sqe = try ring.accept(
                @ptrToInt(&remote_addr),
                server_fd,
                &remote_addr.any,
                &remote_addr_size,
                0,
            );
            _ = sqe;
            accept_waiting = true;
        }

        _ = try ring.submit_and_wait(1);

        const cqe = try ring.copy_cqe();

        if (cqe.user_data <= max_int_standalone_cqe) {
            handleStandaloneCQE(cqe);
        } else if (cqe.user_data == @ptrToInt(&remote_addr)) {
            try ctx.handleAccept(cqe, &remote_addr);
            accept_waiting = false;
            continue;
        } else for (ctx.clients.items) |*client| {
            if (cqe.user_data != @ptrToInt(client)) {
                continue;
            }

            dispatch(&ctx, client, cqe);
            break;
        }
    }
}

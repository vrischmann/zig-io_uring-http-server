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

const ServerContext = struct {
    const Self = @This();

    root_allocator: *mem.Allocator,
    ring: *IO_Uring,
    clients: std.ArrayList(Client),

    pub fn init(allocator: *mem.Allocator, ring: *IO_Uring) !Self {
        var res = Self{
            .root_allocator = allocator,
            .ring = ring,
            .clients = try std.ArrayList(Client).initCapacity(allocator, max_connections),
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
                logger.err("unexpected errno={d}", .{err});
                return error.Unexpected;
            },
        }

        const client_fd = @intCast(os.socket_t, cqe.res);

        var client = try self.clients.addOne();
        client.init(self.root_allocator, remote_addr.*, client_fd);

        try submitRead(self, client, client_fd, 0);
    }

    pub fn disconnectClient(self: *Self, client: *Client) void {
        _ = self.ring.close(0, client.fd) catch {};

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

const Client = struct {
    const Self = @This();

    const State = enum {
        read_request,
        read_body,
        open_response_file,
        read_response_file,
        write_file,
        write_response,
    };

    arena: heap.ArenaAllocator,

    addr: net.Address,
    fd: os.socket_t,

    temp_buffer: [32]u8 = undefined,
    buffer: std.ArrayList(u8),

    state: State = .read_request,

    current: struct {
        result: ParseRequestResult = undefined,
        body: []const u8 = "",
        content_length: ?usize = null,
    } = .{},

    pub fn init(self: *Self, allocator: *mem.Allocator, remote_addr: net.Address, client_fd: os.socket_t) void {
        self.* = .{
            .arena = heap.ArenaAllocator.init(allocator),
            .addr = remote_addr,
            .fd = client_fd,
            .buffer = undefined,
        };
        self.buffer = std.ArrayList(u8).init(&self.arena.allocator);
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    pub fn setBuffer(self: *Self, data: []const u8) void {
        self.buffer.items = self.buffer.items[0..data.len];
        mem.copy(u8, self.buffer.items, data);
    }
};

const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

pub fn dispatch(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) void {
    var res = switch (client.state) {
        .read_request => handleReadRequest(ctx, client, cqe),
        .read_body => handleReadBody(ctx, client, cqe),
        .open_response_file => handleOpenFile(ctx, client, cqe),
        .write_response => handleWriteResponse(ctx, client, cqe),
        else => {
            std.debug.panic("state {s} not handled", .{client.state});
        },
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
            logger.err("addr={s} unexpected errno={d}", .{ client.addr, err });
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
        client.current.result = result;
        try processRequest(ctx, client);
    } else {
        // Not enough data, read more.

        logger.debug("addr={s} HTTP request incomplete, submitting read", .{client.addr});

        try submitRead(ctx, client, client.fd, 0);
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
            logger.err("addr={s} unexpected errno={d}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("addr={s} HANDLE READ BODY read of {d} bytes succeeded", .{ client.addr, read });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    const content_length = client.current.content_length.?;

    if (client.buffer.items.len < content_length) {
        logger.debug("addr={s} buffer len={d} bytes, content length={d} bytes", .{
            client.addr,
            client.buffer.items.len,
            content_length,
        });

        // Not enough data, read more.
        try submitRead(ctx, client, client.fd, 0);
        return;
    }

    try processRequestWithBody(ctx, client);
}

fn handleOpenFile(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .open_response_file);

    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("addr={s} unexpected errno={d}", .{ client.addr, err });
            return error.Unexpected;
        },
    }
}

fn handleWriteResponse(ctx: *ServerContext, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.state == .write_response);

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
            logger.err("addr={s} unexpected errno={d}", .{ client.addr, err });
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
    client.current = .{};
    client.buffer.clearRetainingCapacity();
    client.state = .read_request;

    try submitRead(ctx, client, client.fd, 0);
}

fn processRequestWithBody(ctx: *ServerContext, client: *Client) !void {
    _ = ctx;

    logger.debug("addr={s} body data=\"{s}\" size={s}", .{
        client.addr,
        fmt.fmtSliceEscapeLower(client.buffer.items),
        fmt.fmtIntSizeBin(@intCast(u64, client.buffer.items.len)),
    });

    // TODO(vincent): actually do something

    client.setBuffer(static_response);
    client.state = .write_response;

    try submitWrite(ctx, client, client.fd, 0);
}

fn processRequest(ctx: *ServerContext, client: *Client) !void {
    const req = client.current.result.req;

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
        try client.buffer.replaceRange(0, client.current.result.consumed, &[0]u8{});

        if (n > client.buffer.items.len) {
            logger.debug("addr={s} body incomplete, usable={d} bytes, body data=\"{s}\", content length: {d} bytes", .{
                client.addr,
                client.buffer.items.len,
                fmt.fmtSliceEscapeLower(client.buffer.items),
                n,
            });

            client.state = .read_body;
            client.current.content_length = n;

            try submitRead(ctx, client, client.fd, 0);
            return;
        }

        try processRequestWithBody(ctx, client);
        return;
    }

    // If the request is for a static file, submit an open
    if (mem.startsWith(u8, client.current.result.req.getPath(), "/static/")) {
        client.state = .open_response_file;

        const path = client.current.result.req.getPath()[1..];
        if (mem.eql(u8, path, "static/")) {
            return error.InvalidFilePath;
        }

        try submitOpenFile(
            ctx,
            client,
            path,
            os.linux.O.RDONLY | os.linux.O.NOFOLLOW,
            0644,
        );
        return;
    }

    logger.debug("path: {s}", .{client.current.result.req.getPath()});

    // TODO(vincent): actually do something

    client.setBuffer(static_response);
    client.state = .write_response;

    try submitWrite(ctx, client, client.fd, 0);
}

fn submitRead(ctx: *ServerContext, client: *Client, fd: os.socket_t, offset: u64) !void {
    logger.debug("addr={s} submitting read from {d}, offset {d}", .{
        client.addr,
        fd,
        offset,
    });

    var sqe = try ctx.ring.read(
        @ptrToInt(client),
        fd,
        &client.temp_buffer,
        offset,
    );
    _ = sqe;
}

fn submitWrite(ctx: *ServerContext, client: *Client, fd: os.socket_t, offset: u64) !void {
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

fn submitOpenFile(ctx: *ServerContext, client: *Client, path: []const u8, flags: u32, mode: os.mode_t) !void {
    logger.debug("addr={s} submitting open, path=\"{s}\"", .{
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    // NOTE(vincent): with the GPA this calls mmap, slow as shit.
    const null_terminated_path = try client.arena.allocator.dupeZ(u8, path);
    defer client.arena.allocator.free(null_terminated_path);

    std.debug.print("null terminated path: {s}\n", .{fmt.fmtSliceHexLower(mem.spanZ(null_terminated_path))});

    var sqe = try ctx.ring.openat(
        @ptrToInt(client),
        os.linux.AT.FDCWD,
        null_terminated_path,
        flags,
        mode,
    );
    _ = sqe;
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

    var remote_addr = net.Address{
        .any = undefined,
    };
    var remote_addr_size: u32 = @sizeOf(os.sockaddr);

    var accept_waiting: bool = false;
    var iteration: usize = 0;

    while (true) : (iteration += 1) {
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

        if (cqe.user_data == 0) {
            logger.debug("cqe without user data, not doing anything", .{});
        } else if (cqe.user_data == @ptrToInt(&remote_addr)) {
            try ctx.handleAccept(cqe, &remote_addr);
            accept_waiting = false;
        } else {
            for (ctx.clients.items) |*client| {
                if (cqe.user_data != @ptrToInt(client)) {
                    continue;
                }

                dispatch(&ctx, client, cqe);
                break;
            }
        }

        // std.time.sleep(300 * std.time.ns_per_ms);
    }
}

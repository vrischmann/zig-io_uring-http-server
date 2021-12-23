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

const c = @cImport({
    @cInclude("picohttpparser.h");
});

const max_ring_entries = 512;
const max_buffer_size = 4096;
const max_connections = 128;
const max_serve_threads = 8;

const logger = std.log.scoped(.main);

pub const StatusCode = enum(u16) {
    OK = @as(u16, 200),
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Request type contains fields populated by picohttpparser and provides
/// helpers methods for easier use with Zig.
pub const Request = struct {
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

pub const ParseRequestResult = struct {
    req: Request,
    consumed: usize,
};

pub fn parseRequest(previous_buffer_len: usize, buffer: []const u8) !?ParseRequestResult {
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

/// Creates a server socket, bind it and listen on it.
///
/// This enables SO_REUSEADDR so that we can have multiple listeners
/// on the same port, that way the kernel load balances connections to our workers.
pub fn createSocket(port: u16) !os.socket_t {
    const sockfd = try os.socket(os.AF.INET6, os.SOCK.STREAM, 0);
    errdefer os.close(sockfd);

    // Enable reuseaddr if possible
    os.setsockopt(
        sockfd,
        os.SOL.SOCKET,
        os.SO.REUSEPORT,
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

/// Callback encapsulates a context and a function pointer that will be called when
/// the server loop will process the CQEs.
/// Pointers to this structure is what get passed as user data in a SQE and what we later get back in a CQE.
///
/// There are two kinds of callbacks currently:
/// * operations associated with a client
/// * operations not associated with a client
///
/// When a user gets a callback they must call initStandalone or initClient.
///
/// A callback also has a debug message that is known at compile time.
const Callback = struct {
    debug_msg: []const u8,

    kind: union(enum) {
        client: struct {
            context: *Client,
            call: fn (*Server, *Client, io_uring_cqe) anyerror!void,
        },
        standalone: struct {
            call: fn (*Server, io_uring_cqe) anyerror!void,
        },
    },

    next: ?*Callback = null,

    pub fn initStandalone(self: *Callback, comptime debug_msg: []const u8, cb: fn (*Server, io_uring_cqe) anyerror!void) void {
        logger.debug("CALLBACK ======== initializing standalone callback, msg: {s}", .{debug_msg});

        self.* = .{
            .debug_msg = debug_msg,
            .kind = .{
                .standalone = .{
                    .call = cb,
                },
            },
        };
    }

    pub fn initClient(self: *Callback, comptime debug_msg: []const u8, client: *Client, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) void {
        logger.debug("CALLBACK ======== initializing client (addr={s}) callback, msg: {s}", .{ client.addr, debug_msg });

        self.* = .{
            .debug_msg = debug_msg,
            .kind = .{
                .client = .{
                    .context = client,
                    .call = cb,
                },
            },
        };
    }
};

/// CallbackPool is a pool of callback objects that facilitates lifecycle management of a callback.
/// The implementation is a free list of pre-allocated objects.
///
/// For each SQEs a callback must be obtained via get().
/// When the server loop is processing CQEs it will use the callback and then release it with put().
const CallbackPool = struct {
    const Self = @This();

    allocator: mem.Allocator,
    free_list: ?*Callback,

    pub fn init(allocator: mem.Allocator) !Self {
        var res = Self{
            .allocator = allocator,
            .free_list = null,
        };

        // Preallocate as many callbacks as ring entries.

        var i: usize = 0;
        while (i < max_ring_entries) : (i += 1) {
            const callback = try allocator.create(Callback);
            callback.* = .{
                .debug_msg = "",
                .kind = undefined,
                .next = res.free_list,
            };
            res.free_list = callback;
        }

        return res;
    }

    pub fn deinit(self: *Self) void {
        // All callbacks must be put back in the pool before deinit is called
        assert(self.count() == max_ring_entries);

        var ret = self.free_list;
        while (ret) |item| {
            ret = item.next;
            self.allocator.destroy(item);
        }
    }

    /// Returns the number of callback in the pool.
    pub fn count(self: *Self) usize {
        var n: usize = 0;
        var ret = self.free_list;
        while (ret) |item| {
            n += 1;
            ret = item.next;
        }
        return n;
    }

    /// Returns a ready to use callback or an error if none are available.
    pub fn get(self: *Self) !*Callback {
        const ret = self.free_list orelse return error.OutOfCallback;
        self.free_list = ret.next;
        ret.next = null;
        return ret;
    }

    /// Reset the callback and puts it back into the pool.
    pub fn put(self: *Self, callback: *Callback) void {
        logger.debug("CALLBACK ======== putting callback to pool, msg: {s}", .{callback.debug_msg});

        callback.debug_msg = "";
        callback.kind = undefined;
        callback.next = self.free_list;
        self.free_list = callback;
    }
};

/// The HTTP server.
///
/// This struct does nothing by itself, the caller must drive it to achieve anything.
/// After initialization the caller must, in a loop:
/// * call maybeAccept
/// * call submit
/// * call processCompletions
///
/// Then the server will accept connections and process requests.
///
/// NOTE: this is _not_ thread safe ! You must create on Server object per thread.
pub const Server = struct {
    const Self = @This();

    const ID = usize;

    root_allocator: mem.Allocator,
    ring: IO_Uring,
    id: ID,

    /// the server loop will be running on this thread.
    thread: std.Thread,
    /// indicates is the server should continue running.
    running: Atomic(bool) = Atomic(bool).init(true),
    /// the number of pending SQEs.
    /// Necessary for drain() to work.
    pending: usize = 0,

    /// Listener state
    listener: struct {
        server_fd: os.socket_t,

        accept_waiting: bool = false,
        timeout: os.linux.kernel_timespec = .{
            .tv_sec = 0,
            .tv_nsec = 0,
        },

        // Next peer we're accepting
        peer_addr: net.Address = net.Address{
            .any = undefined,
        },
        peer_addr_size: u32 = @sizeOf(os.sockaddr),
    },

    // CQEs storage
    cqes: [max_ring_entries]io_uring_cqe = undefined,

    clients: struct {
        list: std.ArrayList(*Client),
    },
    callbacks: CallbackPool,

    registered_fds: RegisteredFileDescriptors,

    pub fn init(self: *Self, allocator: mem.Allocator, id: ID, server_fd: os.socket_t) !void {
        self.* = .{
            .root_allocator = allocator,
            .ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0),
            .id = id,
            .thread = undefined,
            .listener = .{
                .server_fd = server_fd,
            },
            .clients = .{
                .list = try std.ArrayList(*Client).initCapacity(allocator, max_connections),
            },
            .callbacks = try CallbackPool.init(allocator),
            .registered_fds = .{},
        };
        try self.registered_fds.register(&self.ring);
    }

    pub fn deinit(self: *Self) void {
        for (self.clients.list.items) |client| {
            client.deinit();
            self.root_allocator.destroy(client);
        }
        self.clients.list.deinit();
        self.callbacks.deinit();
        self.ring.deinit();
    }

    pub fn run(self: *Self, accept_timeout: u63) !void {
        while (self.running.load(.SeqCst)) {
            try self.maybeAccept(accept_timeout);
            const submitted = try self.submit(1);
            _ = try self.processCompletions(submitted);
        }
        try self.drain();
    }

    pub fn maybeAccept(self: *Self, timeout: u63) !void {
        if (!self.running.load(.SeqCst)) {
            return;
        }
        if (self.listener.accept_waiting or self.clients.list.items.len >= max_connections) {
            return;
        }

        // Queue an accept and link it to a timeout.

        var sqe = try self.submitAccept();
        sqe.flags |= os.linux.IOSQE_IO_LINK;

        self.listener.timeout.tv_sec = 0;
        self.listener.timeout.tv_nsec = timeout;

        _ = try self.submitAcceptLinkTimeout();

        self.listener.accept_waiting = true;
    }

    pub fn drain(self: *Self) !void {
        while (self.pending > 0) {
            _ = try self.submit(0);
            _ = try self.processCompletions(self.pending);
        }
    }

    pub fn submit(self: *Self, nr: u32) !usize {
        const n = try self.ring.submit_and_wait(nr);
        self.pending += n;
        return n;
    }

    pub fn processCompletions(self: *Self, wait_nr: usize) !usize {
        const cqe_count = try self.ring.copy_cqes(&self.cqes, @intCast(u32, wait_nr));

        for (self.cqes[0..cqe_count]) |cqe| {
            debug.assert(cqe.user_data != 0);

            var cb = @intToPtr(*Callback, cqe.user_data);
            defer self.callbacks.put(cb);

            switch (cb.kind) {
                .client => |client_cb| {
                    client_cb.call(self, client_cb.context, cqe) catch |err| {
                        self.handleClientCallbackError(client_cb.context, err);
                    };
                },
                .standalone => |standalone_cb| {
                    standalone_cb.call(self, cqe) catch |err| {
                        self.handleStandaloneCallbackError(err);
                    };
                },
            }
        }

        self.pending -= cqe_count;

        return cqe_count;
    }

    fn handleStandaloneCallbackError(self: *Self, err: anyerror) void {
        if (err == error.Canceled) return;

        logger.err("ctx#{d:<4} unexpected error {s}", .{ self.id, err });
    }

    fn handleClientCallbackError(self: *Self, client: *Client, err: anyerror) void {
        // This is the only error that doesn't trigger a close of the socket (for now).
        // Handle it separately to avoid code repetition.
        if (err == error.Canceled) return;

        switch (err) {
            error.ConnectionResetByPeer => {
                logger.info("ctx#{d:<4} client fd={d} disconnected", .{ self.id, client.fd });
            },
            error.UnexpectedEOF => {
                logger.debug("ctx#{d:<4} unexpected eof", .{self.id});
            },
            else => {
                logger.err("ctx#{d:<4} unexpected error {s}", .{ self.id, err });
            },
        }

        _ = self.submitClose(client, client.fd, onCloseClient) catch {};
    }

    fn submitAccept(self: *Self) !*io_uring_sqe {
        logger.debug("ctx#{d:<4} submitting accept on {d}", .{
            self.id,
            self.listener.server_fd,
        });

        var tmp = try self.callbacks.get();
        tmp.initStandalone("submitAccept", onAccept);

        return try self.ring.accept(
            @ptrToInt(tmp),
            self.listener.server_fd,
            &self.listener.peer_addr.any,
            &self.listener.peer_addr_size,
            0,
        );
    }

    fn submitAcceptLinkTimeout(self: *Self) !*io_uring_sqe {
        logger.debug("ctx#{d:<4} submitting link timeout", .{self.id});

        var tmp = try self.callbacks.get();
        tmp.initStandalone("submitAcceptLinkTimeout", onAcceptLinkTimeout);

        return self.ring.link_timeout(
            @ptrToInt(tmp),
            &self.listener.timeout,
            0,
        );
    }

    fn submitStandaloneClose(self: *Server, fd: os.fd_t, cb: fn (*Server, io_uring_cqe) anyerror!void) !*io_uring_sqe {
        logger.debug("ctx#{d:<4} submitting close of {d}", .{
            self.id,
            fd,
        });

        var tmp = try self.callbacks.get();
        tmp.initStandalone("submitStandaloneClose", cb);

        return self.ring.close(
            @ptrToInt(tmp),
            fd,
        );
    }

    fn submitClose(self: *Server, client: *Client, fd: os.fd_t, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) !*io_uring_sqe {
        logger.debug("ctx#{d:<4} addr={s} submitting close of {d}", .{
            self.id,
            client.addr,
            fd,
        });

        var tmp = try self.callbacks.get();
        tmp.initClient("submitClose", client, cb);

        return self.ring.close(
            @ptrToInt(tmp),
            fd,
        );
    }

    fn onAccept(self: *Self, cqe: os.linux.io_uring_cqe) !void {
        defer self.listener.accept_waiting = false;

        switch (cqe.err()) {
            .SUCCESS => {},
            .INTR => {
                logger.debug("ctx#{d:<4} ON ACCEPT interrupted", .{self.id});
                return error.Canceled;
            },
            .CANCELED => {
                logger.debug("ctx#{d:<4} ON ACCEPT timed out", .{self.id});
                return error.Canceled;
            },
            else => |err| {
                logger.err("ctx#{d:<4} ON ACCEPT unexpected errno={}", .{ self.id, err });
                return error.Unexpected;
            },
        }

        logger.debug("ctx#{d:<4} ON ACCEPT accepting connection from {s}", .{ self.id, self.listener.peer_addr });

        const client_fd = @intCast(os.socket_t, cqe.res);

        var client = try self.root_allocator.create(Client);
        errdefer self.root_allocator.destroy(client);

        try client.init(self.root_allocator, self.listener.peer_addr, client_fd);
        errdefer client.deinit();

        try self.clients.list.append(client);

        _ = try submitRead(self, client, client_fd, 0, onReadRequest);
    }

    fn onAcceptLinkTimeout(self: *Self, cqe: os.linux.io_uring_cqe) !void {
        switch (cqe.err()) {
            .CANCELED => {
                logger.debug("ctx#{d:<4} ON LINK TIMEOUT operation finished, timeout canceled", .{self.id});
            },
            .ALREADY => {
                logger.debug("ctx#{d:<4} ON LINK TIMEOUT operation already finished before timeout expired", .{self.id});
            },
            .TIME => {
                logger.debug("ctx#{d:<4} ON LINK TIMEOUT timeout finished before accept", .{self.id});
            },
            else => |err| {
                logger.err("ctx#{d:<4} ON LINK TIMEOUT unexpected errno={}", .{ self.id, err });
                return error.Unexpected;
            },
        }
    }

    fn onCloseClient(self: *Self, client: *Client, cqe: os.linux.io_uring_cqe) !void {
        logger.debug("ctx#{d:<4} addr={s} ON CLOSE CLIENT fd={}", .{
            self.id,
            client.addr,
            client.fd,
        });

        // Cleanup resources
        releaseRegisteredFileDescriptor(self, client);
        client.deinit();
        self.root_allocator.destroy(client);

        // Remove client from list
        const maybe_pos: ?usize = for (self.clients.list.items) |item, i| {
            if (item == client) {
                break i;
            }
        } else blk: {
            break :blk null;
        };
        if (maybe_pos) |pos| _ = self.clients.list.orderedRemove(pos);

        switch (cqe.err()) {
            .SUCCESS => {},
            else => |err| {
                logger.err("ctx#{d:<4} unexpected errno={}", .{ self.id, err });
                return error.Unexpected;
            },
        }
    }

    fn onClose(self: *Self, cqe: os.linux.io_uring_cqe) !void {
        logger.debug("ctx#{d:<4} ON CLOSE", .{self.id});

        switch (cqe.err()) {
            .SUCCESS => {},
            else => |err| {
                logger.err("ctx#{d:<4} unexpected errno={}", .{ self.id, err });
                return error.Unexpected;
            },
        }
    }
};

fn releaseRegisteredFileDescriptor(ctx: *Server, client: *Client) void {
    if (client.registered_fd) |registered_fd| {
        ctx.registered_fds.release(registered_fd);
        ctx.registered_fds.update(&ctx.ring) catch |err| {
            logger.err("ctx#{d:<4} unable to update registered file descriptors, err={}", .{ ctx.id, err });
        };
        client.registered_fd = null;
    }
}

const Client = struct {
    const Self = @This();

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

    gpa: mem.Allocator,

    addr: net.Address,
    fd: os.socket_t,

    // Buffer and allocator used for small allocations (nul-terminated path, integer to int conversions etc).
    temp_buffer: [128]u8 = undefined,
    temp_buffer_fba: heap.FixedBufferAllocator = undefined,

    buffer: std.ArrayList(u8),

    request: struct {
        result: ParseRequestResult = undefined,
        body: []const u8 = "",
        content_length: ?usize = null,
    } = .{},

    response: Response = .{},

    // non-null if the client was able to acquire a registered file descriptor.
    registered_fd: ?i32 = null,

    pub fn init(self: *Self, allocator: mem.Allocator, peer_addr: net.Address, client_fd: os.socket_t) !void {
        self.* = .{
            .gpa = allocator,
            .addr = peer_addr,
            .fd = client_fd,
            .buffer = undefined,
        };
        self.temp_buffer_fba = heap.FixedBufferAllocator.init(&self.temp_buffer);

        self.buffer = try std.ArrayList(u8).initCapacity(self.gpa, max_buffer_size);
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }

    pub fn setBuffer(self: *Self, data: []const u8) void {
        self.buffer.expandToCapacity();
        self.buffer.items = self.buffer.items[0..data.len];

        mem.copy(u8, self.buffer.items, data);
    }
};

fn onReadRequest(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ ctx.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.debug("ctx#{d:<4} addr={s} connection reset by peer", .{ ctx.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ REQUEST read of {d} bytes succeeded", .{ ctx.id, client.addr, read });

    const previous_len = client.buffer.items.len;
    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    if (try parseRequest(previous_len, client.buffer.items)) |result| {
        client.request.result = result;
        try processRequest(ctx, client);
    } else {
        // Not enough data, read more.

        logger.debug("ctx#{d:<4} addr={s} HTTP request incomplete, submitting read", .{ ctx.id, client.addr });

        _ = try submitRead(ctx, client, client.fd, 0, onReadRequest);
    }
}

fn onReadBody(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ ctx.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("ctx#{d:<4} addr={s} connection reset by peer", .{ ctx.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ BODY read of {d} bytes succeeded", .{ ctx.id, client.addr, read });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    const content_length = client.request.content_length.?;

    if (client.buffer.items.len < content_length) {
        logger.debug("ctx#{d:<4} addr={s} buffer len={d} bytes, content length={d} bytes", .{
            ctx.id,
            client.addr,
            client.buffer.items.len,
            content_length,
        });

        // Not enough data, read more.
        _ = try submitRead(ctx, client, client.fd, 0, onReadBody);
        return;
    }

    try processRequestWithBody(ctx, client);
}

fn onOpenResponseFile(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len == 0);

    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {},
        .NOENT => {
            client.temp_buffer_fba.reset();

            logger.warn("ctx#{d:<4} addr={s} no such file or directory, path=\"{s}\"", .{
                ctx.id,
                client.addr,
                fmt.fmtSliceEscapeLower(client.response.file.path),
            });

            try submitWriteNotFound(ctx, client);
            return;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }

    client.response.file.fd = @intCast(os.fd_t, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON OPEN RESPONSE FILE fd={}", .{ ctx.id, client.addr, client.response.file.fd });

    client.temp_buffer_fba.reset();

    // Try to acquire a registered file descriptor.
    // NOTE(vincent): constantly updating the registered file descriptors crashes the kernel
    // client.registered_fd = ctx.registered_fds.acquire(client.response.file.fd);
    // if (client.registered_fd != null) {
    //     try ctx.registered_fds.update(ctx.ring);
    // }
}

fn onStatxResponseFile(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    _ = ctx;

    switch (cqe.err()) {
        .SUCCESS => {
            debug.assert(client.buffer.items.len == 0);
        },
        .CANCELED => {
            return error.Canceled;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON STATX RESPONSE FILE unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }

    logger.debug("ctx#{d:<4} addr={s} ON STATX RESPONSE FILE path=\"{s}\" fd={}, size={s}", .{
        ctx.id,
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

    if (client.registered_fd) |registered_fd| {
        var sqe = try submitRead(ctx, client, registered_fd, 0, onReadResponseFile);
        sqe.flags |= os.linux.IOSQE_FIXED_FILE;
    } else {
        _ = try submitRead(ctx, client, client.response.file.fd, 0, onReadResponseFile);
    }
}

fn onReadResponseFile(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON READ RESPONSE FILE unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ RESPONSE FILE read of {d} bytes from {d} succeeded", .{
        ctx.id,
        client.addr,
        read,
        client.response.file.fd,
    });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    try submitWrite(ctx, client, client.fd, 0, onWriteResponseFile);
}

fn onWriteResponseFile(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const written = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE write of {d} bytes to {d} succeeded", .{
        ctx.id,
        client.addr,
        written,
        client.fd,
    });

    client.response.written += written;

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        try submitWrite(ctx, client, client.fd, 0, onWriteResponseFile);
        return;
    }

    if (client.response.written < client.response.file.statx_buf.size) {
        // More data to read from the file, submit another read

        client.buffer.clearRetainingCapacity();

        if (client.registered_fd) |registered_fd| {
            var sqe = try submitRead(ctx, client, registered_fd, 0, onReadResponseFile);
            sqe.flags |= os.linux.IOSQE_FIXED_FILE;
        } else {
            _ = try submitRead(ctx, client, client.response.file.fd, 0, onReadResponseFile);
        }
        return;
    }

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE done", .{
        ctx.id,
        client.addr,
    });

    // Response file written, read the next request

    releaseRegisteredFileDescriptor(ctx, client);
    // Close the response file descriptor
    _ = try ctx.submitClose(client, client.response.file.fd, onCloseResponseFile);
    client.response.file.fd = -1;

    // Reset the client state
    client.request = .{};
    client.response = .{};
    client.buffer.clearRetainingCapacity();

    _ = try submitRead(ctx, client, client.fd, 0, onReadRequest);
}

fn onCloseResponseFile(ctx: *Server, client: *Client, cqe: os.linux.io_uring_cqe) !void {
    logger.debug("ctx#{d:<4} addr={s} ON CLOSE RESPONSE FILE fd={}", .{
        ctx.id,
        client.addr,
        client.response.file.fd,
    });

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} unexpected errno={}", .{ ctx.id, err });
            return error.Unexpected;
        },
    }
}

fn onWriteResponseBuffer(ctx: *Server, client: *Client, cqe: io_uring_cqe) !void {
    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ ctx.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("ctx#{d:<4} addr={s} connection reset by peer", .{ ctx.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ ctx.id, client.addr, err });
            return error.Unexpected;
        },
    }

    const written = @intCast(usize, cqe.res);

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        try submitWrite(ctx, client, client.fd, 0, onWriteResponseBuffer);
        return;
    }

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE done", .{
        ctx.id,
        client.addr,
    });

    // Response written, read the next request
    client.request = .{};
    client.buffer.clearRetainingCapacity();

    _ = try submitRead(ctx, client, client.fd, 0, onReadRequest);
}

fn submitWriteNotFound(ctx: *Server, client: *Client) !void {
    _ = ctx;

    logger.debug("ctx#{d:<4} addr={s} returning 404 Not Found", .{
        ctx.id,
        client.addr,
    });

    const static_response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    client.setBuffer(static_response);

    try submitWrite(ctx, client, client.fd, 0, onWriteResponseBuffer);
}

fn processRequestWithBody(ctx: *Server, client: *Client) !void {
    _ = ctx;

    logger.debug("ctx#{d:<4} addr={s} body data=\"{s}\" size={s}", .{
        ctx.id,
        client.addr,
        fmt.fmtSliceEscapeLower(client.buffer.items),
        fmt.fmtIntSizeBin(@intCast(u64, client.buffer.items.len)),
    });

    // TODO(vincent): actually do something

    const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

    client.setBuffer(static_response);

    try submitWrite(ctx, client, client.fd, 0, onWriteResponseBuffer);
}

fn processRequest(ctx: *Server, client: *Client) !void {
    const req = client.request.result.req;

    logger.debug("ctx#{d:<4} addr={s} parsed HTTP request", .{ ctx.id, client.addr });

    logger.debug("ctx#{d:<4} addr={s} method: {s}, path: {s}, minor version: {d}", .{
        ctx.id,
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

    logger.debug("ctx#{d:<4} addr={s} content length: {d}", .{ ctx.id, client.addr, content_length });

    // If there's a content length we switch to reading the body.
    if (content_length) |n| {
        try client.buffer.replaceRange(0, client.request.result.consumed, &[0]u8{});

        if (n > client.buffer.items.len) {
            logger.debug("ctx#{d:<4} addr={s} body incomplete, usable={d} bytes, body data=\"{s}\", content length: {d} bytes", .{
                ctx.id,
                client.addr,
                client.buffer.items.len,
                fmt.fmtSliceEscapeLower(client.buffer.items),
                n,
            });

            client.request.content_length = n;

            _ = try submitRead(ctx, client, client.fd, 0, onReadBody);
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

        client.response.file.path = try client.temp_buffer_fba.allocator().dupeZ(u8, path);

        client.buffer.clearRetainingCapacity();

        var sqe = try submitOpenFile(
            ctx,
            client,
            client.response.file.path,
            os.linux.O.RDONLY | os.linux.O.NOFOLLOW,
            0644,
            onOpenResponseFile,
        );
        sqe.flags |= os.linux.IOSQE_IO_LINK;

        try submitStatxFile(
            ctx,
            client,
            client.response.file.path,
            os.linux.AT.SYMLINK_NOFOLLOW,
            os.linux.STATX_SIZE,
            &client.response.file.statx_buf,
            onStatxResponseFile,
        );

        return;
    }

    // TODO(vincent): actually do something

    const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

    client.setBuffer(static_response);

    try submitWrite(ctx, client, client.fd, 0, onWriteResponseBuffer);
}

fn submitRead(ctx: *Server, client: *Client, fd: os.socket_t, offset: u64, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting read from {d}, offset {d}", .{
        ctx.id,
        client.addr,
        fd,
        offset,
    });

    var tmp = try ctx.callbacks.get();
    tmp.initClient("submitRead", client, cb);

    return ctx.ring.read(
        @ptrToInt(tmp),
        fd,
        &client.temp_buffer,
        offset,
    );
}

fn submitWrite(ctx: *Server, client: *Client, fd: os.fd_t, offset: u64, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) !void {
    logger.debug("ctx#{d:<4} addr={s} submitting write of {s} to {d}, offset {d}, data=\"{s}\"", .{
        ctx.id,
        client.addr,
        fmt.fmtIntSizeBin(client.buffer.items.len),
        fd,
        offset,
        fmt.fmtSliceEscapeLower(client.buffer.items),
    });

    var tmp = try ctx.callbacks.get();
    tmp.initClient("submitWrite", client, cb);

    var sqe = try ctx.ring.write(
        @ptrToInt(tmp),
        fd,
        client.buffer.items,
        offset,
    );
    _ = sqe;
}

fn submitOpenFile(ctx: *Server, client: *Client, path: [:0]const u8, flags: u32, mode: os.mode_t, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting open, path=\"{s}\"", .{
        ctx.id,
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    var tmp = try ctx.callbacks.get();
    tmp.initClient("submitOpenFile", client, cb);

    return try ctx.ring.openat(
        @ptrToInt(tmp),
        os.linux.AT.FDCWD,
        path,
        flags,
        mode,
    );
}

fn submitStatxFile(ctx: *Server, client: *Client, path: [:0]const u8, flags: u32, mask: u32, buf: *os.linux.Statx, cb: fn (*Server, *Client, io_uring_cqe) anyerror!void) !void {
    logger.debug("ctx#{d:<4} addr={s} submitting statx, path=\"{s}\"", .{
        ctx.id,
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    var tmp = try ctx.callbacks.get();
    tmp.initClient("submitStatxFile", client, cb);

    var sqe = try ctx.ring.statx(
        @ptrToInt(tmp),
        os.linux.AT.FDCWD,
        path,
        flags,
        mask,
        buf,
    );
    _ = sqe;
}

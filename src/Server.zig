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

const http = @import("http.zig");
const RegisteredFileDescriptors = @import("io.zig").RegisteredFileDescriptors;

const max_ring_entries = 512;
const max_buffer_size = 4096;
const max_connections = 128;

const logger = std.log.scoped(.main);

const Self = @This();

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

//

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
    const ClientFn = fn (*Self, *ClientState, io_uring_cqe) anyerror!void;
    const StandaloneFn = fn (*Self, io_uring_cqe) anyerror!void;

    debug_msg: []const u8,

    kind: union(enum) {
        client: struct {
            context: *ClientState,
            call: ClientFn,
        },
        standalone: struct {
            call: StandaloneFn,
        },
    },

    next: ?*Callback = null,

    pub fn initStandalone(self: *Callback, comptime debug_msg: []const u8, cb: StandaloneFn) void {
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

    pub fn initClient(self: *Callback, comptime debug_msg: []const u8, client: *ClientState, cb: ClientFn) void {
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
    allocator: mem.Allocator,
    free_list: ?*Callback,

    pub fn init(allocator: mem.Allocator) !CallbackPool {
        var res = CallbackPool{
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

    pub fn deinit(self: *CallbackPool) void {
        // All callbacks must be put back in the pool before deinit is called
        assert(self.count() == max_ring_entries);

        var ret = self.free_list;
        while (ret) |item| {
            ret = item.next;
            self.allocator.destroy(item);
        }
    }

    /// Returns the number of callback in the pool.
    pub fn count(self: *CallbackPool) usize {
        var n: usize = 0;
        var ret = self.free_list;
        while (ret) |item| {
            n += 1;
            ret = item.next;
        }
        return n;
    }

    /// Returns a ready to use callback or an error if none are available.
    pub fn get(self: *CallbackPool) !*Callback {
        const ret = self.free_list orelse return error.OutOfCallback;
        self.free_list = ret.next;
        ret.next = null;
        return ret;
    }

    /// Reset the callback and puts it back into the pool.
    pub fn put(self: *CallbackPool, callback: *Callback) void {
        logger.debug("CALLBACK ======== putting callback to pool, msg: {s}", .{callback.debug_msg});

        callback.debug_msg = "";
        callback.kind = undefined;
        callback.next = self.free_list;
        self.free_list = callback;
    }
};

const ID = usize;

/// allocator used to allocate each client state
root_allocator: mem.Allocator,

/// uring dedicated to this server object.
ring: IO_Uring,

/// this server's ID. Used only for logging.
id: ID,

/// indicates if the server should continue running.
/// This is _not_ owned by the server but by the caller.
running: *Atomic(bool),

/// the number of pending SQEs.
/// Necessary for drain() to work.
pending: usize = 0,

/// Listener state
listener: struct {
    /// server file descriptor used for accept(2) operation.
    /// Must have had bind(2) and listen(2) called on it before being passed to `init()`.
    server_fd: os.socket_t,

    /// indicates if an accept operation is pending.
    accept_waiting: bool = false,

    /// the timeout data for the link_timeout operation linked to the previous accept.
    ///
    /// Each accept operation has a following timeout linked to it; this works in such a way
    /// that if the timeout has expired the accept operation is cancelled and if the accept has finished
    /// before the timeout then the timeout operation is cancelled.
    ///
    /// This is useful to run the main loop for a bounded duration.
    timeout: os.linux.kernel_timespec = .{
        .tv_sec = 0,
        .tv_nsec = 0,
    },

    // Next peer we're accepting.
    // Will be valid after a successful CQE for an accept operation.
    peer_addr: net.Address = net.Address{
        .any = undefined,
    },
    peer_addr_size: u32 = @sizeOf(os.sockaddr),
},

/// CQEs storage
cqes: [max_ring_entries]io_uring_cqe = undefined,

/// List of client states.
/// A new state is created for each socket accepted and destroyed when the socket is closed for any reason.
clients: std.ArrayList(*ClientState),

/// Free list of callback objects necessary for working with the uring.
/// See the documentation of CallbackPool.
callbacks: CallbackPool,

/// Set of registered file descriptors for use with the uring.
///
/// TODO(vincent): make use of this somehow ? right now it crashes the kernel.
registered_fds: RegisteredFileDescriptors,

/// initializes a Server object.
///
/// `allocator` will be used to:
/// * allocate all client states (including request/response bodies).
/// * allocate the callback pool
/// Depending on the workload the allocator can be hit quite often (for example if all clients close their connection).
///
/// `id` is used for logging only.
///
/// `running` is owned by the caller and indicates if the server should shutdown properly.
///
/// `server_fd` must be a socket properly initialized with listen(2) and bind(2) which will be used for accept(2) operations.
pub fn init(self: *Self, allocator: mem.Allocator, id: ID, running: *Atomic(bool), server_fd: os.socket_t) !void {
    self.* = .{
        .root_allocator = allocator,
        .ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0),
        .id = id,
        .running = running,
        .listener = .{
            .server_fd = server_fd,
        },
        .clients = try std.ArrayList(*ClientState).initCapacity(allocator, max_connections),
        .callbacks = try CallbackPool.init(allocator),
        .registered_fds = .{},
    };
    try self.registered_fds.register(&self.ring);
}

pub fn deinit(self: *Self) void {
    for (self.clients.items) |client| {
        client.deinit();
        self.root_allocator.destroy(client);
    }
    self.clients.deinit();
    self.callbacks.deinit();
    self.ring.deinit();
}

/// Runs the main loop until the `running` boolean is false.
///
/// `accept_timeout` controls how much time the loop can wait for an accept operation to finish.
/// This duration is the lower bound duration before the main loop can stop when `running` is false;
pub fn run(self: *Self, accept_timeout: u63) !void {
    // TODO(vincent): we don't properly shutdown the peer sockets; we should do that.
    // This can be done using standard close(2) calls I think.

    while (self.running.load(.SeqCst)) {
        // first step: (maybe) submit and accept with a link_timeout linked to it.
        //
        // Nothing is submitted if:
        // * a previous accept operation is already waiting.
        // * the number of connected clients reached the predefined limit.
        try self.maybeAccept(accept_timeout);

        // second step: submit to the kernel all previous queued SQE.
        //
        // SQEs might be queued by the maybeAccept call above or by the processCompletions call below, but
        // obviously in that case its SQEs queued from the _previous iteration_ that are submitted to the kernel.
        //
        // Additionally we wait for at least 1 CQE to be available, if none is available the thread will be put to sleep by the kernel.
        // Note that this doesn't work if the uring is setup with busy-waiting.
        const submitted = try self.submit(1);

        // third step: process all available CQEs.
        //
        // This asks the kernel to wait for at least `submitted` CQE to be available.
        // Since we successfully submitted that many SQEs it is guaranteed we will _at some point_
        // get that many CQEs but there's no guarantee they will be available instantly; if the
        // kernel lags in processing the SQEs we can have a delay in getting the CQEs.
        // This is further accentuated by the number of pending SQEs we can have.
        //
        // One example would be submitting a lot of fdatasync operations on slow devices.
        //
        _ = try self.processCompletions(submitted);
    }
    try self.drain();
}

fn maybeAccept(self: *Self, timeout: u63) !void {
    if (!self.running.load(.SeqCst)) {
        // we must stop: stop accepting connections.
        return;
    }
    if (self.listener.accept_waiting or self.clients.items.len >= max_connections) {
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

/// Continuously submit SQEs and process completions until there are
/// no more pending operations.
///
/// This must be called when shutting down.
fn drain(self: *Self) !void {
    while (self.pending > 0) {
        _ = try self.submit(0);
        _ = try self.processCompletions(self.pending);
    }
}

fn submit(self: *Self, nr: u32) !usize {
    const n = try self.ring.submit_and_wait(nr);
    self.pending += n;
    return n;
}

fn processCompletions(self: *Self, wait_nr: usize) !usize {
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

fn handleClientCallbackError(self: *Self, client: *ClientState, err: anyerror) void {
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

fn submitStandaloneClose(self: *Self, fd: os.fd_t, cb: Callback.StandaloneFn) !*io_uring_sqe {
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

fn submitClose(self: *Self, client: *ClientState, fd: os.fd_t, cb: Callback.ClientFn) !*io_uring_sqe {
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

    var client = try self.root_allocator.create(ClientState);
    errdefer self.root_allocator.destroy(client);

    try client.init(self.root_allocator, self.listener.peer_addr, client_fd);
    errdefer client.deinit();

    try self.clients.append(client);

    _ = try self.submitRead(client, client_fd, 0, onReadRequest);
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

fn onCloseClient(self: *Self, client: *ClientState, cqe: os.linux.io_uring_cqe) !void {
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
    const maybe_pos: ?usize = for (self.clients.items) |item, i| {
        if (item == client) {
            break i;
        }
    } else blk: {
        break :blk null;
    };
    if (maybe_pos) |pos| _ = self.clients.orderedRemove(pos);

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

fn onReadRequest(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ self.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.debug("ctx#{d:<4} addr={s} connection reset by peer", .{ self.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ REQUEST read of {d} bytes succeeded", .{ self.id, client.addr, read });

    const previous_len = client.buffer.items.len;
    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    if (try http.parseRequest(previous_len, client.buffer.items)) |result| {
        client.request.result = result;
        try processRequest(self, client);
    } else {
        // Not enough data, read more.

        logger.debug("ctx#{d:<4} addr={s} HTTP request incomplete, submitting read", .{ self.id, client.addr });

        _ = try self.submitRead(client, client.fd, 0, onReadRequest);
    }
}

fn onWriteResponseBuffer(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ self.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("ctx#{d:<4} addr={s} connection reset by peer", .{ self.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }

    const written = @intCast(usize, cqe.res);

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
        return;
    }

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE done", .{
        self.id,
        client.addr,
    });

    // Response written, read the next request
    client.request = .{};
    client.buffer.clearRetainingCapacity();

    _ = try self.submitRead(client, client.fd, 0, onReadRequest);
}

fn onCloseResponseFile(self: *Self, client: *ClientState, cqe: os.linux.io_uring_cqe) !void {
    logger.debug("ctx#{d:<4} addr={s} ON CLOSE RESPONSE FILE fd={}", .{
        self.id,
        client.addr,
        client.response.file.fd,
    });

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} unexpected errno={}", .{ self.id, err });
            return error.Unexpected;
        },
    }
}

fn onWriteResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const written = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE write of {d} bytes to {d} succeeded", .{
        self.id,
        client.addr,
        written,
        client.fd,
    });

    client.response.written += written;

    if (written < client.buffer.items.len) {
        // Short write, write the remaining data

        // Remove the already written data
        try client.buffer.replaceRange(0, written, &[0]u8{});

        _ = try self.submitWrite(client, client.fd, 0, onWriteResponseFile);
        return;
    }

    if (client.response.written < client.response.file.statx_buf.size) {
        // More data to read from the file, submit another read

        client.buffer.clearRetainingCapacity();

        if (client.registered_fd) |registered_fd| {
            var sqe = try self.submitRead(client, registered_fd, 0, onReadResponseFile);
            sqe.flags |= os.linux.IOSQE_FIXED_FILE;
        } else {
            _ = try self.submitRead(client, client.response.file.fd, 0, onReadResponseFile);
        }
        return;
    }

    logger.debug("ctx#{d:<4} addr={s} ON WRITE RESPONSE FILE done", .{
        self.id,
        client.addr,
    });

    // Response file written, read the next request

    releaseRegisteredFileDescriptor(self, client);
    // Close the response file descriptor
    _ = try self.submitClose(client, client.response.file.fd, onCloseResponseFile);
    client.response.file.fd = -1;

    // Reset the client state
    client.request = .{};
    client.response = .{};
    client.buffer.clearRetainingCapacity();

    _ = try self.submitRead(client, client.fd, 0, onReadRequest);
}

fn onReadResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len > 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON READ RESPONSE FILE unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ RESPONSE FILE read of {d} bytes from {d} succeeded", .{
        self.id,
        client.addr,
        read,
        client.response.file.fd,
    });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    _ = try self.submitWrite(client, client.fd, 0, onWriteResponseFile);
}

fn onStatxResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    _ = self;

    switch (cqe.err()) {
        .SUCCESS => {
            debug.assert(client.buffer.items.len == 0);
        },
        .CANCELED => {
            return error.Canceled;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} ON STATX RESPONSE FILE unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }

    logger.debug("ctx#{d:<4} addr={s} ON STATX RESPONSE FILE path=\"{s}\" fd={}, size={s}", .{
        self.id,
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
        var sqe = try self.submitRead(client, registered_fd, 0, onReadResponseFile);
        sqe.flags |= os.linux.IOSQE_FIXED_FILE;
    } else {
        _ = try self.submitRead(client, client.response.file.fd, 0, onReadResponseFile);
    }
}

fn onReadBody(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    switch (cqe.err()) {
        .SUCCESS => {},
        .PIPE => {
            logger.err("ctx#{d:<4} addr={s} broken pipe", .{ self.id, client.addr });
            return error.BrokenPipe;
        },
        .CONNRESET => {
            logger.err("ctx#{d:<4} addr={s} connection reset by peer", .{ self.id, client.addr });
            return error.ConnectionResetByPeer;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }
    if (cqe.res <= 0) {
        return error.UnexpectedEOF;
    }

    const read = @intCast(usize, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON READ BODY read of {d} bytes succeeded", .{ self.id, client.addr, read });

    try client.buffer.appendSlice(client.temp_buffer[0..read]);

    const content_length = client.request.content_length.?;

    if (client.buffer.items.len < content_length) {
        logger.debug("ctx#{d:<4} addr={s} buffer len={d} bytes, content length={d} bytes", .{
            self.id,
            client.addr,
            client.buffer.items.len,
            content_length,
        });

        // Not enough data, read more.
        _ = try self.submitRead(client, client.fd, 0, onReadBody);
        return;
    }

    try processRequestWithBody(self, client);
}

fn onOpenResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
    debug.assert(client.buffer.items.len == 0);

    switch (cqe.err()) {
        .SUCCESS => {},
        .NOENT => {
            client.temp_buffer_fba.reset();

            logger.warn("ctx#{d:<4} addr={s} no such file or directory, path=\"{s}\"", .{
                self.id,
                client.addr,
                fmt.fmtSliceEscapeLower(client.response.file.path),
            });

            try self.submitWriteNotFound(client);
            return;
        },
        else => |err| {
            logger.err("ctx#{d:<4} addr={s} unexpected errno={}", .{ self.id, client.addr, err });
            return error.Unexpected;
        },
    }

    client.response.file.fd = @intCast(os.fd_t, cqe.res);

    logger.debug("ctx#{d:<4} addr={s} ON OPEN RESPONSE FILE fd={}", .{ self.id, client.addr, client.response.file.fd });

    client.temp_buffer_fba.reset();

    // Try to acquire a registered file descriptor.
    // NOTE(vincent): constantly updating the registered file descriptors crashes the kernel
    // client.registered_fd = self.registered_fds.acquire(client.response.file.fd);
    // if (client.registered_fd != null) {
    //     try self.registered_fds.update(self.ring);
    // }
}

fn releaseRegisteredFileDescriptor(ctx: *Self, client: *ClientState) void {
    if (client.registered_fd) |registered_fd| {
        ctx.registered_fds.release(registered_fd);
        ctx.registered_fds.update(&ctx.ring) catch |err| {
            logger.err("ctx#{d:<4} unable to update registered file descriptors, err={}", .{ ctx.id, err });
        };
        client.registered_fd = null;
    }
}

const ClientState = struct {
    const Response = struct {
        written: usize = 0,

        status_code: http.StatusCode = .OK,

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

    // TODO(vincent): prevent going over the max_buffer_size somehow ("limiting" allocator ?)
    // TODO(vincent): right now we always use clearRetainingCapacity() which may keep a lot of memory
    // allocated for no reason.
    // Implement some sort of statistics to determine if we should release memory, for example:
    //  * max size used by the last 100 requests for reads or writes
    //  * duration without any request before releasing everything
    buffer: std.ArrayList(u8),

    request: struct {
        result: http.ParseRequestResult = undefined,
        body: []const u8 = "",
        content_length: ?usize = null,
    } = .{},

    response: Response = .{},

    // non-null if the client was able to acquire a registered file descriptor.
    registered_fd: ?i32 = null,

    pub fn init(self: *ClientState, allocator: mem.Allocator, peer_addr: net.Address, client_fd: os.socket_t) !void {
        self.* = .{
            .gpa = allocator,
            .addr = peer_addr,
            .fd = client_fd,
            .buffer = undefined,
        };
        self.temp_buffer_fba = heap.FixedBufferAllocator.init(&self.temp_buffer);

        self.buffer = try std.ArrayList(u8).initCapacity(self.gpa, max_buffer_size);
    }

    pub fn deinit(self: *ClientState) void {
        self.buffer.deinit();
    }

    pub fn setBuffer(self: *ClientState, data: []const u8) void {
        self.buffer.expandToCapacity();
        self.buffer.items = self.buffer.items[0..data.len];

        mem.copy(u8, self.buffer.items, data);
    }
};

fn submitWriteNotFound(self: *Self, client: *ClientState) !void {
    logger.debug("ctx#{d:<4} addr={s} returning 404 Not Found", .{
        self.id,
        client.addr,
    });

    const static_response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    client.setBuffer(static_response);

    _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
}

fn processRequestWithBody(self: *Self, client: *ClientState) !void {
    logger.debug("ctx#{d:<4} addr={s} body data=\"{s}\" size={s}", .{
        self.id,
        client.addr,
        fmt.fmtSliceEscapeLower(client.buffer.items),
        fmt.fmtIntSizeBin(@intCast(u64, client.buffer.items.len)),
    });

    // TODO(vincent): actually do something

    const static_response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

    client.setBuffer(static_response);

    _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
}

fn processRequest(self: *Self, client: *ClientState) !void {
    const req = client.request.result.req;

    logger.debug("ctx#{d:<4} addr={s} parsed HTTP request", .{ self.id, client.addr });
    logger.debug("ctx#{d:<4} addr={s} method: {s}, path: {s}, minor version: {d}", .{
        self.id,
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

    logger.debug("ctx#{d:<4} addr={s} content length: {d}", .{ self.id, client.addr, content_length });

    // If there's a content length we switch to reading the body.
    if (content_length) |n| {
        try client.buffer.replaceRange(0, client.request.result.consumed, &[0]u8{});

        if (n > client.buffer.items.len) {
            logger.debug("ctx#{d:<4} addr={s} body incomplete, usable={d} bytes, body data=\"{s}\", content length: {d} bytes", .{
                self.id,
                client.addr,
                client.buffer.items.len,
                fmt.fmtSliceEscapeLower(client.buffer.items),
                n,
            });

            client.request.content_length = n;

            _ = try self.submitRead(client, client.fd, 0, onReadBody);
            return;
        }

        try self.processRequestWithBody(client);
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

        var sqe = try self.submitOpenFile(
            client,
            client.response.file.path,
            os.linux.O.RDONLY | os.linux.O.NOFOLLOW,
            0644,
            onOpenResponseFile,
        );
        sqe.flags |= os.linux.IOSQE_IO_LINK;

        _ = try self.submitStatxFile(
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

    _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
}

fn submitRead(self: *Self, client: *ClientState, fd: os.socket_t, offset: u64, cb: Callback.ClientFn) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting read from {d}, offset {d}", .{
        self.id,
        client.addr,
        fd,
        offset,
    });

    var tmp = try self.callbacks.get();
    tmp.initClient("submitRead", client, cb);

    return self.ring.read(
        @ptrToInt(tmp),
        fd,
        &client.temp_buffer,
        offset,
    );
}

fn submitWrite(self: *Self, client: *ClientState, fd: os.fd_t, offset: u64, cb: Callback.ClientFn) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting write of {s} to {d}, offset {d}, data=\"{s}\"", .{
        self.id,
        client.addr,
        fmt.fmtIntSizeBin(client.buffer.items.len),
        fd,
        offset,
        fmt.fmtSliceEscapeLower(client.buffer.items),
    });

    var tmp = try self.callbacks.get();
    tmp.initClient("submitWrite", client, cb);

    return self.ring.write(
        @ptrToInt(tmp),
        fd,
        client.buffer.items,
        offset,
    );
}

fn submitOpenFile(self: *Self, client: *ClientState, path: [:0]const u8, flags: u32, mode: os.mode_t, cb: Callback.ClientFn) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting open, path=\"{s}\"", .{
        self.id,
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    var tmp = try self.callbacks.get();
    tmp.initClient("submitOpenFile", client, cb);

    return try self.ring.openat(
        @ptrToInt(tmp),
        os.linux.AT.FDCWD,
        path,
        flags,
        mode,
    );
}

fn submitStatxFile(self: *Self, client: *ClientState, path: [:0]const u8, flags: u32, mask: u32, buf: *os.linux.Statx, cb: Callback.ClientFn) !*io_uring_sqe {
    logger.debug("ctx#{d:<4} addr={s} submitting statx, path=\"{s}\"", .{
        self.id,
        client.addr,
        fmt.fmtSliceEscapeLower(path),
    });

    var tmp = try self.callbacks.get();
    tmp.initClient("submitStatxFile", client, cb);

    return self.ring.statx(
        @ptrToInt(tmp),
        os.linux.AT.FDCWD,
        path,
        flags,
        mask,
        buf,
    );
}

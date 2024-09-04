const std = @import("std");
const build_options = @import("build_options");
const ascii = std.ascii;
const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const posix = std.posix;

const picohttp = @import("picohttpparser");

const Atomic = std.atomic.Value;
const assert = std.debug.assert;

const IoUring = std.os.linux.IoUring;
const io_uring_cqe = std.os.linux.io_uring_cqe;
const io_uring_sqe = std.os.linux.io_uring_sqe;

pub const createSocket = @import("io.zig").createSocket;
const RegisteredFile = @import("io.zig").RegisteredFile;
const RegisteredFileDescriptors = @import("io.zig").RegisteredFileDescriptors;
const Callback = @import("callback.zig").Callback;

const logger = std.log.scoped(.main);

/// HTTP types and stuff
pub const Method = enum(u4) {
    get,
    head,
    post,
    put,
    delete,
    connect,
    options,
    trace,
    patch,

    pub fn toString(self: Method) []const u8 {
        switch (self) {
            .get => return "GET",
            .head => return "HEAD",
            .post => return "POST",
            .put => return "PUT",
            .delete => return "DELETE",
            .connect => return "CONNECT",
            .options => return "OPTIONS",
            .trace => return "TRACE",
            .patch => return "PATCH",
        }
    }

    fn fromString(s: []const u8) !Method {
        if (ascii.eqlIgnoreCase(s, "GET")) {
            return .get;
        } else if (ascii.eqlIgnoreCase(s, "HEAD")) {
            return .head;
        } else if (ascii.eqlIgnoreCase(s, "POST")) {
            return .post;
        } else if (ascii.eqlIgnoreCase(s, "PUT")) {
            return .put;
        } else if (ascii.eqlIgnoreCase(s, "DELETE")) {
            return .delete;
        } else if (ascii.eqlIgnoreCase(s, "CONNECT")) {
            return .connect;
        } else if (ascii.eqlIgnoreCase(s, "OPTIONS")) {
            return .options;
        } else if (ascii.eqlIgnoreCase(s, "TRACE")) {
            return .trace;
        } else if (ascii.eqlIgnoreCase(s, "PATCH")) {
            return .patch;
        } else {
            return error.InvalidMethod;
        }
    }
};

pub const StatusCode = enum(u10) {
    // informational
    continue_ = 100,
    switching_protocols = 101,

    // success
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    partial_content = 206,

    // redirection
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // client error
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    gone = 410,
    too_many_requests = 429,

    // server error
    internal_server_error = 500,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,

    pub fn toString(self: StatusCode) []const u8 {
        switch (self) {
            // informational
            .continue_ => return "Continue",
            .switching_protocols => return "Switching Protocols",

            .ok => return "OK",
            .created => return "Created",
            .accepted => return "Accepted",
            .no_content => return "No Content",
            .partial_content => return "Partial Content",

            // redirection
            .moved_permanently => return "Moved Permanently",
            .found => return "Found",
            .not_modified => return "Not Modified",
            .temporary_redirect => return "Temporary Redirected",
            .permanent_redirect => return "Permanent Redirect",

            // client error
            .bad_request => return "Bad Request",
            .unauthorized => return "Unauthorized",
            .forbidden => return "Forbidden",
            .not_found => return "Not Found",
            .method_not_allowed => return "Method Not Allowed",
            .not_acceptable => return "Not Acceptable",
            .gone => return "Gone",
            .too_many_requests => return "Too Many Requests",

            // server error
            .internal_server_error => return "Internal Server Error",
            .bad_gateway => return "Bad Gateway",
            .service_unavailable => return "Service Unavailable",
            .gateway_timeout => return "Gateway Timeout",
        }
    }
};

pub const Headers = struct {
    storage: [picohttp.RawRequest.max_headers]picohttp.RawHeader,
    view: []picohttp.RawHeader,

    fn create(req: picohttp.RawRequest) !Headers {
        assert(req.num_headers < picohttp.RawRequest.max_headers);

        var res = Headers{
            .storage = undefined,
            .view = undefined,
        };

        const num_headers = try req.copyHeaders(&res.storage);
        res.view = res.storage[0..num_headers];

        return res;
    }

    pub fn get(self: Headers, name: []const u8) ?picohttp.RawHeader {
        for (self.view) |item| {
            if (ascii.eqlIgnoreCase(name, item.name)) {
                return item;
            }
        }
        return null;
    }
};

/// Contains peer information for a request.
pub const Peer = struct {
    addr: net.Address,
};

/// Contains request data.
/// This is what the handler will receive.
pub const Request = struct {
    method: Method,
    path: []const u8,
    minor_version: usize,
    headers: Headers,
    body: ?[]const u8,

    fn create(req: picohttp.RawRequest, body: ?[]const u8) !Request {
        return Request{
            .method = try Method.fromString(req.getMethod()),
            .path = req.getPath(),
            .minor_version = req.getMinorVersion(),
            .headers = try Headers.create(req),
            .body = body,
        };
    }
};

/// The response returned by the handler.
pub const Response = union(enum) {
    /// The response is a simple buffer.
    response: struct {
        status_code: StatusCode,
        headers: []picohttp.RawHeader,
        data: []const u8,
    },
    /// The response is a static file that will be read from the filesystem.
    send_file: struct {
        status_code: StatusCode,
        headers: []picohttp.RawHeader,
        path: []const u8,
    },
};

pub fn RequestHandler(comptime Context: type) type {
    return *const fn (Context, mem.Allocator, Peer, Request) anyerror!Response;
}

const ResponseStateFileDescriptor = union(enum) {
    direct: posix.fd_t,
    registered: posix.fd_t,

    pub fn format(self: ResponseStateFileDescriptor, comptime fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;

        if (comptime !mem.eql(u8, "s", fmt_string)) @compileError("format string must be s");
        switch (self) {
            .direct => |fd| try writer.print("(direct fd={d})", .{fd}),
            .registered => |fd| try writer.print("(registered fd={d})", .{fd}),
        }
    }
};

const ClientState = struct {
    const RequestState = struct {
        parse_result: picohttp.ParseRequestResult = .{
            .raw_request = .{},
            .consumed = 0,
        },
        content_length: ?usize = null,
        /// this is a view into the client buffer
        body: ?[]const u8 = null,
    };

    /// Holds state used to send a response to the client.
    const ResponseState = struct {
        /// status code and header are overwritable in the handler
        status_code: StatusCode = .ok,
        headers: []picohttp.RawHeader = &[_]picohttp.RawHeader{},

        /// state used when we need to send a static file from the filesystem.
        file: struct {
            path: [:0]u8 = undefined,
            fd: ResponseStateFileDescriptor = undefined,
            statx_buf: os.linux.Statx = undefined,

            offset: usize = 0,
        } = .{},
    };

    gpa: mem.Allocator,

    /// peer information associated with this client
    peer: Peer,
    fd: posix.socket_t,

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

    request_state: RequestState = .{},
    response_state: ResponseState = .{},

    pub fn init(self: *ClientState, allocator: mem.Allocator, peer_addr: net.Address, client_fd: posix.socket_t, max_buffer_size: usize) !void {
        self.* = .{
            .gpa = allocator,
            .peer = .{
                .addr = peer_addr,
            },
            .fd = client_fd,
            .buffer = undefined,
        };
        self.temp_buffer_fba = heap.FixedBufferAllocator.init(&self.temp_buffer);

        self.buffer = try std.ArrayList(u8).initCapacity(self.gpa, max_buffer_size);
    }

    pub fn deinit(self: *ClientState) void {
        self.buffer.deinit();
    }

    fn refreshBody(self: *ClientState) void {
        const consumed = self.request_state.parse_result.consumed;
        if (consumed > 0) {
            self.request_state.body = self.buffer.items[consumed..];
        }
    }

    pub fn reset(self: *ClientState) void {
        self.request_state = .{};
        self.response_state = .{};
        self.buffer.clearRetainingCapacity();
    }

    fn startWritingResponse(self: *ClientState, content_length: ?usize) !void {
        var writer = self.buffer.writer();

        try writer.print("HTTP/1.1 {d} {s}\n", .{
            @intFromEnum(self.response_state.status_code),
            self.response_state.status_code.toString(),
        });
        for (self.response_state.headers) |header| {
            try writer.print("{s}: {s}\n", .{ header.name, header.value });
        }
        if (content_length) |n| {
            try writer.print("Content-Length: {d}\n", .{n});
        }
        try writer.print("\n", .{});
    }
};

pub const ServerOptions = struct {
    max_ring_entries: u13 = 512,
    max_buffer_size: usize = 4096,
    max_connections: usize = 128,
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
pub fn Server(comptime Context: type) type {
    return struct {
        const Self = @This();
        const CallbackType = Callback(*Self, *ClientState);

        /// allocator used to allocate each client state
        root_allocator: mem.Allocator,

        /// uring dedicated to this server object.
        ring: IoUring,

        /// options controlling the behaviour of the server.
        options: ServerOptions,

        /// indicates if the server should continue running.
        /// This is _not_ owned by the server but by the caller.
        running: *Atomic(bool),

        /// This field lets us keep track of the number of pending operations which is necessary to implement drain() properly.
        ///
        /// Note that this is different than the number of SQEs pending in the submission queue or CQEs pending in the completion queue.
        /// For example an accept operation which has been consumed by the kernel but hasn't accepted any connection yet must be considered
        /// pending for us but it's not pending in either the submission or completion queue.
        /// Another example is a timeout: once accepted and until expired it won't be available in the completion queue.
        pending: usize = 0,

        /// Listener state
        listener: struct {
            /// server file descriptor used for accept(2) operation.
            /// Must have had bind(2) and listen(2) called on it before being passed to `init()`.
            server_fd: posix.socket_t,

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
                .sec = 0,
                .nsec = 0,
            },

            // Next peer we're accepting.
            // Will be valid after a successful CQE for an accept operation.
            peer_addr: net.Address = net.Address{
                .any = undefined,
            },
            peer_addr_size: u32 = @sizeOf(posix.sockaddr),
        },

        /// CQEs storage
        cqes: []io_uring_cqe = undefined,

        /// List of client states.
        /// A new state is created for each socket accepted and destroyed when the socket is closed for any reason.
        clients: std.ArrayList(*ClientState),

        /// Free list of callback objects necessary for working with the uring.
        /// See the documentation of Callback.Pool.
        callbacks: CallbackType.Pool,

        /// Set of registered file descriptors for use with the uring.
        ///
        /// TODO(vincent): make use of this somehow ? right now it crashes the kernel.
        registered_fds: RegisteredFileDescriptors,
        registered_files: std.StringHashMap(RegisteredFile),

        user_context: Context,
        handler: RequestHandler(Context),

        /// initializes a Server object.
        pub fn init(
            self: *Self,
            /// General purpose allocator which will:
            /// * allocate all client states (including request/response bodies).
            /// * allocate the callback pool
            /// Depending on the workload the allocator can be hit quite often (for example if all clients close their connection).
            allocator: mem.Allocator,
            /// controls the behaviour of the server (max number of connections, max buffer size, etc).
            options: ServerOptions,
            /// owned by the caller and indicates if the server should shutdown properly.
            running: *Atomic(bool),
            /// must be a socket properly initialized with listen(2) and bind(2) which will be used for accept(2) operations.
            server_fd: posix.socket_t,
            /// user provided context that will be passed to the request handlers.
            user_context: Context,
            /// user provied request handler.
            comptime handler: RequestHandler(Context),
        ) !void {
            // TODO(vincent): probe for available features for io_uring ?

            self.* = .{
                .root_allocator = allocator,
                .ring = try std.os.linux.IoUring.init(options.max_ring_entries, 0),
                .options = options,
                .running = running,
                .listener = .{
                    .server_fd = server_fd,
                },
                .cqes = try allocator.alloc(io_uring_cqe, options.max_ring_entries),
                .clients = try std.ArrayList(*ClientState).initCapacity(allocator, options.max_connections),
                .callbacks = undefined,
                .registered_fds = .{},
                .registered_files = std.StringHashMap(RegisteredFile).init(allocator),
                .user_context = user_context,
                .handler = handler,
            };

            self.callbacks = try CallbackType.Pool.init(allocator, self, options.max_ring_entries);

            try self.registered_fds.register(&self.ring);
        }

        pub fn deinit(self: *Self) void {
            var registered_files_iterator = self.registered_files.iterator();
            while (registered_files_iterator.next()) |entry| {
                self.root_allocator.free(entry.key_ptr.*);
            }
            self.registered_files.deinit();

            for (self.clients.items) |client| {
                client.deinit();
                self.root_allocator.destroy(client);
            }
            self.clients.deinit();

            self.callbacks.deinit();
            self.root_allocator.free(self.cqes);
            self.ring.deinit();
        }

        /// Runs the main loop until the `running` boolean is false.
        ///
        /// `accept_timeout` controls how much time the loop can wait for an accept operation to finish.
        /// This duration is the lower bound duration before the main loop can stop when `running` is false;
        pub fn run(self: *Self, accept_timeout: u63) !void {
            // TODO(vincent): we don't properly shutdown the peer sockets; we should do that.
            // This can be done using standard close(2) calls I think.

            while (self.running.load(.seq_cst)) {
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
                _ = try self.processCompletions(submitted);
            }
            try self.drain();
        }

        fn maybeAccept(self: *Self, timeout: u63) !void {
            if (!self.running.load(.seq_cst)) {
                // we must stop: stop accepting connections.
                return;
            }
            if (self.listener.accept_waiting or self.clients.items.len >= self.options.max_connections) {
                return;
            }

            // Queue an accept and link it to a timeout.

            var sqe = try self.submitAccept();
            sqe.flags |= os.linux.IOSQE_IO_LINK;

            self.listener.timeout.sec = 0;
            self.listener.timeout.nsec = timeout;

            _ = try self.submitAcceptLinkTimeout();

            self.listener.accept_waiting = true;
        }

        /// Continuously submit SQEs and process completions until there are
        /// no more pending operations.
        ///
        /// This must be called when shutting down.
        fn drain(self: *Self) !void {
            // This call is only useful if pending > 0.
            //
            // It is currently impossible to have pending == 0 after an iteration of the main loop because:
            // * if no accept waiting maybeAccept `pending` will increase by 2.
            // * if an accept is waiting but we didn't get a connection, `pending` must still be >= 1.
            // * if an accept is waiting and we got a connection, the previous processCompletions call
            //   increased `pending` while doing request processing.
            // * if no accept waiting and too many connections, the previous processCompletions call
            //   increased `pending` while doing request processing.
            //
            // But to be extra sure we do this submit call outside the drain loop to ensure we have flushed all queued SQEs
            // submitted in the last processCompletions call in the main loop.

            _ = try self.submit(0);

            while (self.pending > 0) {
                _ = try self.submit(0);
                _ = try self.processCompletions(self.pending);
            }
        }

        /// Submits all pending SQE to the kernel, if any.
        /// Waits for `nr` events to be completed before returning (0 means don't wait).
        ///
        /// This also increments `pending` by the number of events submitted.
        ///
        /// Returns the number of events submitted.
        fn submit(self: *Self, nr: u32) !usize {
            const n = try self.ring.submit_and_wait(nr);
            self.pending += n;
            return n;
        }

        /// Process all ready CQEs, if any.
        /// Waits for `nr` events to be completed before processing begins (0 means don't wait).
        ///
        /// This also decrements `pending` by the number of events processed.
        ///
        /// Returnsd the number of events processed.
        fn processCompletions(self: *Self, nr: usize) !usize {
            // TODO(vincent): how should we handle EAGAIN and EINTR ? right now they will shutdown the server.
            const cqe_count = try self.ring.copy_cqes(self.cqes, @as(u32, @intCast(nr)));

            for (self.cqes[0..cqe_count]) |cqe| {
                debug.assert(cqe.user_data != 0);

                // We know that a SQE/CQE is _always_ associated with a pointer of type Callback.

                var cb = @as(*CallbackType, @ptrFromInt(cqe.user_data));
                defer self.callbacks.put(cb);

                // Call the provided function with the proper context.
                //
                // Note that while the callback function signature can return an error we don't bubble them up
                // simply because we can't shutdown the server due to a processing error.

                cb.call(cb.server, cb.client_context, cqe) catch |err| {
                    self.handleCallbackError(cb.client_context, err);
                };
            }

            self.pending -= cqe_count;

            return cqe_count;
        }

        fn handleCallbackError(self: *Self, client_opt: ?*ClientState, err: anyerror) void {
            if (err == error.Canceled) return;

            if (client_opt) |client| {
                switch (err) {
                    error.ConnectionResetByPeer => {
                        logger.info("ctx#{s:<4} client fd={d} disconnected", .{ self.user_context, client.fd });
                    },
                    error.UnexpectedEOF => {
                        logger.debug("ctx#{s:<4} unexpected eof", .{self.user_context});
                    },
                    else => {
                        logger.err("ctx#{s:<4} unexpected error {!}", .{ self.user_context, err });
                    },
                }

                _ = self.submitClose(client, client.fd, onCloseClient) catch {};
            } else {
                logger.err("ctx#{s:<4} unexpected error {!}", .{ self.user_context, err });
            }
        }

        fn submitAccept(self: *Self) !*io_uring_sqe {
            if (build_options.debug_accepts) {
                logger.debug("ctx#{s:<4} submitting accept on {d}", .{
                    self.user_context,
                    self.listener.server_fd,
                });
            }

            const tmp = try self.callbacks.get(onAccept, .{});

            return try self.ring.accept(
                @intFromPtr(tmp),
                self.listener.server_fd,
                &self.listener.peer_addr.any,
                &self.listener.peer_addr_size,
                0,
            );
        }

        fn submitAcceptLinkTimeout(self: *Self) !*io_uring_sqe {
            if (build_options.debug_accepts) {
                logger.debug("ctx#{s:<4} submitting link timeout", .{self.user_context});
            }

            const tmp = try self.callbacks.get(onAcceptLinkTimeout, .{});

            return self.ring.link_timeout(
                @intFromPtr(tmp),
                &self.listener.timeout,
                0,
            );
        }

        fn submitStandaloneClose(self: *Self, fd: posix.fd_t, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} submitting close of {d}", .{
                self.user_context,
                fd,
            });

            const tmp = try self.callbacks.get(cb, .{});

            return self.ring.close(
                @intFromPtr(tmp),
                fd,
            );
        }

        fn submitClose(self: *Self, client: *ClientState, fd: posix.fd_t, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} addr={} submitting close of {d}", .{
                self.user_context,
                client.peer.addr,
                fd,
            });

            const tmp = try self.callbacks.get(cb, .{client});

            return self.ring.close(
                @intFromPtr(tmp),
                fd,
            );
        }

        fn onAccept(self: *Self, cqe: os.linux.io_uring_cqe) !void {
            defer self.listener.accept_waiting = false;

            switch (cqe.err()) {
                .SUCCESS => {},
                .INTR => {
                    logger.debug("ctx#{s:<4} ON ACCEPT interrupted", .{self.user_context});
                    return error.Canceled;
                },
                .CANCELED => {
                    if (build_options.debug_accepts) {
                        logger.debug("ctx#{s:<4} ON ACCEPT timed out", .{self.user_context});
                    }
                    return error.Canceled;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} ON ACCEPT unexpected errno={}", .{ self.user_context, err });
                    return error.Unexpected;
                },
            }

            logger.debug("ctx#{s:<4} ON ACCEPT accepting connection from {}", .{ self.user_context, self.listener.peer_addr });

            const client_fd = @as(posix.socket_t, @intCast(cqe.res));

            var client = try self.root_allocator.create(ClientState);
            errdefer self.root_allocator.destroy(client);

            try client.init(
                self.root_allocator,
                self.listener.peer_addr,
                client_fd,
                self.options.max_buffer_size,
            );
            errdefer client.deinit();

            try self.clients.append(client);

            _ = try self.submitRead(client, client_fd, 0, onReadRequest);
        }

        fn onAcceptLinkTimeout(self: *Self, cqe: os.linux.io_uring_cqe) !void {
            switch (cqe.err()) {
                .CANCELED => {
                    if (build_options.debug_accepts) {
                        logger.debug("ctx#{s:<4} ON LINK TIMEOUT operation finished, timeout canceled", .{self.user_context});
                    }
                },
                .ALREADY => {
                    if (build_options.debug_accepts) {
                        logger.debug("ctx#{s:<4} ON LINK TIMEOUT operation already finished before timeout expired", .{self.user_context});
                    }
                },
                .TIME => {
                    if (build_options.debug_accepts) {
                        logger.debug("ctx#{s:<4} ON LINK TIMEOUT timeout finished before accept", .{self.user_context});
                    }
                },
                else => |err| {
                    logger.err("ctx#{s:<4} ON LINK TIMEOUT unexpected errno={}", .{ self.user_context, err });
                    return error.Unexpected;
                },
            }
        }

        fn onCloseClient(self: *Self, client: *ClientState, cqe: os.linux.io_uring_cqe) !void {
            logger.debug("ctx#{s:<4} addr={} ON CLOSE CLIENT fd={}", .{
                self.user_context,
                client.peer.addr,
                client.fd,
            });

            // Cleanup resources
            client.deinit();
            self.root_allocator.destroy(client);

            // Remove client from list
            const maybe_pos: ?usize = for (self.clients.items, 0..) |item, i| {
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
                    logger.err("ctx#{s:<4} unexpected errno={}", .{ self.user_context, err });
                    return error.Unexpected;
                },
            }
        }

        fn onClose(self: *Self, cqe: os.linux.io_uring_cqe) !void {
            logger.debug("ctx#{s:<4} ON CLOSE", .{self.user_context});

            switch (cqe.err()) {
                .SUCCESS => {},
                else => |err| {
                    logger.err("ctx#{s:<4} unexpected errno={}", .{ self.user_context, err });
                    return error.Unexpected;
                },
            }
        }

        fn onReadRequest(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    logger.err("ctx#{s:<4} addr={} broken pipe", .{ self.user_context, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    logger.debug("ctx#{s:<4} addr={} connection reset by peer", .{ self.user_context, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }
            if (cqe.res <= 0) {
                return error.UnexpectedEOF;
            }

            const read = @as(usize, @intCast(cqe.res));

            logger.debug("ctx#{s:<4} addr={} ON READ REQUEST read of {d} bytes succeeded", .{ self.user_context, client.peer.addr, read });

            const previous_len = client.buffer.items.len;
            try client.buffer.appendSlice(client.temp_buffer[0..read]);

            if (try picohttp.parseRequest(previous_len, client.buffer.items)) |result| {
                client.request_state.parse_result = result;
                try processRequest(self, client);
            } else {
                // Not enough data, read more.

                logger.debug("ctx#{s:<4} addr={} HTTP request incomplete, submitting read", .{ self.user_context, client.peer.addr });

                _ = try self.submitRead(
                    client,
                    client.fd,
                    0,
                    onReadRequest,
                );
            }
        }

        fn onWriteResponseBuffer(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    logger.err("ctx#{s:<4} addr={} broken pipe", .{ self.user_context, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    logger.err("ctx#{s:<4} addr={} connection reset by peer", .{ self.user_context, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }

            const written = @as(usize, @intCast(cqe.res));

            if (written < client.buffer.items.len) {
                // Short write, write the remaining data

                // Remove the already written data
                try client.buffer.replaceRange(0, written, &[0]u8{});

                _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
                return;
            }

            logger.debug("ctx#{s:<4} addr={} ON WRITE RESPONSE done", .{
                self.user_context,
                client.peer.addr,
            });

            // Response written, read the next request
            client.request_state = .{};
            client.buffer.clearRetainingCapacity();

            _ = try self.submitRead(client, client.fd, 0, onReadRequest);
        }

        fn onCloseResponseFile(self: *Self, client: *ClientState, cqe: os.linux.io_uring_cqe) !void {
            logger.debug("ctx#{s:<4} addr={} ON CLOSE RESPONSE FILE fd={s}", .{
                self.user_context,
                client.peer.addr,
                client.response_state.file.fd,
            });

            switch (cqe.err()) {
                .SUCCESS => {},
                else => |err| {
                    logger.err("ctx#{s:<4} unexpected errno={}", .{ self.user_context, err });
                    return error.Unexpected;
                },
            }
        }

        fn onWriteResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            debug.assert(client.buffer.items.len > 0);

            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    logger.err("ctx#{s:<4} addr={} broken pipe", .{ self.user_context, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    logger.err("ctx#{s:<4} addr={} connection reset by peer", .{ self.user_context, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} ON WRITE RESPONSE FILE unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }
            if (cqe.res <= 0) {
                return error.UnexpectedEOF;
            }

            const written = @as(usize, @intCast(cqe.res));

            logger.debug("ctx#{s:<4} addr={} ON WRITE RESPONSE FILE write of {d} bytes to {d} succeeded", .{
                self.user_context,
                client.peer.addr,
                written,
                client.fd,
            });

            if (written < client.buffer.items.len) {
                // Short write, write the remaining data

                // Remove the already written data
                try client.buffer.replaceRange(0, written, &[0]u8{});

                _ = try self.submitWrite(client, client.fd, 0, onWriteResponseFile);
                return;
            }

            if (client.response_state.file.offset < client.response_state.file.statx_buf.size) {
                // More data to read from the file, submit another read

                client.buffer.clearRetainingCapacity();

                const offset = client.response_state.file.offset;

                switch (client.response_state.file.fd) {
                    .direct => |fd| {
                        _ = try self.submitRead(client, fd, offset, onReadResponseFile);
                    },
                    .registered => |fd| {
                        var sqe = try self.submitRead(client, fd, offset, onReadResponseFile);
                        sqe.flags |= os.linux.IOSQE_FIXED_FILE;
                    },
                }
                return;
            }

            logger.debug("ctx#{s:<4} addr={} ON WRITE RESPONSE FILE done", .{
                self.user_context,
                client.peer.addr,
            });

            // Response file written, read the next request

            // Close the response file descriptor
            switch (client.response_state.file.fd) {
                .direct => |fd| {
                    _ = try self.submitClose(client, fd, onCloseResponseFile);
                    client.response_state.file.fd = .{ .direct = -1 };
                },
                .registered => {},
            }

            // Reset the client state
            client.reset();

            _ = try self.submitRead(client, client.fd, 0, onReadRequest);
        }

        fn onReadResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            switch (cqe.err()) {
                .SUCCESS => {},
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} ON READ RESPONSE FILE unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }
            if (cqe.res <= 0) {
                return error.UnexpectedEOF;
            }

            const read = @as(usize, @intCast(cqe.res));

            client.response_state.file.offset += read;

            logger.debug("ctx#{s:<4} addr={} ON READ RESPONSE FILE read of {d} bytes from {s} succeeded, data=\"{s}\"", .{
                self.user_context,
                client.peer.addr,
                read,
                client.response_state.file.fd,
                fmt.fmtSliceEscapeLower(client.temp_buffer[0..read]),
            });

            try client.buffer.appendSlice(client.temp_buffer[0..read]);

            _ = try self.submitWrite(client, client.fd, 0, onWriteResponseFile);
        }

        fn onStatxResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            switch (cqe.err()) {
                .SUCCESS => {
                    debug.assert(client.buffer.items.len == 0);
                },
                .CANCELED => {
                    return error.Canceled;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} ON STATX RESPONSE FILE unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }

            logger.debug("ctx#{s:<4} addr={} ON STATX RESPONSE FILE path=\"{s}\" fd={s}, size={s}", .{
                self.user_context,
                client.peer.addr,
                client.response_state.file.path,
                client.response_state.file.fd,
                fmt.fmtIntSizeBin(client.response_state.file.statx_buf.size),
            });

            // Prepare the preambule + headers.
            // This will be written to the socket on the next write operation following
            // the first read operation for this file.
            client.response_state.status_code = .ok;
            try client.startWritingResponse(client.response_state.file.statx_buf.size);

            // If the file has already been registered, use its registered file descriptor.
            if (self.registered_files.get(client.response_state.file.path)) |entry| {
                logger.debug("ctx#{s:<4} addr={} ON STATX RESPONSE FILE file descriptor already registered, path=\"{s}\" registered fd={d}", .{
                    self.user_context,
                    client.peer.addr,
                    client.response_state.file.path,
                    entry.fd,
                });

                var sqe = try self.submitRead(client, entry.fd, 0, onReadResponseFile);
                sqe.flags |= os.linux.IOSQE_FIXED_FILE;

                return;
            }

            // The file has not yet been registered, try to do it

            // Assert the file descriptor is of type .direct, if it isn't it's a bug.
            debug.assert(client.response_state.file.fd == .direct);
            const fd = client.response_state.file.fd.direct;

            if (self.registered_fds.acquire(fd)) |registered_fd| {
                // We were able to acquire a registered file descriptor, make use of it.

                logger.debug("ctx#{s:<4} addr={} ON STATX RESPONSE FILE registered file descriptor, path=\"{s}\" registered fd={d}", .{
                    self.user_context,
                    client.peer.addr,
                    client.response_state.file.path,
                    registered_fd,
                });

                client.response_state.file.fd = .{ .registered = registered_fd };

                try self.registered_fds.update(&self.ring);

                const entry = try self.registered_files.getOrPut(client.response_state.file.path);
                if (!entry.found_existing) {
                    entry.key_ptr.* = try self.root_allocator.dupe(u8, client.response_state.file.path);
                    entry.value_ptr.* = RegisteredFile{
                        .fd = registered_fd,
                        .size = client.response_state.file.statx_buf.size,
                    };
                }

                var sqe = try self.submitRead(client, registered_fd, 0, onReadResponseFile);
                sqe.flags |= os.linux.IOSQE_FIXED_FILE;
                return;
            }

            // The file isn't registered and we weren't able to register it, do a standard read.
            _ = try self.submitRead(client, fd, 0, onReadResponseFile);
        }

        fn onReadBody(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            assert(client.request_state.content_length != null);
            assert(client.request_state.body != null);

            switch (cqe.err()) {
                .SUCCESS => {},
                .PIPE => {
                    logger.err("ctx#{s:<4} addr={} broken pipe", .{ self.user_context, client.peer.addr });
                    return error.BrokenPipe;
                },
                .CONNRESET => {
                    logger.err("ctx#{s:<4} addr={} connection reset by peer", .{ self.user_context, client.peer.addr });
                    return error.ConnectionResetByPeer;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }
            if (cqe.res <= 0) {
                return error.UnexpectedEOF;
            }

            const read = @as(usize, @intCast(cqe.res));

            logger.debug("ctx#{s:<4} addr={} ON READ BODY read of {d} bytes succeeded", .{ self.user_context, client.peer.addr, read });

            try client.buffer.appendSlice(client.temp_buffer[0..read]);
            client.refreshBody();

            const content_length = client.request_state.content_length.?;
            const body = client.request_state.body.?;

            if (body.len < content_length) {
                logger.debug("ctx#{s:<4} addr={} buffer len={d} bytes, content length={d} bytes", .{
                    self.user_context,
                    client.peer.addr,
                    body.len,
                    content_length,
                });

                // Not enough data, read more.
                _ = try self.submitRead(client, client.fd, 0, onReadBody);
                return;
            }

            // Request is complete: call handler
            try self.callHandler(client);
        }

        fn onOpenResponseFile(self: *Self, client: *ClientState, cqe: io_uring_cqe) !void {
            debug.assert(client.buffer.items.len == 0);

            switch (cqe.err()) {
                .SUCCESS => {},
                .NOENT => {
                    client.temp_buffer_fba.reset();

                    logger.warn("ctx#{s:<4} addr={} no such file or directory, path=\"{s}\"", .{
                        self.user_context,
                        client.peer.addr,
                        fmt.fmtSliceEscapeLower(client.response_state.file.path),
                    });

                    try self.submitWriteNotFound(client);
                    return;
                },
                else => |err| {
                    logger.err("ctx#{s:<4} addr={} unexpected errno={}", .{ self.user_context, client.peer.addr, err });
                    return error.Unexpected;
                },
            }

            client.response_state.file.fd = .{ .direct = @as(posix.fd_t, @intCast(cqe.res)) };

            logger.debug("ctx#{s:<4} addr={} ON OPEN RESPONSE FILE fd={s}", .{ self.user_context, client.peer.addr, client.response_state.file.fd });

            client.temp_buffer_fba.reset();
        }

        fn callHandler(self: *Self, client: *ClientState) !void {
            // Create a request for the handler.
            // This doesn't own any data and it only lives for the duration of this function call.
            const req = try Request.create(
                client.request_state.parse_result.raw_request,
                client.request_state.body,
            );

            // Call the user provided handler to get a response.
            const response = try self.handler(
                self.user_context,
                client.gpa,
                client.peer,
                req,
            );
            // TODO(vincent): cleanup in case of errors ?
            // errdefer client.reset();

            // At this point the request data is no longer needed so we can clear the buffer.
            client.buffer.clearRetainingCapacity();

            // Process the response:
            // * `response` contains a simple buffer that we can write to the socket straight away.
            // * `send_file` contains a file path that we need to open and statx before we can read/write it to the socket.

            switch (response) {
                .response => |res| {
                    client.response_state.status_code = res.status_code;
                    client.response_state.headers = res.headers;

                    try client.startWritingResponse(res.data.len);
                    try client.buffer.appendSlice(res.data);

                    _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
                },
                .send_file => |res| {
                    client.response_state.status_code = res.status_code;
                    client.response_state.headers = res.headers;
                    client.response_state.file.path = try client.temp_buffer_fba.allocator().dupeZ(u8, res.path);

                    if (self.registered_files.get(client.response_state.file.path)) |registered_file| {
                        logger.debug("ctx#{s:<4} addr={} FILE path=\"{s}\" is already registered, fd={d}", .{
                            self.user_context,
                            client.peer.addr,
                            client.response_state.file.path,
                            registered_file.fd,
                        });

                        client.response_state.file.fd = .{ .registered = registered_file.fd };
                        client.temp_buffer_fba.reset();

                        // Prepare the preambule + headers.
                        // This will be written to the socket on the next write operation following
                        // the first read operation for this file.
                        client.response_state.status_code = .ok;
                        try client.startWritingResponse(registered_file.size);

                        // Now read the response file
                        var sqe = try self.submitRead(client, registered_file.fd, 0, onReadResponseFile);
                        sqe.flags |= os.linux.IOSQE_FIXED_FILE;
                    } else {
                        var sqe = try self.submitOpenFile(
                            client,
                            client.response_state.file.path,
                            .{ .ACCMODE = .RDONLY, .NOFOLLOW = true },
                            0o644,
                            onOpenResponseFile,
                        );
                        sqe.flags |= os.linux.IOSQE_IO_LINK;

                        _ = try self.submitStatxFile(
                            client,
                            client.response_state.file.path,
                            os.linux.AT.SYMLINK_NOFOLLOW,
                            os.linux.STATX_SIZE,
                            &client.response_state.file.statx_buf,
                            onStatxResponseFile,
                        );
                    }
                },
            }
        }

        fn submitWriteNotFound(self: *Self, client: *ClientState) !void {
            logger.debug("ctx#{s:<4} addr={} returning 404 Not Found", .{
                self.user_context,
                client.peer.addr,
            });

            const static_response = "Not Found";

            client.response_state.status_code = .not_found;
            try client.startWritingResponse(static_response.len);
            try client.buffer.appendSlice(static_response);

            _ = try self.submitWrite(client, client.fd, 0, onWriteResponseBuffer);
        }

        fn processRequest(self: *Self, client: *ClientState) !void {
            // Try to find the content length. If there's one we switch to reading the body.
            const content_length = try client.request_state.parse_result.raw_request.getContentLength();
            if (content_length) |n| {
                logger.debug("ctx#{s:<4} addr={} content length: {d}", .{ self.user_context, client.peer.addr, n });

                client.request_state.content_length = n;
                client.refreshBody();

                if (client.request_state.body) |body| {
                    logger.debug("ctx#{s:<4} addr={} body incomplete, usable={d} bytes, content length: {d} bytes", .{
                        self.user_context,
                        client.peer.addr,
                        body.len,
                        n,
                    });

                    _ = try self.submitRead(client, client.fd, 0, onReadBody);
                    return;
                }

                // Request is complete: call handler
                try self.callHandler(client);
                return;
            }

            // Otherwise it's a simple call to the handler.
            try self.callHandler(client);
        }

        fn submitRead(self: *Self, client: *ClientState, fd: posix.socket_t, offset: u64, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} addr={} submitting read from {d}, offset {d}", .{
                self.user_context,
                client.peer.addr,
                fd,
                offset,
            });

            const tmp = try self.callbacks.get(cb, .{client});

            return self.ring.read(
                @intFromPtr(tmp),
                fd,
                .{ .buffer = &client.temp_buffer },
                offset,
            );
        }

        fn submitWrite(self: *Self, client: *ClientState, fd: posix.fd_t, offset: u64, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} addr={} submitting write of {s} to {d}, offset {d}, data=\"{s}\"", .{
                self.user_context,
                client.peer.addr,
                fmt.fmtIntSizeBin(client.buffer.items.len),
                fd,
                offset,
                fmt.fmtSliceEscapeLower(client.buffer.items),
            });

            const tmp = try self.callbacks.get(cb, .{client});

            return self.ring.write(
                @intFromPtr(tmp),
                fd,
                client.buffer.items,
                offset,
            );
        }

        fn submitOpenFile(self: *Self, client: *ClientState, path: [:0]const u8, flags: os.linux.O, mode: posix.mode_t, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} addr={} submitting open, path=\"{s}\"", .{
                self.user_context,
                client.peer.addr,
                fmt.fmtSliceEscapeLower(path),
            });

            const tmp = try self.callbacks.get(cb, .{client});

            return try self.ring.openat(
                @intFromPtr(tmp),
                os.linux.AT.FDCWD,
                path,
                flags,
                mode,
            );
        }

        fn submitStatxFile(self: *Self, client: *ClientState, path: [:0]const u8, flags: u32, mask: u32, buf: *os.linux.Statx, comptime cb: anytype) !*io_uring_sqe {
            logger.debug("ctx#{s:<4} addr={} submitting statx, path=\"{s}\"", .{
                self.user_context,
                client.peer.addr,
                fmt.fmtSliceEscapeLower(path),
            });

            const tmp = try self.callbacks.get(cb, .{client});

            return self.ring.statx(
                @intFromPtr(tmp),
                os.linux.AT.FDCWD,
                path,
                flags,
                mask,
                buf,
            );
        }
    };
}

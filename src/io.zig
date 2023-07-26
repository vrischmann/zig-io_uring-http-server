const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const net = std.net;
const os = std.os;

const IO_Uring = std.os.linux.IO_Uring;

const logger = std.log.scoped(.io_helpers);

// TODO(vincent): make this dynamic
const max_connections = 128;

pub const RegisteredFile = struct {
    fd: os.fd_t,
    size: u64,
};

/// Manages a set of registered file descriptors.
/// The set size is fixed at compile time.
///
/// A client must acquire a file descriptor to use it, and release it when it disconnects.
pub const RegisteredFileDescriptors = struct {
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
        for (&self.states, 0..) |*state, i| {
            if (state.* == .free) {
                // Slot is free, change its state and set the file descriptor.

                state.* = .used;
                self.fds[i] = fd;

                return @as(i32, @intCast(i));
            }
        } else {
            return null;
        }
    }

    pub fn release(self: *Self, index: i32) void {
        const idx = @as(usize, @intCast(index));

        debug.assert(self.states[idx] == .used);
        debug.assert(self.fds[idx] != -1);

        self.states[idx] = .free;
        self.fds[idx] = -1;
    }
};

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

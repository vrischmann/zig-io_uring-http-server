const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.posix;

const IoUring = std.os.linux.IoUring;

const logger = std.log.scoped(.io_helpers);

// TODO(vincent): make this dynamic
const max_connections = 128;

pub const RegisteredFile = struct {
    fd: posix.fd_t,
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

    fds: [max_connections]posix.fd_t = [_]posix.fd_t{-1} ** max_connections,
    states: [max_connections]State = [_]State{.free} ** max_connections,

    pub fn register(self: *Self, ring: *IoUring) !void {
        logger.debug("REGISTERED FILE DESCRIPTORS, fds={d}", .{
            self.fds,
        });

        try ring.register_files(self.fds[0..]);
    }

    pub fn update(self: *Self, ring: *IoUring) !void {
        logger.debug("UPDATE FILE DESCRIPTORS, fds={d}", .{
            self.fds,
        });

        try ring.register_files_update(0, self.fds[0..]);
    }

    pub fn acquire(self: *Self, fd: posix.fd_t) ?i32 {
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
pub fn createSocket(port: u16) !posix.socket_t {
    const sockfd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, 0);
    errdefer posix.close(sockfd);

    // Enable reuseaddr if possible
    posix.setsockopt(
        sockfd,
        posix.SOL.SOCKET,
        posix.SO.REUSEPORT,
        &mem.toBytes(@as(c_int, 1)),
    ) catch {};

    // Disable IPv6 only
    try posix.setsockopt(
        sockfd,
        posix.IPPROTO.IPV6,
        os.linux.IPV6.V6ONLY,
        &mem.toBytes(@as(c_int, 0)),
    );

    const addr = try net.Address.parseIp6("::0", port);

    try posix.bind(sockfd, &addr.any, @sizeOf(posix.sockaddr.in6));
    try posix.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

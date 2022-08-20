const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;

const assert = std.debug.assert;

const io_uring_cqe = std.os.linux.io_uring_cqe;

/// Callback encapsulates a context and a function pointer that will be called when
/// the server loop will process the CQEs.
/// Pointers to this structure is what get passed as user data in a SQE and what we later get back in a CQE.
///
/// There are two kinds of callbacks currently:
/// * operations associated with a client
/// * operations not associated with a client
pub fn Callback(comptime ServerType: type, comptime ClientContext: type) type {
    return struct {
        const Self = @This();

        server: ServerType,
        client_context: ?ClientContext = null,
        call: *const fn (ServerType, ?ClientContext, io_uring_cqe) anyerror!void,

        next: ?*Self = null,

        /// Pool is a pool of callback objects that facilitates lifecycle management of a callback.
        /// The implementation is a free list of pre-allocated objects.
        ///
        /// For each SQEs a callback must be obtained via get().
        /// When the server loop is processing CQEs it will use the callback and then release it with put().
        pub const Pool = struct {
            allocator: mem.Allocator,
            nb: usize,
            free_list: ?*Self,

            pub fn init(allocator: mem.Allocator, server: ServerType, nb: usize) !Pool {
                var res = Pool{
                    .allocator = allocator,
                    .nb = nb,
                    .free_list = null,
                };

                // Preallocate as many callbacks as ring entries.

                var i: usize = 0;
                while (i < nb) : (i += 1) {
                    const callback = try allocator.create(Self);
                    callback.* = .{
                        .server = server,
                        .client_context = undefined,
                        .call = undefined,
                        .next = res.free_list,
                    };
                    res.free_list = callback;
                }

                return res;
            }

            pub fn deinit(self: *Pool) void {
                // All callbacks must be put back in the pool before deinit is called
                assert(self.count() == self.nb);

                var ret = self.free_list;
                while (ret) |item| {
                    ret = item.next;
                    self.allocator.destroy(item);
                }
            }

            /// Returns the number of callback in the pool.
            pub fn count(self: *Pool) usize {
                var n: usize = 0;
                var ret = self.free_list;
                while (ret) |item| {
                    n += 1;
                    ret = item.next;
                }
                return n;
            }

            /// Returns a ready to use callback or an error if none are available.
            /// `cb` must be a function with either one of the following signatures:
            ///   * fn(ServerType, io_uring_cqe)
            ///   * fn(ServerType, ClientContext, io_uring_cqe)
            ///
            /// If `cb` takes a ClientContext `args` must be a tuple with at least the first element being a ClientContext.
            pub fn get(self: *Pool, comptime cb: anytype, args: anytype) !*Self {
                const ret = self.free_list orelse return error.OutOfCallback;
                self.free_list = ret.next;

                // Provide a wrapper based on the callback function.

                const func_args = std.meta.fields(std.meta.ArgsTuple(@TypeOf(cb)));

                switch (func_args.len) {
                    3 => {
                        comptime {
                            expectFuncArgType(func_args, 0, ServerType);
                            expectFuncArgType(func_args, 1, ClientContext);
                            expectFuncArgType(func_args, 2, io_uring_cqe);
                        }

                        ret.client_context = args[0];
                        ret.call = struct {
                            fn wrapper(server: ServerType, client_context: ?ClientContext, cqe: io_uring_cqe) anyerror!void {
                                return cb(server, client_context.?, cqe);
                            }
                        }.wrapper;
                    },
                    2 => {
                        comptime {
                            expectFuncArgType(func_args, 0, ServerType);
                            expectFuncArgType(func_args, 1, io_uring_cqe);
                        }

                        ret.client_context = null;
                        ret.call = struct {
                            fn wrapper(server: ServerType, client_context: ?ClientContext, cqe: io_uring_cqe) anyerror!void {
                                _ = client_context;
                                return cb(server, cqe);
                            }
                        }.wrapper;
                    },
                    else => @compileError("invalid callback function " ++ @typeName(@TypeOf(cb))),
                }

                ret.next = null;

                return ret;
            }

            /// Reset the callback and puts it back into the pool.
            pub fn put(self: *Pool, callback: *Self) void {
                callback.client_context = null;
                callback.next = self.free_list;
                self.free_list = callback;
            }
        };
    };
}

/// Checks that the argument at `idx` has the type `exp`.
fn expectFuncArgType(comptime args: []const std.builtin.TypeInfo.StructField, comptime idx: usize, comptime exp: type) void {
    if (args[idx].field_type != exp) {
        var msg = fmt.comptimePrint("expected func arg {d} to be of type {s}, got {s}", .{
            idx,
            @typeName(exp),
            @typeName(args[idx].field_type),
        });
        @compileError(msg);
    }
}

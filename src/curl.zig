const std = @import("std");
const heap = std.heap;
const io = std.io;
const mem = std.mem;

const c = @cImport({
    @cInclude("curl/curl.h");
});

pub const Response = struct {
    allocator: mem.Allocator,

    response_code: usize,
    data: []const u8,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.data);
    }
};

pub fn do(allocator: mem.Allocator, method: []const u8, url: [:0]const u8, body_opt: ?[]const u8) !Response {
    _ = method;

    if (c.curl_global_init(c.CURL_GLOBAL_ALL) != c.CURLE_OK) {
        return error.CURLGlobalInitFailed;
    }
    defer c.curl_global_cleanup();

    const handle = c.curl_easy_init() orelse return error.CURLHandleInitFailed;
    defer c.curl_easy_cleanup(handle);

    var response = std.ArrayList(u8).init(allocator);

    // setup curl options
    _ = c.curl_easy_setopt(handle, c.CURLOPT_URL, url.ptr);

    // set write function callbacks
    _ = c.curl_easy_setopt(handle, c.CURLOPT_WRITEFUNCTION, &writeToArrayListCallback);
    _ = c.curl_easy_setopt(handle, c.CURLOPT_WRITEDATA, &response);

    // set read function callbacks

    var headers: [*c]c.curl_slist = null;
    defer c.curl_slist_free_all(headers);

    if (body_opt) |data| {
        headers = c.curl_slist_append(headers, "Content-Type: application/json");

        _ = c.curl_easy_setopt(handle, c.CURLOPT_HTTPHEADER, headers);
        _ = c.curl_easy_setopt(handle, c.CURLOPT_POSTFIELDSIZE, data.len);
        _ = c.curl_easy_setopt(handle, c.CURLOPT_COPYPOSTFIELDS, data.ptr);
    }

    // perform
    if (c.curl_easy_perform(handle) != c.CURLE_OK) {
        return error.FailedToPerformRequest;
    }

    // get information
    var res = Response{
        .allocator = allocator,
        .response_code = 0,
        .data = response.toOwnedSlice(),
    };

    _ = c.curl_easy_getinfo(handle, c.CURLINFO_RESPONSE_CODE, &res.response_code);

    return res;
}

fn writeToArrayListCallback(data: *anyopaque, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    var buffer = @intToPtr(*std.ArrayList(u8), @ptrToInt(user_data));
    var typed_data = @intToPtr([*]u8, @ptrToInt(data));

    buffer.appendSlice(typed_data[0 .. nmemb * size]) catch return 0;

    return nmemb * size;
}

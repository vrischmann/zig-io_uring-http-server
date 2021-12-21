# zig-io\_uring-http-server

Experiment writing a sort of working HTTP server using:
* [io\_uring](https://unixism.net/loti/what_is_io_uring.html)
* [Zig](https://ziglang.org)
* [picohttpparser](https://github.com/h2o/picohttpparser)

# Requirements

* Linux 5.11 minimum
* [Zig master](https://ziglang.org/download/)
* libcurl and its development files (`libcurl-devel` on Fedora, `libcurl4-openssl-dev` on Debian)

# Building

Just run this:
```
zig build
```

The binary will be at `zig-out/bin/httpserver`.

# Testing

Just run this:
```
zig build test
```

The test harness need libcurl installed to perform request on the HTTP server.

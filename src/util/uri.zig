const std = @import("std");

pub const Error = error{
    MissingHost,
    UnsupportedScheme,
};

pub fn defaultPortForScheme(scheme: []const u8) Error!u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
    return error.UnsupportedScheme;
}

pub fn hostHeaderAlloc(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: ?u16,
    scheme: []const u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    const default_port = try defaultPortForScheme(scheme);
    if (port == null or port.? == default_port) return allocator.dupe(u8, host);
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port.? });
}

pub fn hostHeaderAllocForUri(allocator: std.mem.Allocator, uri: std.Uri) (Error || std.mem.Allocator.Error)![]u8 {
    const host_part = uri.host orelse return error.MissingHost;
    const host = try host_part.toRawMaybeAlloc(allocator);
    return hostHeaderAlloc(allocator, host, uri.port, uri.scheme);
}

test "hostHeaderAllocForUri omits default ports and includes non-default ports" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    {
        const uri = try std.Uri.parse("https://example.test/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test", host);
    }
    {
        const uri = try std.Uri.parse("https://example.test:443/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test", host);
    }
    {
        const uri = try std.Uri.parse("https://example.test:8443/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test:8443", host);
    }

    {
        const uri = try std.Uri.parse("http://example.test/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test", host);
    }
    {
        const uri = try std.Uri.parse("http://example.test:80/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test", host);
    }
    {
        const uri = try std.Uri.parse("http://example.test:8080/path");
        const host = try hostHeaderAllocForUri(a, uri);
        try std.testing.expectEqualStrings("example.test:8080", host);
    }
}

test "hostHeaderAllocForUri preserves IPv6 brackets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const uri = try std.Uri.parse("http://[::1]:8080/x");
    const host = try hostHeaderAllocForUri(a, uri);
    try std.testing.expectEqualStrings("[::1]:8080", host);
}

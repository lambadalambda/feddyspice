const std = @import("std");

const app = @import("../app.zig");
const http_types = @import("../http_types.zig");
const url = @import("../util/url.zig");
const users = @import("../users.zig");
const version = @import("../version.zig");

pub fn hostMeta(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const scheme = @tagName(app_state.cfg.scheme);
    const domain = app_state.cfg.domain;

    const body = std.fmt.allocPrint(
        allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
        \\  <Link rel="lrdd" type="application/jrd+json" template="{s}://{s}/.well-known/webfinger?resource={{uri}}" />
        \\</XRD>
        \\
    ,
        .{ scheme, domain },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/xrd+xml; charset=utf-8",
        .body = body,
    };
}

pub fn nodeinfoDiscovery(app_state: *app.App, allocator: std.mem.Allocator) http_types.Response {
    const base = url.baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const href = std.fmt.allocPrint(allocator, "{s}/nodeinfo/2.0", .{base}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .links = [_]struct { rel: []const u8, href: []const u8 }{
            .{
                .rel = "http://nodeinfo.diaspora.software/ns/schema/2.0",
                .href = href,
            },
        },
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn nodeinfoDocumentWithVersion(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    schema_version: []const u8,
) http_types.Response {
    const user_count = users.count(&app_state.conn) catch 0;
    const open_registrations = (user_count == 0);

    const payload = .{
        .version = schema_version,
        .software = .{
            .name = "feddyspice",
            .version = version.version,
        },
        .protocols = [_][]const u8{"activitypub"},
        .services = .{
            .inbound = [_][]const u8{},
            .outbound = [_][]const u8{},
        },
        .openRegistrations = open_registrations,
        .usage = .{
            .users = .{
                .total = user_count,
            },
            .localPosts = @as(i64, 0),
        },
        .metadata = .{},
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
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

pub fn webfinger(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    const resource = common.parseQueryParam(allocator, q, "resource") catch
        return .{ .status = .bad_request, .body = "invalid query\n" };
    if (resource == null) return .{ .status = .bad_request, .body = "missing resource\n" };

    const prefix = "acct:";
    if (!std.mem.startsWith(u8, resource.?, prefix)) return .{ .status = .not_found, .body = "not found\n" };

    const acct = resource.?[prefix.len..];
    const at = std.mem.indexOfScalar(u8, acct, '@') orelse return .{ .status = .not_found, .body = "not found\n" };
    const username = acct[0..at];
    const domain = acct[at + 1 ..];
    if (!std.mem.eql(u8, domain, app_state.cfg.domain)) return .{ .status = .not_found, .body = "not found\n" };

    const user = users.lookupUserByUsername(&app_state.conn, allocator, username) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (user == null) return .{ .status = .not_found, .body = "not found\n" };

    const base = url.baseUrlAlloc(app_state, allocator) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const href = std.fmt.allocPrint(allocator, "{s}/users/{s}", .{ base, username }) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const Link = struct {
        rel: []const u8,
        type: []const u8,
        href: []const u8,
    };

    const payload = .{
        .subject = resource.?,
        .links = [_]Link{
            .{ .rel = "self", .type = "application/activity+json", .href = href },
        },
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/jrd+json; charset=utf-8",
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

const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const filters = @import("../filters.zig");
const http_types = @import("../http_types.zig");
const oauth = @import("../oauth.zig");

const FilterPayload = struct {
    id: []const u8,
    phrase: []const u8,
    context: []const []const u8,
    expires_at: ?[]const u8,
    irreversible: bool,
    whole_word: bool,
};

fn splitContextAlloc(allocator: std.mem.Allocator, raw: []const u8) []const []const u8 {
    if (raw.len == 0) return &.{};

    var it = std.mem.splitScalar(u8, raw, '\n');
    var count: usize = 0;
    while (it.next()) |part| {
        if (part.len == 0) continue;
        count += 1;
    }

    if (count == 0) return &.{};

    const out = allocator.alloc([]const u8, count) catch return &.{};
    var idx: usize = 0;
    it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        out[idx] = part;
        idx += 1;
    }
    return out;
}

fn makeFilterPayload(allocator: std.mem.Allocator, f: filters.Filter) FilterPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{f.id}) catch "0";
    return .{
        .id = id_str,
        .phrase = f.phrase,
        .context = splitContextAlloc(allocator, f.context),
        .expires_at = f.expires_at,
        .irreversible = f.irreversible,
        .whole_word = f.whole_word,
    };
}

fn parseBool(s: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(s, "true")) return true;
    if (std.mem.eql(u8, s, "1")) return true;
    return false;
}

fn getContextParam(parsed: *const @import("../form.zig").Form) ?[]const u8 {
    return parsed.get("context[]") orelse parsed.get("context");
}

pub fn filtersIndex(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const rows = filters.listByUser(&app_state.conn, allocator, info.?.user_id, 200) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    var payloads: std.ArrayListUnmanaged(FilterPayload) = .empty;
    defer payloads.deinit(allocator);

    for (rows) |f| {
        payloads.append(allocator, makeFilterPayload(allocator, f)) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
    }

    return common.jsonOk(allocator, payloads.items);
}

pub fn filtersCreate(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const phrase_raw = parsed.get("phrase") orelse return .{ .status = .unprocessable_entity, .body = "invalid phrase\n" };
    const phrase = std.mem.trim(u8, phrase_raw, " \t\r\n");
    if (phrase.len == 0) return .{ .status = .unprocessable_entity, .body = "invalid phrase\n" };

    const context_raw = getContextParam(&parsed) orelse "";
    const irreversible = parseBool(parsed.get("irreversible") orelse "false");
    const whole_word = parseBool(parsed.get("whole_word") orelse "false");

    const f = filters.create(&app_state.conn, allocator, info.?.user_id, phrase, context_raw, irreversible, whole_word, null) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return common.jsonOk(allocator, makeFilterPayload(allocator, f));
}

pub fn filterGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/filters/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const f = filters.lookupByIdForUser(&app_state.conn, allocator, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (f == null) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, makeFilterPayload(allocator, f.?));
}

pub fn filterUpdate(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/filters/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };
    defer parsed.deinit(allocator);

    const phrase_raw = parsed.get("phrase");
    const phrase_trimmed = if (phrase_raw) |p| std.mem.trim(u8, p, " \t\r\n") else null;
    if (phrase_trimmed != null and phrase_trimmed.?.len == 0) return .{ .status = .unprocessable_entity, .body = "invalid phrase\n" };

    const context_raw = getContextParam(&parsed);

    const irreversible_opt: ?bool = if (parsed.get("irreversible")) |v| parseBool(v) else null;
    const whole_word_opt: ?bool = if (parsed.get("whole_word")) |v| parseBool(v) else null;

    const f = filters.update(&app_state.conn, allocator, id, info.?.user_id, phrase_trimmed, context_raw, irreversible_opt, whole_word_opt) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (f == null) return .{ .status = .not_found, .body = "not found\n" };

    return common.jsonOk(allocator, makeFilterPayload(allocator, f.?));
}

pub fn filterDelete(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request, path: []const u8) http_types.Response {
    const token = common.bearerToken(req.authorization) orelse return common.unauthorized(allocator);
    const info = oauth.verifyAccessToken(&app_state.conn, allocator, token) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (info == null) return common.unauthorized(allocator);

    const prefix = "/api/v1/filters/";
    if (!std.mem.startsWith(u8, path, prefix)) return .{ .status = .not_found, .body = "not found\n" };
    const id_part = path[prefix.len..];
    const id = std.fmt.parseInt(i64, id_part, 10) catch
        return .{ .status = .not_found, .body = "not found\n" };

    const ok = filters.delete(&app_state.conn, id, info.?.user_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .not_found, .body = "not found\n" };

    const payload: struct {} = .{};
    return common.jsonOk(allocator, payload);
}

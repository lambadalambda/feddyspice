const std = @import("std");

const app = @import("../app.zig");
const common = @import("common.zig");
const form = @import("../form.zig");
const http_types = @import("../http_types.zig");
const oauth = @import("../oauth.zig");
const rate_limit = @import("../rate_limit.zig");
const session = @import("session.zig");

pub fn registerApp(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const ok = rate_limit.allowNow(&app_state.conn, "apps_post", 60_000, 30) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return .{ .status = .too_many_requests, .body = "too many requests\n" };

    var parsed = common.parseBodyParams(allocator, req) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const client_name = parsed.get("client_name") orelse
        return .{ .status = .bad_request, .body = "missing client_name\n" };
    const redirect_uris = parsed.get("redirect_uris") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uris\n" };
    const scopes = parsed.get("scopes") orelse "";
    const website = parsed.get("website") orelse "";

    const creds = oauth.createApp(&app_state.conn, allocator, client_name, redirect_uris, scopes, website) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const id_str = std.fmt.allocPrint(allocator, "{d}", .{creds.id}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .id = id_str,
        .name = client_name,
        .website = website,
        .redirect_uri = redirect_uris,
        .client_id = creds.client_id,
        .client_secret = creds.client_secret,
        .vapid_key = "",
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
    };
}

pub fn authorizeGet(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const q = common.queryString(req.target);
    var query = form.parse(allocator, q) catch
        return .{ .status = .bad_request, .body = "invalid query\n" };

    const response_type = query.get("response_type") orelse "";
    if (!std.mem.eql(u8, response_type, "code")) {
        return .{ .status = .bad_request, .body = "unsupported response_type\n" };
    }

    const client_id = query.get("client_id") orelse
        return .{ .status = .bad_request, .body = "missing client_id\n" };
    const redirect_uri = query.get("redirect_uri") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uri\n" };
    const scope = query.get("scope") orelse "";
    const state = query.get("state") orelse "";

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (app_row == null) return .{ .status = .bad_request, .body = "unknown client_id\n" };
    if (!oauth.redirectUriAllowed(app_row.?.redirect_uris, redirect_uri)) {
        return .{ .status = .bad_request, .body = "invalid redirect_uri\n" };
    }

    const user_id = session.currentUserId(app_state, req) catch null;
    if (user_id == null) {
        const encoded = common.percentEncodeAlloc(allocator, req.target) catch "";
        const location = std.fmt.allocPrint(allocator, "/login?return_to={s}", .{encoded}) catch "/login";
        return common.redirect(allocator, location);
    }

    const app_name = common.htmlEscapeAlloc(allocator, app_row.?.name) catch app_row.?.name;
    const client_id_html = common.htmlEscapeAlloc(allocator, client_id) catch client_id;
    const redirect_uri_html = common.htmlEscapeAlloc(allocator, redirect_uri) catch redirect_uri;
    const scope_html = common.htmlEscapeAlloc(allocator, scope) catch scope;
    const state_html = common.htmlEscapeAlloc(allocator, state) catch state;

    const page = std.fmt.allocPrint(
        allocator,
        \\<p>Authorize <strong>{s}</strong>?</p>
        \\<form method="POST" action="/oauth/authorize">
        \\  <input type="hidden" name="response_type" value="code">
        \\  <input type="hidden" name="client_id" value="{s}">
        \\  <input type="hidden" name="redirect_uri" value="{s}">
        \\  <input type="hidden" name="scope" value="{s}">
        \\  <input type="hidden" name="state" value="{s}">
        \\  <button type="submit" name="approve" value="1">Authorize</button>
        \\  <button type="submit" name="deny" value="1">Deny</button>
        \\</form>
    ,
        .{ app_name, client_id_html, redirect_uri_html, scope_html, state_html },
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return common.htmlPage(allocator, "Authorize", page);
}

pub fn authorizePost(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    if (!common.isForm(req.content_type)) {
        return .{ .status = .bad_request, .body = "invalid content-type\n" };
    }
    if (!common.isSameOrigin(req)) return .{ .status = .forbidden, .body = "forbidden\n" };

    const user_id = session.currentUserId(app_state, req) catch null;
    if (user_id == null) return common.redirect(allocator, "/login");

    var parsed = form.parse(allocator, req.body) catch
        return .{ .status = .bad_request, .body = "invalid form\n" };

    const response_type = parsed.get("response_type") orelse "";
    if (!std.mem.eql(u8, response_type, "code")) {
        return .{ .status = .bad_request, .body = "unsupported response_type\n" };
    }

    const client_id = parsed.get("client_id") orelse
        return .{ .status = .bad_request, .body = "missing client_id\n" };
    const redirect_uri = parsed.get("redirect_uri") orelse
        return .{ .status = .bad_request, .body = "missing redirect_uri\n" };
    const scope = parsed.get("scope") orelse "";
    const state = parsed.get("state") orelse "";
    const deny = parsed.get("deny");

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (app_row == null) return .{ .status = .bad_request, .body = "unknown client_id\n" };
    if (!oauth.redirectUriAllowed(app_row.?.redirect_uris, redirect_uri)) {
        return .{ .status = .bad_request, .body = "invalid redirect_uri\n" };
    }

    if (deny != null) {
        const loc = oauthErrorRedirect(allocator, redirect_uri, "access_denied", state) catch redirect_uri;
        return common.redirect(allocator, loc);
    }

    const code = oauth.createAuthCode(&app_state.conn, allocator, app_row.?.id, user_id.?, redirect_uri, scope) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    if (std.mem.eql(u8, redirect_uri, "urn:ietf:wg:oauth:2.0:oob")) {
        const page = std.fmt.allocPrint(allocator, "<p>Authorization code:</p><pre id=\"code\">{s}</pre>", .{code}) catch
            return .{ .status = .internal_server_error, .body = "internal server error\n" };
        var resp = common.htmlPage(allocator, "Authorization code", page);
        resp.headers = noStoreHeadersAlloc(allocator);
        return resp;
    }

    const loc = oauthCodeRedirect(allocator, redirect_uri, code, state) catch redirect_uri;
    return common.redirect(allocator, loc);
}

pub fn token(app_state: *app.App, allocator: std.mem.Allocator, req: http_types.Request) http_types.Response {
    const ok = rate_limit.allowNow(&app_state.conn, "oauth_token", 60_000, 60) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (!ok) return oauthErrorResponse(allocator, .too_many_requests, "temporarily_unavailable", "too many requests");

    var parsed = common.parseBodyParams(allocator, req) catch
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "invalid form");

    const grant_type = parsed.get("grant_type") orelse "";
    if (!std.mem.eql(u8, std.mem.trim(u8, grant_type, " \t\r\n"), "authorization_code")) {
        return oauthErrorResponse(allocator, .bad_request, "unsupported_grant_type", "unsupported grant_type");
    }

    const code = std.mem.trim(u8, parsed.get("code") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing code"), " \t\r\n");
    const client_id = std.mem.trim(u8, parsed.get("client_id") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing client_id"), " \t\r\n");
    const client_secret = std.mem.trim(u8, parsed.get("client_secret") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing client_secret"), " \t\r\n");
    const redirect_uri = std.mem.trim(u8, parsed.get("redirect_uri") orelse
        return oauthErrorResponse(allocator, .bad_request, "invalid_request", "missing redirect_uri"), " \t\r\n");

    const app_row = oauth.lookupAppByClientId(&app_state.conn, allocator, client_id) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (app_row == null) return oauthErrorResponse(allocator, .bad_request, "invalid_client", "unknown client_id");
    if (!std.mem.eql(u8, app_row.?.client_secret, client_secret)) {
        return oauthErrorResponse(allocator, .unauthorized, "invalid_client", "invalid client_secret");
    }

    const consumed = oauth.consumeAuthCode(&app_state.conn, allocator, code) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };
    if (consumed == null) {
        app_state.logger.warn(
            "oauth token invalid_code reason=not_found client_id={s} redirect_uri={s} code_prefix={s}",
            .{ client_id, redirect_uri, code[0..@min(code.len, 8)] },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }
    if (consumed.?.app_id != app_row.?.id) {
        app_state.logger.warn(
            "oauth token invalid_code reason=app_mismatch client_id={s} redirect_uri={s} code_prefix={s} consumed_app_id={d}",
            .{ client_id, redirect_uri, code[0..@min(code.len, 8)], consumed.?.app_id },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }
    if (!std.mem.eql(u8, consumed.?.redirect_uri, redirect_uri)) {
        app_state.logger.warn(
            "oauth token invalid_code reason=redirect_mismatch client_id={s} code_prefix={s} expected_redirect_uri={s} got_redirect_uri={s}",
            .{ client_id, code[0..@min(code.len, 8)], consumed.?.redirect_uri, redirect_uri },
        );
        return oauthErrorResponse(allocator, .bad_request, "invalid_grant", "invalid code");
    }

    const access_token = oauth.createAccessToken(&app_state.conn, allocator, app_row.?.id, consumed.?.user_id, consumed.?.scopes) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    const payload = .{
        .access_token = access_token,
        .token_type = "Bearer",
        .scope = consumed.?.scopes,
        .created_at = std.time.timestamp(),
    };

    const body = std.json.Stringify.valueAlloc(allocator, payload, .{}) catch
        return .{ .status = .internal_server_error, .body = "internal server error\n" };

    return .{
        .content_type = "application/json; charset=utf-8",
        .body = body,
        .headers = noStoreHeadersAlloc(allocator),
    };
}

fn oauthCodeRedirect(allocator: std.mem.Allocator, redirect_uri: []const u8, code: []const u8, state: []const u8) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, redirect_uri, '?') == null) "?" else "&";
    const code_enc = try common.percentEncodeAlloc(allocator, code);
    if (state.len > 0) {
        const state_enc = try common.percentEncodeAlloc(allocator, state);
        return std.fmt.allocPrint(allocator, "{s}{s}code={s}&state={s}", .{ redirect_uri, sep, code_enc, state_enc });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}code={s}", .{ redirect_uri, sep, code_enc });
}

fn oauthErrorRedirect(allocator: std.mem.Allocator, redirect_uri: []const u8, err: []const u8, state: []const u8) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, redirect_uri, '?') == null) "?" else "&";
    const err_enc = try common.percentEncodeAlloc(allocator, err);
    if (state.len > 0) {
        const state_enc = try common.percentEncodeAlloc(allocator, state);
        return std.fmt.allocPrint(allocator, "{s}{s}error={s}&state={s}", .{ redirect_uri, sep, err_enc, state_enc });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}error={s}", .{ redirect_uri, sep, err_enc });
}

fn oauthErrorResponse(
    allocator: std.mem.Allocator,
    status: std.http.Status,
    err_code: []const u8,
    description: []const u8,
) http_types.Response {
    const body = std.json.Stringify.valueAlloc(
        allocator,
        .{ .@"error" = err_code, .error_description = description },
        .{},
    ) catch return .{ .status = .internal_server_error, .body = "internal server error\n" };
    return .{
        .status = status,
        .content_type = "application/json; charset=utf-8",
        .body = body,
        .headers = noStoreHeadersAlloc(allocator),
    };
}

fn noStoreHeadersAlloc(allocator: std.mem.Allocator) []const std.http.Header {
    var headers = allocator.alloc(std.http.Header, 2) catch return &.{};
    headers[0] = .{ .name = "cache-control", .value = "no-store" };
    headers[1] = .{ .name = "pragma", .value = "no-cache" };
    return headers;
}

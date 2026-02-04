const std = @import("std");

const app = @import("../app.zig");
const media = @import("../media.zig");
const remote_actors = @import("../remote_actors.zig");
const remote_statuses = @import("../remote_statuses.zig");
const statuses = @import("../statuses.zig");
const url = @import("../util/url.zig");
const util_html = @import("../util/html.zig");
const util_ids = @import("../util/ids.zig");
const urls = @import("urls.zig");
const users = @import("../users.zig");

pub const AccountPayload = struct {
    id: []const u8,
    username: []const u8,
    acct: []const u8,
    display_name: []const u8,
    note: []const u8,
    url: []const u8,
    locked: bool,
    bot: bool,
    group: bool,
    discoverable: bool,
    created_at: []const u8,
    followers_count: i64,
    following_count: i64,
    statuses_count: i64,
    avatar: []const u8,
    avatar_static: []const u8,
    header: []const u8,
    header_static: []const u8,
};

pub const AccountFieldPayload = struct {
    name: []const u8,
    value: []const u8,
    verified_at: ?[]const u8 = null,
};

pub const CustomEmojiPayload = struct {
    shortcode: []const u8,
    url: []const u8,
    static_url: []const u8,
    visible_in_picker: bool,
    category: ?[]const u8 = null,
};

pub const RolePayload = struct {
    id: i64,
    name: []const u8,
    color: []const u8,
    position: i64,
    permissions: i64,
    highlighted: bool,
    created_at: []const u8,
    updated_at: []const u8,
};

pub const RoleSummaryPayload = struct {
    id: i64,
    name: []const u8,
    color: []const u8,
};

pub const AccountSourcePayload = struct {
    note: []const u8,
    fields: []const AccountFieldPayload,
    privacy: []const u8,
    sensitive: bool,
    language: ?[]const u8,
    follow_requests_count: i64,
};

pub const AccountCredentialsPayload = struct {
    id: []const u8,
    username: []const u8,
    acct: []const u8,
    display_name: []const u8,
    note: []const u8,
    url: []const u8,
    locked: bool,
    bot: bool,
    group: bool,
    discoverable: bool,
    created_at: []const u8,
    last_status_at: []const u8,
    followers_count: i64,
    following_count: i64,
    statuses_count: i64,
    avatar: []const u8,
    avatar_static: []const u8,
    header: []const u8,
    header_static: []const u8,
    fields: []const AccountFieldPayload,
    emojis: []const CustomEmojiPayload,
    roles: []const RoleSummaryPayload,
    source: AccountSourcePayload,
    role: RolePayload,
};

pub const MediaAttachmentPayload = struct {
    id: []const u8,
    type: []const u8,
    url: []const u8,
    preview_url: []const u8,
    remote_url: ?[]const u8 = null,
    text_url: ?[]const u8 = null,
    meta: struct {} = .{},
    description: ?[]const u8,
    blurhash: ?[]const u8 = null,
};

pub const StatusPayload = struct {
    id: []const u8,
    uri: []const u8,
    created_at: []const u8,
    edited_at: ?[]const u8 = null,
    account: AccountPayload,
    content: []const u8,
    visibility: []const u8,
    sensitive: bool,
    spoiler_text: []const u8,
    media_attachments: []const MediaAttachmentPayload,
    application: struct {
        name: []const u8,
        website: ?[]const u8 = null,
    },
    mentions: []const struct {
        id: []const u8,
        username: []const u8,
        url: []const u8,
        acct: []const u8,
    },
    tags: []const struct {
        name: []const u8,
        url: []const u8,
    },
    emojis: []const struct {
        shortcode: []const u8,
        url: []const u8,
        static_url: []const u8,
        visible_in_picker: bool,
    },
    reblogs_count: i64,
    favourites_count: i64,
    replies_count: i64,
    url: []const u8,
};

fn statusPayloadIdInt(p: StatusPayload) i64 {
    return std.fmt.parseInt(i64, p.id, 10) catch 0;
}

pub fn statusPayloadNewerFirst(_: void, a: StatusPayload, b: StatusPayload) bool {
    return switch (std.mem.order(u8, a.created_at, b.created_at)) {
        .gt => true,
        .lt => false,
        .eq => statusPayloadIdInt(a) > statusPayloadIdInt(b),
    };
}

fn mediaAttachmentType(content_type: []const u8) []const u8 {
    if (std.mem.startsWith(u8, content_type, "image/")) return "image";
    if (std.mem.startsWith(u8, content_type, "video/")) return "video";
    if (std.mem.startsWith(u8, content_type, "audio/")) return "audio";
    return "unknown";
}

pub fn makeAccountCredentialsPayload(app_state: *app.App, allocator: std.mem.Allocator, user: users.User) AccountCredentialsPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch "0";
    const user_url = urls.userUrlAlloc(app_state, allocator, user.username) catch "";

    const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, user);
    const header_url = urls.userHeaderUrlAlloc(app_state, allocator, user);
    const note_html = util_html.textToHtmlAlloc(allocator, user.note) catch user.note;

    const last_status_at = if (user.created_at.len >= 10) user.created_at[0..10] else "1970-01-01";

    const empty_fields: []const AccountFieldPayload = &.{};
    const empty_emojis: []const CustomEmojiPayload = &.{};

    const role_payload: RolePayload = .{
        .id = 0,
        .name = "Owner",
        .color = "",
        .position = 0,
        .permissions = 0,
        .highlighted = false,
        .created_at = "1970-01-01T00:00:00.000Z",
        .updated_at = "1970-01-01T00:00:00.000Z",
    };

    const roles_payload: []const RoleSummaryPayload = &.{.{ .id = 0, .name = "Owner", .color = "" }};

    return .{
        .id = id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = user.display_name,
        .note = note_html,
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.created_at,
        .last_status_at = last_status_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
        .fields = empty_fields,
        .emojis = empty_emojis,
        .roles = roles_payload,
        .source = .{
            .note = user.note,
            .fields = empty_fields,
            .privacy = "public",
            .sensitive = false,
            .language = null,
            .follow_requests_count = 0,
        },
        .role = role_payload,
    };
}

pub fn makeMediaAttachmentPayload(app_state: *app.App, allocator: std.mem.Allocator, meta: media.MediaMeta) MediaAttachmentPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{meta.id}) catch "0";
    const base = url.baseUrlAlloc(app_state, allocator) catch "";
    const media_url = std.fmt.allocPrint(allocator, "{s}/media/{s}", .{ base, meta.public_token }) catch "";
    return .{
        .id = id_str,
        .type = mediaAttachmentType(meta.content_type),
        .url = media_url,
        .preview_url = media_url,
        .description = meta.description,
    };
}

pub fn makeRemoteAccountPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    api_id: []const u8,
    actor: remote_actors.RemoteActor,
) AccountPayload {
    const acct = std.fmt.allocPrint(allocator, "{s}@{s}", .{ actor.preferred_username, actor.domain }) catch
        actor.preferred_username;
    const avatar_url = if (actor.avatar_url) |u| u else url.defaultAvatarUrlAlloc(app_state, allocator) catch actor.id;
    const header_url = if (actor.header_url) |u| u else url.defaultHeaderUrlAlloc(app_state, allocator) catch actor.id;

    return .{
        .id = api_id,
        .username = actor.preferred_username,
        .acct = acct,
        .display_name = "",
        .note = "",
        .url = actor.id,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = "1970-01-01T00:00:00.000Z",
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };
}

pub fn makeStatusPayload(app_state: *app.App, allocator: std.mem.Allocator, user: users.User, st: statuses.Status) StatusPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{st.id}) catch "0";
    const user_id_str = std.fmt.allocPrint(allocator, "{d}", .{user.id}) catch "0";

    const html_content = util_html.textToHtmlAlloc(allocator, st.text) catch st.text;

    const user_url = urls.userUrlAlloc(app_state, allocator, user.username) catch "";
    const avatar_url = urls.userAvatarUrlAlloc(app_state, allocator, user);
    const header_url = urls.userHeaderUrlAlloc(app_state, allocator, user);
    const note_html = util_html.textToHtmlAlloc(allocator, user.note) catch user.note;

    const acct: AccountPayload = .{
        .id = user_id_str,
        .username = user.username,
        .acct = user.username,
        .display_name = user.display_name,
        .note = note_html,
        .url = user_url,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = user.created_at,
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const base = url.baseUrlAlloc(app_state, allocator) catch "";
    const uri = std.fmt.allocPrint(allocator, "{s}/api/v1/statuses/{s}", .{ base, id_str }) catch "";

    const metas: []const media.MediaMeta = media.listForStatus(&app_state.conn, allocator, st.id) catch &.{};
    const attachments = blk: {
        if (metas.len == 0) break :blk &.{};
        const out = allocator.alloc(MediaAttachmentPayload, metas.len) catch break :blk &.{};
        for (metas, 0..) |m, i| {
            out[i] = makeMediaAttachmentPayload(app_state, allocator, m);
        }
        break :blk out;
    };

    return .{
        .id = id_str,
        .uri = uri,
        .created_at = st.created_at,
        .account = acct,
        .content = html_content,
        .visibility = st.visibility,
        .sensitive = false,
        .spoiler_text = "",
        .media_attachments = attachments,
        .application = .{ .name = "feddyspice", .website = null },
        .mentions = &.{},
        .tags = &.{},
        .emojis = &.{},
        .reblogs_count = 0,
        .favourites_count = 0,
        .replies_count = 0,
        .url = uri,
    };
}

pub fn makeRemoteStatusPayload(
    app_state: *app.App,
    allocator: std.mem.Allocator,
    actor: remote_actors.RemoteActor,
    st: remote_statuses.RemoteStatus,
) StatusPayload {
    const id_str = std.fmt.allocPrint(allocator, "{d}", .{st.id}) catch "0";

    const acct_str = std.fmt.allocPrint(allocator, "{s}@{s}", .{ actor.preferred_username, actor.domain }) catch
        actor.preferred_username;

    const avatar_url = if (actor.avatar_url) |u| u else url.defaultAvatarUrlAlloc(app_state, allocator) catch actor.id;
    const header_url = if (actor.header_url) |u| u else url.defaultHeaderUrlAlloc(app_state, allocator) catch actor.id;

    const api_id = util_ids.remoteAccountApiIdAlloc(app_state, allocator, actor.id);

    const acct: AccountPayload = .{
        .id = api_id,
        .username = actor.preferred_username,
        .acct = acct_str,
        .display_name = "",
        .note = "",
        .url = actor.id,
        .locked = false,
        .bot = false,
        .group = false,
        .discoverable = true,
        .created_at = "1970-01-01T00:00:00.000Z",
        .followers_count = 0,
        .following_count = 0,
        .statuses_count = 0,
        .avatar = avatar_url,
        .avatar_static = avatar_url,
        .header = header_url,
        .header_static = header_url,
    };

    const attachments: []const MediaAttachmentPayload = blk: {
        const aj = st.attachments_json orelse break :blk &.{};

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, aj, .{}) catch break :blk &.{};
        defer parsed.deinit();

        if (parsed.value != .array) break :blk &.{};
        if (parsed.value.array.items.len == 0) break :blk &.{};

        const out = allocator.alloc(MediaAttachmentPayload, parsed.value.array.items.len) catch break :blk &.{};
        for (parsed.value.array.items, 0..) |item, i| {
            if (item != .object) {
                out[i] = .{
                    .id = "0",
                    .type = "unknown",
                    .url = "",
                    .preview_url = "",
                    .description = null,
                };
                continue;
            }

            const url_val = item.object.get("url");
            const attachment_url = if (url_val != null and url_val.? == .string) url_val.?.string else "";

            const media_type_val = item.object.get("media_type");
            const media_type = if (media_type_val != null and media_type_val.? == .string) media_type_val.?.string else null;

            const kind_val = item.object.get("kind");
            const kind = if (kind_val != null and kind_val.? == .string) kind_val.?.string else null;

            const desc_val = item.object.get("description");
            const desc = if (desc_val != null and desc_val.? == .string) desc_val.?.string else null;

            const blurhash_val = item.object.get("blurhash");
            const blurhash = if (blurhash_val != null and blurhash_val.? == .string) blurhash_val.?.string else null;

            const typ = if (media_type) |mt|
                mediaAttachmentType(mt)
            else if (kind != null and std.mem.eql(u8, kind.?, "Image"))
                "image"
            else if (kind != null and std.mem.eql(u8, kind.?, "Video"))
                "video"
            else if (kind != null and std.mem.eql(u8, kind.?, "Audio"))
                "audio"
            else
                "unknown";

            const attachment_id_str = std.fmt.allocPrint(allocator, "{d}:{d}", .{ st.id, i }) catch "0";
            out[i] = .{
                .id = attachment_id_str,
                .type = typ,
                .url = attachment_url,
                .preview_url = attachment_url,
                .remote_url = if (attachment_url.len == 0) null else attachment_url,
                .description = desc,
                .blurhash = blurhash,
            };
        }
        break :blk out;
    };

    return .{
        .id = id_str,
        .uri = st.remote_uri,
        .created_at = st.created_at,
        .account = acct,
        .content = st.content_html,
        .visibility = st.visibility,
        .sensitive = false,
        .spoiler_text = "",
        .media_attachments = attachments,
        .application = .{ .name = "feddyspice", .website = null },
        .mentions = &.{},
        .tags = &.{},
        .emojis = &.{},
        .reblogs_count = 0,
        .favourites_count = 0,
        .replies_count = 0,
        .url = st.remote_uri,
    };
}

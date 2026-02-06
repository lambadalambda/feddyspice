# Technical debt / refactoring notes

This file tracks “good future refactors” and known risks. Add items whenever you notice something that should be improved, but isn’t worth changing right now.

## Architecture / DRY

- [x] Finish splitting `src/http.zig` into a small router + feature modules (for maintainability and faster iteration).
  - [x] Shared helpers extracted to `src/util/*` (`htmlEscapeAlloc`/`textToHtmlAlloc`, URL builders, remote account API ID mapping).
  - [x] HTTP `Request`/`Response` types moved to `src/http_types.zig` to avoid import cycles while splitting handlers.
  - [x] Core handlers split into `src/http/*` (discovery/instance/pages/oauth/accounts/statuses/timelines/activitypub).
  - [x] Move remaining handlers still living in `src/http.zig` (media, notifications, conversations, follows, metrics, misc compat endpoints).
- [x] DRY federation delivery code (“sign + POST” loops) via shared helpers in `src/federation.zig`.
- [x] Store explicit recipient/mention metadata at post-create time (at least for `visibility=direct`) and base delivery on stored addressing rather than reparsing text.
- [x] DRY: centralize URL normalization helpers (`trimTrailingSlash`, `stripQueryAndFragment`) in `src/util/url.zig`.
- [x] Add `remote_actors.lookupByIdAny` and use it anywhere we currently re-implement slash/no-slash actor lookups (e.g. inbox `Create`/`Delete`).
- [x] Remove duplicated “remote status by URI variants” logic in inbox handlers by using shared helpers (extend `remote_statuses.lookupByUriAny` with `IncludingDeletedAny` if needed).
- [x] Extract shared ActivityPub JSON helpers (`jsonTruthiness`, `jsonContainsIri`, URL-first extraction) into a small module and use it in both inbox parsing and thread backfill.
- [x] DRY `localStatusIdFromIri` / local-IRI parsing (currently duplicated across inbox + backfill codepaths).
- [x] Unify remote Note ingestion into a single entrypoint used by both inbox-ingested and fetch/backfill-ingested statuses (shared parsing, visibility, attachments, reply mapping).
- [x] Unify outbound Host header generation for remote requests (use remote URI scheme for default ports; share across `src/federation.zig` + `src/thread_backfill.zig`).
- [x] DRY multipart parsing: extract shared multipart iterator used by `parseMultipart`, `parseMultipartWithFile`, `parseMultipartWithFiles` (avoid subtle behavior drift).
- [x] Inbox DRY: factor out a shared `trimTrailingSlash`/`stripQueryAndFragment` comparison helper (remove local `trimSlash` copies in `src/http/activitypub_api.zig`).
- [x] Inbox DRY: add `follows.markAcceptedByActivityIdAny` (slash/query/fragment variants) to replace manual “try trimmed / with slash” logic.
- [x] Server DRY: unify `bearerToken`/`targetPath` helpers between `src/server.zig` and `src/http/common.zig` (avoid divergent behavior).

## Performance / robustness

- [x] Avoid `std.heap.page_allocator` per request in `src/server.zig` response header building (use stack + request arena).
- [x] Outbound fetches enforce a maximum response size (`FEDDYSPICE_HTTP_MAX_BODY_BYTES`) and allow per-request overrides (`FetchOptions.max_body_bytes`).
- [x] Apply SQLite connection pragmas consistently for every connection (foreign keys, WAL where applicable) across app/job threads to reduce “half-applied” behavior under load.
- [x] Stop swallowing request-body read errors in `src/server.zig` (empty body fallback can cause confusing “half working” behavior); return a clear 4xx/5xx.
- [x] Background `.sync` job execution should log errors instead of silent `catch {}` (makes federation/backfill failures diagnosable).

## Security

- [x] Verify inbound ActivityPub inbox requests using HTTP Signatures + `Digest` (including `hs2019`, `content-type`, `content-length`, and reverse-proxy host handling).
- [x] Sanitize remote HTML: do not store/re-serve untrusted `object.content` without sanitization (XSS risk).
- [x] Header-injection hardening: validate/strip control characters (`\r`, `\n`, etc.) from any user-controlled header values (e.g. redirects, media content-types) before sending responses.
- [x] Add a baseline “security headers” set on all HTTP responses (nosniff, referrer policy, clickjacking protection; CSP for HTML).
- [x] Add OAuth hardening: `Cache-Control: no-store` for `/oauth/token` + auth-code flows; enforce same-origin on HTML form POSTs when `Origin`/`Referer` is present.
- [x] Validate inbound signature freshness: parse `Date` and enforce max clock skew (configurable).
- [x] Reject excessively nested JSON request bodies before parsing (`FEDDYSPICE_JSON_MAX_NESTING_DEPTH`).
- [x] Replay protection: dedupe signed inbox requests even when activity `id` is missing (hash fallback).
- [x] Outbound transport: reject nonstandard ports by default; re-validate on redirects if we ever enable follow-redirects.
- [x] Add rate limiting/backpressure for high-risk entrypoints (login/token/apps/inbox).
- [x] Add outbound fetch storm protections (per-domain concurrency/backoff).
- [x] Add regression tests for visibility/data leakage (direct/private never exposed via public timelines or unauthenticated endpoints).
- [x] Document/decide media exposure expectations for non-public posts (capability URLs vs auth-gated). Decision: capability URLs (`/media/:token`) with unguessable tokens; access logs redact tokens.
- [x] Remote discovery should prefer HTTPS and not depend on local `FEDDYSPICE_SCHEME` (avoid MITM + “local http can’t follow https servers” corner cases). Allow HTTP fallback only in explicitly trusted/dev configs.

## Feature gaps (Mastodon/Pleroma parity)

This is a “rough backlog” based on Mastodon’s `config/routes/api.rb` and Pleroma’s `lib/pleroma/web/router.ex`, focusing on commonly-used endpoints and payload fields.

- [x] Add app introspection: `GET /api/v1/apps/verify_credentials`.
- [x] Add v1 search aliases: `GET /api/v1/search` and `GET /api/v1/accounts/search` (can delegate to `/api/v2/search`).
- [x] Add missing discovery helpers: `GET /api/v1/trends` (alias to tags) and `GET /api/v1/suggestions` (+ `DELETE /api/v1/suggestions/:account_id`).
- [x] Add notification extras: `GET /api/v1/notifications/:id` and `GET /api/v1/notifications/unread_count`.
- [x] Add status auxiliary endpoints: `GET /api/v1/statuses/:id/reblogged_by`, `/favourited_by`, `/history`, `/source` (placeholders ok initially).
- [x] Add bulk status lookup: `GET /api/v1/statuses?ids[]=...` (Mastodon “hydrate by id list” pattern).
- [x] Add direct timeline: `GET /api/v1/timelines/direct` (DMs), and make `GET /api/v1/timelines/tag/:tag` return real results (currently stubbed empty).
- [x] Add lists/filters CRUD (or robust stubs): `GET/POST/PUT/DELETE /api/v1/lists*` and `GET/POST/PUT/DELETE /api/v1/filters*`.
- [x] Add favourites/bookmarks index endpoints: `GET /api/v1/favourites` and `GET /api/v1/bookmarks`.
- [x] Add blocks/mutes index endpoints: `GET /api/v1/blocks` and `GET /api/v1/mutes`.
- [x] Add account block/mute actions: `POST /api/v1/accounts/:id/(block|unblock|mute|unmute)` (no-op acceptable for single-user, but avoid 404).
- [x] Add reporting stub: `POST /api/v1/reports`.
- [x] Add media deletion: `DELETE /api/v1/media/:id` (and match Mastodon’s “return attachment” semantics).
- [x] Add tags endpoints: `GET /api/v1/tags/:id` and `POST /api/v1/tags/:id/(follow|unfollow)` (even if empty/422 for unknown tags).
- [x] Add missing v1 instance endpoints used by clients: `/api/v1/instance/rules`, `/api/v1/instance/domain_blocks`, `/api/v1/instance/translation_languages`.
- [x] Flesh out `/api/v1/instance` payload fields (stats/urls/languages/contact) if clients require it.
- [x] Fill out `/api/v1/preferences` with Mastodon-shaped keys (currently `{}`) for clients that assume keys exist.
- [x] Implement “interaction state” on statuses (instead of no-ops): favourites/boosts/bookmarks/pins/mutes + `Status` relationship booleans (`favourited`, `reblogged`, `bookmarked`, `pinned`, `muted`).
- [x] Federation parity: outbound `Create(Note)` includes `inReplyTo` for replies and `tag` mention objects; inbound remote `inReplyTo` stored/mapped to improve threads.
- [x] Remote visibility mapping: treat followers-only ActivityPub deliveries as `private` (not `direct`), and keep `direct` statuses out of the home timeline (Mastodon/clients expect them in `/api/v1/timelines/direct`).

## 2026-02 API/Federation audit findings

### High priority

- [x] `POST /api/v2/media` still uses the default 1 MiB body cap.
  - Evidence:
    - `src/server.zig:196` only applies `media_max_len` for `"/api/v1/media"`.
    - `src/http.zig:411` routes `"/api/v2/media"` to the same upload handler.
  - Impact:
    - Clients using `/api/v2/media` can hit unexpected `413 payload too large` for files that `/api/v1/media` accepts.
  - Suggested fix:
    - Treat both `/api/v1/media` and `/api/v2/media` as media-upload paths in request body sizing.
    - Add a regression test that posts `>1MiB` to `/api/v2/media` and expects success.

- [x] ActivityPub `Update(Note)` maps followers-only recipients to `direct` instead of `private`.
  - Evidence:
    - `src/http/activitypub_api.zig:874` computes visibility for updates.
    - `src/http/activitypub_api.zig:894` falls back to `"direct"` when `Public` is absent.
    - `src/remote_note_ingest.zig:92`..`src/remote_note_ingest.zig:103` already classifies followers collections as `"private"` for ingest/create.
  - Impact:
    - A followers-only remote edit can change stored visibility from `private` to `direct`, affecting home/direct timeline placement and notification semantics.
  - Suggested fix:
    - Reuse the same visibility classifier used by `remote_note_ingest` for both `Create` and `Update` paths.
    - Add a test for `Update(Note)` with `to=[.../followers]` to preserve `private`.

- [x] Public status lookup/context endpoints are auth-required, unlike Mastodon/Pleroma behavior.
  - Evidence:
    - `src/http/statuses_api.zig:430` and `src/http/statuses_api.zig:462` require bearer tokens up front.
    - Mastodon allows unauthenticated `show/context` with visibility checks (`../mastodon/app/controllers/api/v1/statuses_controller.rb:10`, `../mastodon/app/controllers/api/v1/statuses_controller.rb:36`, `../mastodon/app/controllers/api/v1/statuses_controller.rb:42`).
    - Pleroma similarly supports unauthenticated access for these actions (`../pleroma/lib/pleroma/web/mastodon_api/controllers/status_controller.ex:35`, `../pleroma/lib/pleroma/web/mastodon_api/controllers/status_controller.ex:40`).
  - Impact:
    - Public links and unauthenticated clients cannot fetch public statuses/threads through Mastodon API endpoints.
  - Suggested fix:
    - Make auth optional for `GET /api/v1/statuses/:id` and `/context`; enforce visibility-based access control instead of unconditional auth.

- [x] Outbound federation `Create(Note)` payloads omit media attachments.
  - Evidence:
    - `src/federation.zig:1116`..`src/federation.zig:1126` builds Note object without an `attachment` field.
  - Impact:
    - Remote followers may receive text-only posts when local statuses include media.
  - Suggested fix:
    - Include ActivityPub `attachment` objects generated from local status media metadata, with tests covering image/video attachment federation.

### Medium priority

- [x] ActivityPub outbox/object serialization is inconsistent with outbound federation payload richness.
  - Evidence:
    - `src/http/activitypub_api.zig:343` defines `ApNote` with only `id/type/attributedTo/content/published/to/cc`.
    - `src/http/activitypub_api.zig:494`..`src/http/activitypub_api.zig:503` serves `Note` without `inReplyTo`, `tag`, or `attachment`.
    - Outbound delivery already includes at least `inReplyTo` and mention `tag` (`src/federation.zig:1124`, `src/federation.zig:1125`).
  - Impact:
    - GET object/outbox views can diverge from delivered activities and lose thread/mention/media semantics for fetchers.
  - Suggested fix:
    - Share a single Note serializer for delivery + object endpoints, then add parity tests.

- [x] Rate limiting is globally keyed per endpoint, not scoped by requester.
  - Evidence:
    - `src/rate_limit.zig:17` stores one row per `key` in `rate_limits`.
    - Call sites use static keys like `"login_post"`, `"oauth_token"`, `"ap_inbox"` (`src/http/pages.zig:54`, `src/http/oauth_api.zig:217`, `src/http/activitypub_api.zig:641`).
  - Impact:
    - One abusive client can throttle all clients for a route.
  - Suggested fix:
    - Include requester dimension (IP and/or authenticated principal) in rate-limit key construction.

- [x] `GET /api/v1/statuses?ids[]=...` is auth-required, while Mastodon/Pleroma allow unauth reads with visibility filtering.
  - Evidence:
    - `src/http/statuses_api.zig:24` enforces bearer token.
    - Mastodon’s `index` is not behind `require_user!` (`../mastodon/app/controllers/api/v1/statuses_controller.rb:10`, `../mastodon/app/controllers/api/v1/statuses_controller.rb:31`).
    - Pleroma declares unauth fallback for `index` (`../pleroma/lib/pleroma/web/mastodon_api/controllers/status_controller.ex:35`, `../pleroma/lib/pleroma/web/mastodon_api/controllers/status_controller.ex:41`).
  - Impact:
    - Some clients cannot hydrate public status IDs without authentication.
  - Suggested fix:
    - Make token optional and filter by status visibility for unauthenticated callers.

### Low priority (refactor / DRY)

- [x] Timeline handlers duplicate pagination/query parsing and Link-header assembly.
  - Evidence:
    - `src/http/timelines_api.zig:80`, `src/http/timelines_api.zig:213`, `src/http/timelines_api.zig:340`, `src/http/timelines_api.zig:533` all repeat `limit/max_id/since_id/min_id` parsing.
    - Similar header construction appears at `src/http/timelines_api.zig:175`, `src/http/timelines_api.zig:302`, `src/http/timelines_api.zig:424`, `src/http/timelines_api.zig:633`.
  - Impact:
    - Higher maintenance cost and risk of behavior drift between timeline endpoints.
  - Suggested fix:
    - Introduce shared pagination parser + link-header helper.

- [x] Repeated query-array parsing logic for ID lists.
  - Evidence:
    - `src/http/statuses_api.zig:34`..`src/http/statuses_api.zig:45` parses `ids[]` manually.
    - `src/http/accounts_api.zig:809`..`src/http/accounts_api.zig:820` parses `id[]` manually.
  - Impact:
    - Duplicate parsing behavior is easy to diverge over time.
  - Suggested fix:
    - Add a shared helper for extracting repeated query values with normalized key aliases.

- [x] Instance helper endpoints are placeholders and can still semantically drift from Mastodon expectations.
  - Evidence:
    - `src/http/instance.zig:53` (`rules`) and `src/http/instance.zig:58` (`domain_blocks`) return static empty arrays.
    - `src/http/instance.zig:63` (`translation_languages`) returns static `{}`.
    - `src/http/instance.zig:34` and `src/http/instance.zig:88` advertise registrations as enabled by default.
  - Impact:
    - Real-world client UX/feature checks can misinterpret server policy/capabilities.
  - Suggested fix:
    - Back these fields with actual config/state and align payload semantics with Mastodon endpoint contracts.

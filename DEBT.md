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
- [ ] Unify outbound Host header generation for remote requests (use remote URI scheme for default ports; share across `src/federation.zig` + `src/thread_backfill.zig`).
- [ ] DRY multipart parsing: extract shared multipart iterator used by `parseMultipart`, `parseMultipartWithFile`, `parseMultipartWithFiles` (avoid subtle behavior drift).
- [ ] Inbox DRY: factor out a shared `trimTrailingSlash`/`stripQueryAndFragment` comparison helper (remove local `trimSlash` copies in `src/http/activitypub_api.zig`).
- [ ] Inbox DRY: add `follows.markAcceptedByActivityIdAny` (slash/query/fragment variants) to replace manual “try trimmed / with slash” logic.
- [ ] Server DRY: unify `bearerToken`/`targetPath` helpers between `src/server.zig` and `src/http/common.zig` (avoid divergent behavior).

## Performance / robustness

- [x] Avoid `std.heap.page_allocator` per request in `src/server.zig` response header building (use stack + request arena).
- [x] Outbound fetches enforce a maximum response size (`FEDDYSPICE_HTTP_MAX_BODY_BYTES`) and allow per-request overrides (`FetchOptions.max_body_bytes`).
- [ ] Apply SQLite connection pragmas consistently for every connection (foreign keys, WAL where applicable) across app/job threads to reduce “half-applied” behavior under load.
- [ ] Stop swallowing request-body read errors in `src/server.zig` (empty body fallback can cause confusing “half working” behavior); return a clear 4xx/5xx.
- [ ] Background `.sync` job execution should log errors instead of silent `catch {}` (makes federation/backfill failures diagnosable).

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

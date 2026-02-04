# Plan

This is a living checklist. We only mark items complete when there are tests covering them (unit/integration/E2E as appropriate).

## 0) Repo / workflow

- [x] Add `CHANGELOG.md` entries for each PR/commit group
- [x] Decide exact “API compatibility target” for pl-fe (document required endpoints)
- [x] Add a minimal Zig project skeleton (`zig build test` runs locally)
- [x] Add formatting workflow (`zig fmt`)

## 1) Single-user core (local-only)

- [x] SQLite schema + migrations (users, oauth apps/tokens, posts, remote actors)
- [x] Config system (domain, listen, db path, CA cert file)
- [x] Password hashing + session cookies (single local user)
- [x] Minimal HTML pages: signup, login, OAuth authorization prompt
- [x] `GET /healthz` and `GET /api/v1/instance` for basic operability checks

## 2) “Enough API for pl-fe” (posting + timelines)

Target: pl-fe can log in and post/read.

- [x] OAuth 2.0: app registration (`POST /api/v1/apps`)
- [x] OAuth 2.0: authorization code flow (`/oauth/authorize`, `/oauth/token`)
- [x] Accounts: verify credentials
- [x] Accounts: profile lookup (`GET /api/v1/accounts/lookup`, `GET /api/v1/accounts/:id`)
- [x] Posting: create status
- [x] Posting: delete status
- [x] Timelines: home (minimal)
- [x] Timelines: public (basic)
- [x] Timelines: pagination (Link headers; `since_id`/`min_id`/`max_id`)
- [x] Attachments (optional early): upload + include in status
- [x] Markers: basic support (`GET/POST /api/v1/markers`)

## 3) Federation basics (ActivityPub)

Target: follow and receive posts from other servers.

- [x] WebFinger (`/.well-known/webfinger`)
- [x] NodeInfo discovery (`/.well-known/nodeinfo`, `/nodeinfo/2.0`)
- [x] Actor document for the local user (`/users/:name`)
- [x] Inbox/outbox endpoints with correct ActivityStreams JSON
- [x] HTTP Signatures for outbound federation requests
- [x] Follow flow: send Follow, receive Accept, store relationship
- [x] Follow flow: receive Follow, send Accept, store follower
- [x] Create flow: send Create(Note) to followers, receive Create(Note)
- [x] Direct messages: send Create/Delete to mentioned remote actors (`visibility=direct`, `to=[actor ids]`)
- [x] Delete handling (tombstones)

## 4) Fedbox E2E tests (Docker)

Target: automated federation smoke tests against multiple real servers.

- [x] Add `docker/federation/compose.yml` with a local Caddy gateway + internal TLS
- [x] Include at least two reference servers (Pleroma + Mastodon) and seed accounts
- [x] Add a test-runner container that executes federation smoke tests
- [x] E2E: feddyspice follows a remote account; remote sends Accept; relationship becomes visible via API
- [x] E2E: remote post shows up in feddyspice timeline
- [x] E2E: feddyspice post arrives on remote timeline

## 5) Hardening (still single-user)

- [x] Background queue for deliveries + retries (SQLite-backed)
- [x] Idempotency + dedupe for inbound activities
- [x] SSRF protections + allowlist for fedbox-only private networking
- [x] Media storage + cleanup
- [x] Minimal observability (structured logs, basic metrics)

## 6) Client requests: eliminate 404s (from `feddyspice.log`)

We keep this list in-sync with reality by periodically scanning `feddyspice.log` for `status=404` and adding tasks here.

- [x] `GET /api/v1/announcements` (client compat placeholder)
- [x] `GET /api/v1/accounts/lookup?acct=:acct` (seen as `acct=alice`)
- [x] `GET /api/v1/custom_emojis` (client compat placeholder)
- [x] `GET /api/v1/follow_requests` (client compat placeholder)
- [x] `GET /api/v1/followed_tags` (client compat placeholder)
- [x] `GET /api/v1/lists` (client compat placeholder)
- [x] `GET/POST /api/v1/markers` (client compat placeholder; include `updated_at`)
- [x] `GET /api/v1/notifications` (client compat placeholder)
- [x] `GET /api/v1/preferences` (client compat placeholder)
- [x] `GET /api/v1/push/subscription` (client compat placeholder)
- [x] `GET /api/v1/conversations` (direct messages)
- [x] `POST /api/v1/conversations/:id/read` (direct messages)
- [x] `DELETE /api/v1/conversations/:id` (direct messages)
- [x] `GET /api/v1/accounts/relationships?id[]=:id` (seen as `id[]=1`)
- [x] `GET /api/v1/accounts/:id/statuses` (seen with `pinned=true`, `only_media=true`, `exclude_replies=true`)
- [x] `GET /api/v1/scheduled_statuses` (client compat placeholder)
- [x] `GET /api/v1/timelines/public` (basic)
- [x] `GET /api/v1/trends/tags` (client compat placeholder)
- [x] `GET /api/v2/filters` (client compat placeholder)
- [x] `GET /api/v2/search` (client compat placeholder)
- [x] `GET /api/v2/suggestions` (client compat placeholder)
- [x] `GET /api/v1/instance/peers` (client compat placeholder)
- [x] `GET /api/v1/instance/activity` (client compat placeholder)
- [x] `GET /api/v1/instance/extended_description` (client compat placeholder)
- [x] `GET /api/v1/directory` (client compat placeholder)
- [x] `GET /nodeinfo/2.1` (client compat alias)
- [x] `GET /robots.txt` (crawler compat)
- [x] `HEAD /` and `HEAD /users/:name` (client/crawler compat)
- [x] Trailing-slash path normalization (`/api/v1/instance/`, `/api/v2/instance/`, etc.)

## 7) Mastodon API parity (selected, from `../mastodon/config/routes/api.rb`)

This is the “eventually” list. We should keep it scoped to what pl-fe needs, but `../mastodon/config/routes/api.rb` is the canonical reference for what clients might try.

### Accounts

- [x] `GET /api/v1/accounts/:id` (profile view)
- [x] `GET /api/v1/accounts/:id/statuses` (profile timeline; filters + pagination)
- [x] `GET /api/v1/accounts/:id/followers`
- [x] `GET /api/v1/accounts/:id/following`
- [x] `POST /api/v1/accounts/:id/follow` + `POST /api/v1/accounts/:id/unfollow` (or document why we only support `POST /api/v1/follows`)
- [x] `GET /api/v1/accounts/relationships` (Relationship entity)

### Statuses

- [x] `DELETE /api/v1/statuses/:id` (delete local status)
- [x] `GET /api/v1/statuses/:id/context`
- [x] `POST /api/v1/statuses/:id/favourite` + `POST /api/v1/statuses/:id/unfavourite`
- [x] `POST /api/v1/statuses/:id/reblog` + `POST /api/v1/statuses/:id/unreblog`
- [x] `POST /api/v1/statuses/:id/bookmark` + `POST /api/v1/statuses/:id/unbookmark`

### Timelines

- [x] `GET /api/v1/timelines/tag/:tag`
- [x] `GET /api/v1/timelines/list/:id`
- [x] `GET /api/v1/timelines/link?url=...`

### Media

- [x] `POST /api/v1/media` (upload)
- [x] `PUT /api/v1/media/:id` (update metadata)
- [x] Attachments in `POST /api/v1/statuses` (IDs from media upload)

### Notifications / streaming

- [x] `GET /api/v1/notifications` (real notifications)
- [x] `POST /api/v1/notifications/clear` + `POST /api/v1/notifications/:id/dismiss`
- [x] Streaming: WebSocket `/api/v1/streaming` (`stream=user`) with `update` + `delete` + `notification` events

## 8) Security hardening (follow-ups)

These are explicitly security-focused tasks (not just “compat” work). Each item needs tests.

- [ ] Add baseline security headers for all HTTP responses (at least: `X-Content-Type-Options`, `Referrer-Policy`, clickjacking/CSP).
- [ ] OAuth: add `Cache-Control: no-store` to token/code-related responses; consider CSRF protection for HTML form POSTs (`/login`, `/signup`, `/oauth/authorize`).
- [ ] HTTP Signatures: validate `Date` header format + max clock skew (configurable).
- [ ] HTTP Signatures: replay protection when ActivityPub activity `id` is missing (fallback dedupe key).
- [ ] Transport: disallow outbound `http(s)` URLs with nonstandard ports by default (configurable).
- [ ] Rate limiting/backpressure for public entrypoints (`/login`, `/oauth/token`, `/api/v1/apps`, `/users/:name/inbox`) and outbound fetch storms.
- [ ] Add visibility regression tests: no `direct`/`private` content in unauthenticated timelines/search; define/verify media URL exposure policy.
- [ ] Tighten request parsing limits: JSON max depth/field count, attachment count caps, and consistent timeouts.

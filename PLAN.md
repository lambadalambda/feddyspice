# Plan

This is a living checklist. We only mark items complete when there are tests covering them (unit/integration/E2E as appropriate).

## 0) Repo / workflow

- [ ] Add `CHANGELOG.md` entries for each PR/commit group
- [ ] Decide exact “API compatibility target” for pl-fe (document required endpoints)
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
- [ ] Accounts: profile lookup
- [x] Posting: create status
- [ ] Posting: delete status
- [x] Timelines: home (minimal)
- [ ] Timelines: public, pagination
- [ ] Attachments (optional early): upload + include in status

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
- [ ] Delete handling (tombstones)

## 4) Fedbox E2E tests (Docker)

Target: automated federation smoke tests against multiple real servers.

- [x] Add `docker/federation/compose.yml` with a local Caddy gateway + internal TLS
- [x] Include at least two reference servers (Pleroma + Mastodon) and seed accounts
- [x] Add a test-runner container that executes federation smoke tests
- [x] E2E: feddyspice follows a remote account; remote sends Accept; relationship becomes visible via API
- [x] E2E: remote post shows up in feddyspice timeline
- [x] E2E: feddyspice post arrives on remote timeline

## 5) Hardening (still single-user)

- [ ] Background queue for deliveries + retries (SQLite-backed)
- [ ] Idempotency + dedupe for inbound activities
- [ ] SSRF protections + allowlist for fedbox-only private networking
- [ ] Media storage + cleanup
- [ ] Minimal observability (structured logs, basic metrics)

# Plan

This is a living checklist. We only mark items complete when there are tests covering them (unit/integration/E2E as appropriate).

## 0) Repo / workflow

- [ ] Add `CHANGELOG.md` entries for each PR/commit group
- [ ] Decide exact “API compatibility target” for pl-fe (document required endpoints)
- [ ] Add a minimal Zig project skeleton (`zig build test` runs in CI)
- [ ] Add formatting/lint workflow (`zig fmt`, basic static checks)

## 1) Single-user core (local-only)

- [ ] SQLite schema + migrations (users, oauth apps/tokens, posts, deliveries, remote actors)
- [ ] Config system (domain, ports, data dirs, secrets)
- [ ] Password hashing + session cookies (single local user)
- [ ] Minimal HTML pages: signup, login, OAuth authorization prompt
- [ ] `GET /healthz` and `GET /api/v1/instance` for basic operability checks

## 2) “Enough API for pl-fe” (posting + timelines)

Target: pl-fe can log in and post/read.

- [ ] OAuth 2.0: app registration (`POST /api/v1/apps`)
- [ ] OAuth 2.0: authorization code flow (`/oauth/authorize`, `/oauth/token`)
- [ ] Accounts: verify credentials, profile lookup
- [ ] Posting: create status, delete status
- [ ] Timelines: home/public (initially minimal), pagination
- [ ] Attachments (optional early): upload + include in status

## 3) Federation basics (ActivityPub)

Target: follow and receive posts from other servers.

- [ ] WebFinger (`/.well-known/webfinger`)
- [ ] NodeInfo discovery (`/.well-known/nodeinfo`, `/nodeinfo/2.0`)
- [ ] Actor document for the local user (`/users/:name`)
- [ ] Inbox/outbox endpoints with correct ActivityStreams JSON
- [ ] HTTP Signatures for outbound federation requests
- [ ] Follow flow: send Follow, receive Accept, store relationship
- [ ] Create flow: send Create(Note) to followers, receive Create(Note)
- [ ] Delete handling (tombstones)

## 4) Fedbox E2E tests (Docker)

Target: automated federation smoke tests against multiple real servers.

- [ ] Add `docker/federation/compose.yml` with a local Caddy gateway + internal TLS
- [ ] Include at least two reference servers (e.g. Pleroma + Mastodon) and seed accounts
- [ ] Add a test-runner container that executes federation smoke tests
- [ ] E2E: feddyspice follows a remote account; remote sends Accept; relationship becomes visible via API
- [ ] E2E: remote post shows up in feddyspice timeline
- [ ] E2E: feddyspice post arrives on remote timeline

## 5) Hardening (still single-user)

- [ ] Background queue for deliveries + retries (SQLite-backed)
- [ ] Idempotency + dedupe for inbound activities
- [ ] SSRF protections + allowlist for fedbox-only private networking
- [ ] Media storage + cleanup
- [ ] Minimal observability (structured logs, basic metrics)


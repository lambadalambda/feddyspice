# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial repository scaffolding (docs + planning).
- Fedbox scaffold for federation smoke tests.
- Zig project skeleton and minimal HTTP server with `/healthz`.
- SQLite DB wrapper and migrations (including initial `users` table).
- Password hashing (Argon2id) and single-user creation/login helpers.
- App wiring and basic Mastodon-compatible instance endpoint (`/api/v1/instance`).
- Minimal HTML signup/login and session cookies.
- OAuth 2.0 app registration and authorization-code flow (`/api/v1/apps`, `/oauth/authorize`, `/oauth/token`).
- Bearer-token auth for `/api/v1/accounts/verify_credentials`.
- Status posting and timelines (SQLite `statuses` table; `POST /api/v1/statuses`, `GET /api/v1/timelines/home`, `GET /api/v1/statuses/:id`).
- Public timeline endpoint (`GET /api/v1/timelines/public`).
- Mastodon v2 instance endpoint (`GET /api/v2/instance`) for client compatibility.
- Initial ActivityPub discovery endpoints: WebFinger, NodeInfo, and actor document (`/.well-known/webfinger`, `/.well-known/nodeinfo`, `/nodeinfo/2.0`, `/users/:name`).
- Host-meta discovery endpoint (`/.well-known/host-meta`) advertising WebFinger LRDD template.
- Per-actor RSA keypairs (stored in SQLite) and `publicKeyPem` in the ActivityPub actor document.
- HTTP Signatures helper for signing outbound ActivityPub requests (`Digest`, `Date`, `Signature`).
- Remote actor discovery storage + follow tracking tables, plus inbox handling for `Accept` to mark follows as accepted.
- Outbound federation follow (WebFinger → actor → signed Follow to inbox), plus `POST /api/v1/follows` for clients and `FEDDYSPICE_CACERTFILE` for custom TLS CAs (fedbox).
- Inbox handling for ActivityPub `Create` to store remote posts in SQLite (`remote_statuses` table).
- Home timeline + status lookup can return remote posts (negative `id`s in `GET /api/v1/timelines/home` and `GET /api/v1/statuses/:id`).
- Followers table + helpers for tracking inbound follows (remote accounts following this user).
- Inbox handling for ActivityPub `Follow`: store inbound follower + send signed `Accept`; expose `GET /users/:name/followers` and `GET /users/:name/following` collections.
- ActivityPub outbox + object endpoints (`GET /users/:name/outbox`, `GET /users/:name/statuses/:id`).
- Local posts are federated to accepted followers via signed ActivityPub `Create(Note)` deliveries.
- Outbound federation work is offloaded to background jobs to avoid blocking request handling.
- Docker image for feddyspice + fedbox compose integration (`docker/federation/compose.yml`).
- Fedbox E2E tests cover feddyspice federation (follow + post delivery).
- Fedbox E2E test covers inbound `direct` messages and ensures they never leak into the public timeline.
- Basic access logging plus optional file logs (`FEDDYSPICE_LOG_FILE`, `FEDDYSPICE_LOG_LEVEL`).
- `mise` loads local env from `.env` (gitignored) and provides `.env.example`.
- Additional Mastodon API placeholder endpoints used by Elk/pl-fe (notifications, markers, preferences, search, etc.).
- Account lookup + profile endpoint (`GET /api/v1/accounts/lookup`, `GET /api/v1/accounts/:id`).
- Accounts relationships endpoint (`GET /api/v1/accounts/relationships`).
- Account statuses endpoint (`GET /api/v1/accounts/:id/statuses`).
- Soft-delete support for local + remote statuses (`deleted_at`).
- Delete local status endpoint (`DELETE /api/v1/statuses/:id`).
- Deleted local ActivityPub objects return Tombstones (`GET /users/:name/statuses/:id`).
- ActivityPub `Delete` deliveries to followers when local statuses are deleted.
- ActivityPub inbox handling for `Delete` to mark remote statuses deleted.
- Timeline pagination (`max_id`, `since_id`, `min_id`) with `Link` headers on home/public timelines.
- `GET /api/v2/search` resolves acct handles via WebFinger (enables finding remote accounts in pl-fe/Elk).
- `POST /api/v1/accounts/:id/follow` and `POST /api/v1/accounts/:id/unfollow` for client follow UX.
- Stable, path-safe numeric IDs for remote accounts (SQLite `rowid`-based offset).
- `zig build test -Dtest-filter="..."` support for faster test iteration.

### Fixed

- `Dockerfile` Zig download works on both amd64/arm64 Docker builders.
- Mastodon-ish API endpoints accept client JSON + multipart form-data bodies (pl-fe/Elk compatibility) and send permissive CORS headers.
- Fedbox Docker network creation is more reliable via a configurable subnet (`FEDBOX_SUBNET`).
- Fedbox smoke tests handle API differences between servers (follow fallback + HTML content entity decoding).
- `/oauth/token` returns OAuth-style JSON errors and logs why auth-code exchange failed (helps debug pl-fe issues).
- OAuth redirect parameters and hidden form fields are more robust via percent-encoding + HTML escaping.
- Account payloads include valid `url`/`avatar_static`/`header`/`header_static` values for pl-fe validation, with placeholder image endpoints.
- `GET /api/v2/instance` includes `configuration.urls` and `configuration.polls` to avoid Elk client crashes.
- `GET /api/v1/markers` includes required `updated_at`, and status payloads include `sensitive` (pl-fe validation).
- SQLite statements bind text/blob as `SQLITE_TRANSIENT` to avoid pointer lifetime issues.
- Inbound ActivityPub `Create` no longer silently ignores unknown actors (fetches the actor doc on first contact).
- Inbound ActivityPub `Create` infers `direct` vs `public` visibility based on recipients.
- `POST /api/v1/follows` is idempotent when the follow already exists.
- Actor key generation tolerates concurrent requests (avoids transient failures when multiple requests race to create keys).

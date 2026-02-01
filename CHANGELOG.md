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
- Mastodon v2 instance endpoint (`GET /api/v2/instance`) for client compatibility.
- Initial ActivityPub discovery endpoints: WebFinger, NodeInfo, and actor document (`/.well-known/webfinger`, `/.well-known/nodeinfo`, `/nodeinfo/2.0`, `/users/:name`).
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
- Basic access logging plus optional file logs (`FEDDYSPICE_LOG_FILE`, `FEDDYSPICE_LOG_LEVEL`).

### Fixed

- `Dockerfile` Zig download works on both amd64/arm64 Docker builders.
- Mastodon-ish API endpoints accept client JSON + multipart form-data bodies (pl-fe/Elk compatibility) and send permissive CORS headers.
- Fedbox Docker network creation is more reliable via a configurable subnet (`FEDBOX_SUBNET`).
- Fedbox smoke tests handle API differences between servers (follow fallback + HTML content entity decoding).
- `/oauth/token` returns OAuth-style JSON errors and logs why auth-code exchange failed (helps debug pl-fe issues).
- OAuth redirect parameters and hidden form fields are more robust via percent-encoding + HTML escaping.

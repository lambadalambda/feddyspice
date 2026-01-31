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
- Docker image for feddyspice + fedbox compose integration (`docker/federation/compose.yml`).

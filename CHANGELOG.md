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

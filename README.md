# feddyspice

Minimal **single-user** Fediverse server written in **Zig**, using **SQLite**, with **no built-in frontend** (beyond the minimum needed for OAuth signup/login). The primary UI is intended to be **pl-fe**: https://github.com/mkljczk/pl-fe

## Project goals

- Single-user first (one local account; simplest thing that can federate).
- SQLite-backed, small/efficient, minimal moving parts.
- ActivityPub federation + enough Mastodon-compatible API surface for pl-fe.
- Development by TDD (unit + integration + federation-in-a-box E2E).

Non-goals (at least initially):

- Multi-user hosting, moderation tooling, advanced admin UI.
- Full Mastodon API compatibility.

## Development

Tooling is managed via `mise`:

```bash
mise install
```

Common workflows:

- `zig build test`
- `zig build run`
- `zig fmt .`

## Running locally

```bash
FEDDYSPICE_DOMAIN=localhost \
FEDDYSPICE_SCHEME=http \
FEDDYSPICE_LISTEN=0.0.0.0:8080 \
FEDDYSPICE_DB_PATH=./feddyspice.sqlite3 \
zig build run
```

## Federation-in-a-box (E2E)

This repo includes a Docker Compose “fedbox” that runs:

- `feddyspice` (this project)
- two reference servers (Pleroma + Mastodon)
- a small test runner that verifies real federation flows

See `docker/federation/README.md`.

## Using pl-fe

The intent is to support logging in from pl-fe via OAuth and then using pl-fe as the main client.

In practice, this means implementing a minimal set of:

- OAuth 2.0 endpoints (`/oauth/authorize`, `/oauth/token`, app registration)
- Mastodon-ish REST endpoints pl-fe expects (accounts, timelines, posting)

## Status

Pre-alpha. See `PLAN.md` for the checklist of milestones.

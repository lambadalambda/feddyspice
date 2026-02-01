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

## Logging

By default, logs go to stderr. To also write logs to a file:

```bash
export FEDDYSPICE_LOG_FILE=./feddyspice.log
export FEDDYSPICE_LOG_LEVEL=info # debug|info|warn|error
```

## Running behind ngrok (practical)

If you're exposing a local instance to the internet via ngrok, make sure the **external** domain is what feddyspice uses when generating ActivityPub URLs.

Example (ngrok terminates TLS and forwards to local HTTP):

```bash
# Replace with your ngrok hostname, e.g. "abc123.ngrok-free.app"
export FEDDYSPICE_DOMAIN="YOUR_NGROK_HOSTNAME"
export FEDDYSPICE_SCHEME=https
export FEDDYSPICE_LISTEN=127.0.0.1:8080
export FEDDYSPICE_DB_PATH=./feddyspice.sqlite3

zig build run
```

Then in another terminal:

```bash
ngrok http 8080
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

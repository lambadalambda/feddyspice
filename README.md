# feddyspice

Minimal **single-user** Fediverse server written in **Zig**, using **SQLite**, with **no built-in frontend** (beyond the minimum needed for signup/login + OAuth). The primary UI is intended to be **pl-fe**: https://github.com/mkljczk/pl-fe

## Project goals

- Single-user first (one local account; simplest thing that can federate).
- SQLite-backed, small/efficient, minimal moving parts.
- ActivityPub federation + enough Mastodon-compatible API surface for pl-fe (and a bit of Elk).
- Development by TDD (unit + integration + federation-in-a-box E2E).

Non-goals (at least initially):

- Multi-user hosting, moderation tooling, advanced admin UI.
- Full Mastodon API compatibility.

## What works (today)

- Single local user via `GET/POST /signup`, `GET/POST /login`.
- OAuth 2.0 authorization-code flow for clients (`/api/v1/apps`, `/oauth/authorize`, `/oauth/token`).
- Posting + timelines (home/public + pagination) with Mastodon-ish JSON shapes.
- Media uploads (`POST /api/v1/media`) and attaching uploads to statuses.
- WebSocket streaming (`GET /api/v1/streaming?stream=user&access_token=...`) with `update`/`delete`/`notification` events.
- ActivityPub federation: WebFinger/NodeInfo/actor, inbox/outbox, follow/accept, Create/Delete, direct messages, unfollow (`Undo(Follow)`), and basic interactions (Like/Announce + Undo).

## Development

Tooling is managed via `mise`:

```bash
mise install
```

Copy `.env.example` to `.env` (gitignored) and adjust as needed.

Common workflows:

- `mise run zig:test`
- `mise run zig:fmt`
- `mise run fed:test` (E2E federation smoke tests)

## Running locally

```bash
FEDDYSPICE_DOMAIN=localhost \
FEDDYSPICE_SCHEME=http \
FEDDYSPICE_LISTEN=0.0.0.0:8080 \
FEDDYSPICE_DB_PATH=./feddyspice.sqlite3 \
zig build run
```

First-time setup:

- Open `http://localhost:8080/signup` to create the single local user.
- Then use pl-fe (or visit `/login` for the HTML flow used during OAuth authorization).

## Configuration (env vars)

`mise` loads `.env` automatically for tasks. For production or `zig build run`, export variables explicitly.

Key settings:

- `FEDDYSPICE_DOMAIN` / `FEDDYSPICE_SCHEME`: public-facing base used to generate ActivityPub URLs.
- `FEDDYSPICE_LISTEN`: bind address (default `0.0.0.0:8080`).
- `FEDDYSPICE_DB_PATH`: SQLite path (default `feddyspice.sqlite3`).
- `FEDDYSPICE_JOBS_MODE`: `spawn` (default) | `sync` | `disabled`.
- `FEDDYSPICE_LOG_FILE`, `FEDDYSPICE_LOG_LEVEL`: optional file logging.

Federation/dev-only knobs (security-sensitive):

- `FEDDYSPICE_ALLOW_PRIVATE_NETWORKS`: allow outbound fetches to RFC1918/loopback/etc (needed for fedbox).
- `FEDDYSPICE_HTTP_ALLOW_NONSTANDARD_PORTS`: allow explicit `:port` URLs (fedbox enables this for helper services).

See `.env.example` for the current full list and defaults.

## Logging

By default, logs go to stderr. To also write logs to a file:

```bash
export FEDDYSPICE_LOG_FILE=./feddyspice.log
export FEDDYSPICE_LOG_LEVEL=info # debug|info|warn|error
```

## Metrics

Prometheus-style metrics are exposed at `GET /metrics`.

## Background jobs

Outbound federation deliveries can be controlled via `FEDDYSPICE_JOBS_MODE`:

- `spawn` (default): enqueue deliveries into SQLite and run them via a background worker thread (with retries)
- `sync`: run deliveries inline (useful for debugging)
- `disabled`: queue jobs but do not execute automatically (useful for tests)

## Outbound HTTP timeouts

Outbound HTTP requests use a socket-level timeout controlled by `FEDDYSPICE_HTTP_TIMEOUT_MS` (default: `10000`).

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

## Deployment

- Standalone Docker Compose (Caddy TLS reverse proxy): `docker/standalone/README.md`
- Coolify: `docs/deploy/coolify.md`

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

## Docs

- Architecture: `docs/architecture.md`
- Milestones and endpoint checklist: `PLAN.md`
- Refactoring/security notes: `DEBT.md`

## API compatibility target

Compatibility is intentionally scoped to:

- Primary client: **pl-fe**
- Secondary client: **Elk** (optional; kept working when practical)

The reference surface is the **Mastodon API** (v1/v2) only for the subset those clients actually use, plus enough **ActivityPub** to federate.

For the living list of endpoints and milestones, see `PLAN.md` (especially sections 2, 6, and 7).

## Status

Pre-alpha. See `PLAN.md` for the checklist of milestones.

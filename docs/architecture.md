# Architecture

feddyspice is a minimal **single-user** Fediverse server in **Zig**. It aims to be “just enough Mastodon API + ActivityPub to federate” while keeping the codebase small, testable, and SQLite-backed.

## Goals and non-goals

Goals:

- Single local account, fast iteration.
- SQLite for all persistent state (including background jobs).
- TDD-first: most behavior is exercised by Zig unit/integration tests; federation is validated in Docker via fedbox.

Non-goals:

- Multi-user hosting.
- Full Mastodon API parity.
- A bundled social UI (pl-fe is the intended client).

## High-level layout

- `src/main.zig`: entrypoint; loads config, initializes `App`, optionally starts the job worker thread, runs the HTTP server.
- `src/app.zig`: the “service container” holding shared state (`Config`, SQLite connection, logger, transport, streaming hub, job mode).
- `src/server.zig`: HTTP server loop, request parsing, body size limits, WebSocket upgrade for streaming, response writing, access logging.
- `src/http.zig`: router for endpoints; delegates to feature modules under `src/http/`.
- `src/db.zig` + `src/migrations.zig`: SQLite wrapper and schema migrations.
- `src/background.zig` + `src/jobs*.zig` + `src/job_worker.zig`: background delivery queue and worker.
- `src/federation.zig`: ActivityPub activity/object construction + delivery.
- `docker/federation/`: fedbox E2E environment (Caddy TLS + Pleroma + Mastodon + helper sender + test runner).

## Process model

In production, feddyspice typically runs as a **single process** with:

- an HTTP server loop (accept → parse → route → respond)
- optionally, a background worker thread (`FEDDYSPICE_JOBS_MODE=spawn`) that polls SQLite and executes queued federation deliveries

The HTTP server and job worker **share the same SQLite file**, but use separate connections.

## Request/response lifecycle

1. `src/server.zig` accepts a TCP connection and parses an HTTP request head via Zig stdlib.
2. Headers are collected into a small set of typed fields (`Host`, `Origin`, `Referer`, `Date`, `Digest`, `Signature`, `Cookie`, `Authorization`, etc.).
3. The request body is read into an arena allocator with a route-specific size cap (larger for `/api/v1/media`).
4. Requests are routed via `src/http.zig` into a handler in `src/http/*`.
5. A `http_types.Response` is serialized back to the client, including baseline security headers and permissive CORS for API clients.

WebSocket streaming is handled as an “early exit”:

- `src/server.zig` recognizes a WebSocket upgrade under `/api/v1/streaming`, verifies the OAuth token, performs the handshake, then attaches the connection to the streaming hub.

## Storage layer (SQLite)

SQLite is the only database. Schema is created/updated via ordered migrations in `src/migrations.zig` and applied on startup (`App.initFromConfig`) and in most tests (`App.initMemory`).

Notable tables (non-exhaustive):

- `users`, `sessions`: single-user account + HTML session cookies.
- `oauth_apps`, `oauth_auth_codes`, `oauth_access_tokens`: OAuth 2.0 authorization code flow for clients like pl-fe.
- `statuses`: local posts (`visibility` + text + timestamps).
- `status_recipients`: stored addressing for each local status (used for delivery and visibility enforcement).
- `remote_actors`: cached ActivityPub actor documents (id, inbox/sharedInbox, profile fields).
- `follows`: outbound follows initiated by the local user (and their “accepted” state).
- `followers`: inbound followers (remote actors who follow the local user).
- `remote_statuses`: remote posts ingested from federation; exposed via the Mastodon-ish API using negative IDs.
- `media`: uploaded media + capability URL tokens (`/media/:token`).
- `notifications`, `conversations`: minimal support for DMs/notifications expected by clients.
- `jobs`: background queue for federation work.
- `inbox_dedupe`: replay/idempotency tracking for inbound federation.
- `rate_limits`: simple SQLite-backed rate limiting for high-risk endpoints.

### Remote IDs in the Mastodon-ish API

Mastodon’s API uses numeric IDs. feddyspice maps remote statuses into that space by exposing them as **negative** integer IDs in API responses while preserving their canonical `remote_uri` internally (`remote_statuses`).

## HTTP routing and feature modules

`src/http.zig` does minimal routing and then calls into feature modules:

- `src/http/pages.zig`: HTML-only pages (`/signup`, `/login`) used to bootstrap OAuth flows.
- `src/http/oauth_api.zig`: `/api/v1/apps`, `/oauth/authorize`, `/oauth/token`.
- `src/http/accounts_api.zig`, `src/http/statuses_api.zig`, `src/http/timelines_api.zig`: Mastodon-ish REST surface for pl-fe/Elk.
- `src/http/activitypub_api.zig`: ActivityPub actor, inbox, outbox, and object endpoints.
- `src/http/media_api.zig`, `src/http/notifications_api.zig`, `src/http/conversations_api.zig`: features needed by clients.
- `src/http/discovery.zig`, `src/http/instance.zig`: WebFinger/NodeInfo/instance docs.

## Federation (ActivityPub)

Federation is centered around:

- correct ActivityStreams JSON and endpoint discovery (`WebFinger` → actor doc → inbox)
- HTTP Signatures + `Digest` verification for inbound inbox deliveries
- outbound signed requests with backpressure + SSRF protections
- **addressing-based fanout** (delivery depends on `to`/`cc` and stored recipients, not on “activity type”)

### Addressing and visibility

The server enforces four visibility modes:

- `public`: federated broadly; `Public` appears in `to`.
- `unlisted`: federated broadly but not “publicly listed”; `Public` appears in `cc`.
- `private`: federated only to accepted followers.
- `direct`: federated only to explicit recipients (and never appears in public endpoints).

When a local status is created, feddyspice stores explicit recipient metadata (`status_recipients`) so delivery and later fanout does not depend on reparsing the post text.

### Outbound federation

Outbound federation work is generally performed by background jobs:

- `Follow` / `Undo(Follow)` for follow/unfollow.
- `Create(Note)` / `Delete` for local statuses.
- `Like` / `Undo(Like)` and `Announce` / `Undo(Announce)` for interactions on remote statuses.

Delivery targets are chosen from:

- accepted followers (when appropriate for the visibility)
- stored recipients (mentions / explicit recipients)
- the remote author inbox for interactions (and, when needed, additional recipients for Announce)

### Inbound federation

Inbound deliveries arrive at `/users/:name/inbox` and are processed roughly as:

1. Validate request size and JSON complexity.
2. Verify HTTP signature, `Digest`, and `Date` freshness.
3. Apply inbox dedupe (idempotency) before mutating state.
4. Handle a small set of activity types (`Follow`, `Accept`, `Undo(Follow)`, `Create`, `Delete`), ignoring unknowns.

Remote Note HTML is sanitized on ingest before being stored/re-served.

## Outbound HTTP (transport) and SSRF protections

All outbound network calls go through the `Transport` interface (`src/transport.zig`):

- `RealTransport`: uses `std.http.Client`, enforces timeouts, response size limits, and DNS-based SSRF protections.
- `NullTransport`: used when the network must be disabled.
- `MockTransport`: used by tests to run federation logic without spinning up servers.

SSRF protection is controlled by config:

- `FEDDYSPICE_ALLOW_PRIVATE_NETWORKS` (default `false`): blocks private/loopback/link-local/multicast address ranges unless enabled (fedbox enables it).
- `FEDDYSPICE_HTTP_ALLOW_NONSTANDARD_PORTS` (default `false`): rejects URLs with explicit non-80/443 ports unless enabled (fedbox enables it for helper services).

## Background jobs and retries

The background queue is SQLite-backed:

- `src/jobs.zig`: job types + payload structs.
- `src/jobs_db.zig`: enqueue/claim/finish logic, with optional dedupe keys.
- `src/background.zig`: job dispatcher (mostly federation send + delivery fanout).
- `src/job_worker.zig`: polling worker thread.

`FEDDYSPICE_JOBS_MODE` controls behavior:

- `spawn`: enqueue jobs into SQLite; worker thread executes with retries.
- `sync`: execute inline (useful for debugging).
- `disabled`: enqueue but do not automatically run (useful in tests).

## Streaming (WebSockets)

Streaming is implemented as a small in-process pub/sub hub:

- `src/streaming_hub.zig`: subscriptions per user and stream (e.g. `user`, `public`).
- `src/server.zig` + `src/websocket.zig`: WebSocket upgrade + framing + send loop.

Handlers publish Mastodon-ish events (`update`, `delete`, `notification`) to keep clients like pl-fe responsive.

## Testing strategy

- **Unit/integration tests**: Zig `test` blocks run against an in-memory SQLite DB and frequently use `MockTransport` instead of real networking.
- **E2E federation**: fedbox uses Docker Compose (`docker/federation/compose.yml`) to run real servers (Pleroma + Mastodon) behind an internal-TLS gateway, then runs Python smoke tests (`docker/federation/test_runner/`).

Common commands:

- `mise run zig:test`
- `mise run fed:test`


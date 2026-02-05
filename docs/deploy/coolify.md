# Deploying on Coolify

Coolify can deploy feddyspice directly from this repo’s `Dockerfile` and put it behind Coolify’s built-in reverse proxy (TLS, domains, WebSockets).

## Create the application

1. In Coolify, create a new application from this Git repo.
2. Choose **Dockerfile** as the build method.
3. Set the **internal port** to `8080`.
4. Attach your public domain in Coolify (this is the hostname other servers will federate with).

## Persistent storage (required)

feddyspice stores all state (including media uploads) in SQLite. Mount a persistent volume to:

- Mount path: `/data`

The database file will be `/data/feddyspice.sqlite3`.

## Environment variables

Set these env vars in Coolify:

- `FEDDYSPICE_DOMAIN`: your public hostname (e.g. `social.example.com`)
- `FEDDYSPICE_SCHEME`: `https`
- `FEDDYSPICE_LISTEN`: `0.0.0.0:8080`
- `FEDDYSPICE_DB_PATH`: `/data/feddyspice.sqlite3`
- `FEDDYSPICE_JOBS_MODE`: `spawn`
- `FEDDYSPICE_LOG_LEVEL`: `info`

Optional:

- `FEDDYSPICE_LOG_FILE`: `/data/feddyspice.log` (otherwise use Coolify’s container logs)

Leave security-sensitive dev knobs disabled in production:

- `FEDDYSPICE_ALLOW_PRIVATE_NETWORKS=false`
- `FEDDYSPICE_HTTP_ALLOW_NONSTANDARD_PORTS=false`

## Health check (recommended)

Configure the container health check to use:

- Path: `/healthz`

## First-time setup

After the first deploy:

1. Visit `https://$FEDDYSPICE_DOMAIN/signup` once to create the single local user.
2. Log in via OAuth from pl-fe / Elk using `https://$FEDDYSPICE_DOMAIN` as the instance URL.

## Common pitfalls

- If `FEDDYSPICE_DOMAIN` doesn’t match the actual public hostname, federation will break (bad actor IDs, inbox URLs, signatures).
- If you change domains later, you must update `FEDDYSPICE_DOMAIN` and expect remote instances to treat it as a different actor.
- If `POST /signup` or `POST /login` returns `403 forbidden`, ensure your browser accepts cookies from your instance (signup/login use a CSRF cookie) and double-check `FEDDYSPICE_DOMAIN`/`FEDDYSPICE_SCHEME` match the public URL.
- Confirm the app sees the expected domain by checking `GET /api/v2/instance` (`domain` field). If it shows `localhost`, your env vars aren’t being applied to the running container.

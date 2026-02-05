# Standalone Docker Compose deployment

This folder contains a minimal Docker Compose setup for running feddyspice as a single service behind **Caddy** (TLS + reverse proxy).

## Quick start

From the repo root:

```bash
cp docker/standalone/.env.example docker/standalone/.env
docker compose --env-file docker/standalone/.env -f docker/standalone/compose.yml up -d --build
```

Then:

- Open `https://$FEDDYSPICE_DOMAIN/signup` once to create the single local user.
- Point pl-fe / Elk at `https://$FEDDYSPICE_DOMAIN`.

## Data / backups

All state lives in a single SQLite database under the `feddyspice_data` volume (`/data/feddyspice.sqlite3` inside the container).

Backup example:

```bash
docker run --rm -v feddyspice_data:/data -v "$PWD:/backup" alpine:3.20 \
  sh -c 'cp /data/feddyspice.sqlite3 /backup/feddyspice.sqlite3.bak'
```

## Upgrades

```bash
docker compose --env-file docker/standalone/.env -f docker/standalone/compose.yml up -d --build
```

## Using another reverse proxy

If you already have Traefik/nginx/etc, you can run only the `feddyspice` container and terminate TLS elsewhere.

Important:

- `FEDDYSPICE_DOMAIN` must match the public hostname.
- `FEDDYSPICE_SCHEME` should be `https` if TLS is terminated in front of feddyspice.


# Standalone Docker Compose deployment

This folder contains a minimal Docker Compose setup for running feddyspice as a single service behind **Caddy** (TLS + reverse proxy).

## Trust model (important)

This deployment expects **Caddy to be the only public entrypoint**.

- Do not expose the `feddyspice` container port directly to the internet.
- Keep TLS termination and inbound header handling at the reverse proxy layer.
- Forwarded headers used by the app (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`) must come from the trusted proxy path.

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
- Configure your proxy to sanitize/overwrite forwarded headers so clients cannot spoof requester identity.

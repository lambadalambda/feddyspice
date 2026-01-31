# Federation-in-a-box (fedbox)

Repo-local Docker Compose setup that runs **Pleroma + Mastodon** in a private container network behind an internal **Caddy** gateway (HTTP + internal TLS), and executes a small federation smoke test.

This environment is intentionally **not production-like**. It exists to make E2E federation tests repeatable.

## Usage

From the repo root:

```bash
docker compose -f docker/federation/compose.yml up -d --build
docker compose -f docker/federation/compose.yml --profile fedtest run --rm fedtest
```

Cleanup:

```bash
docker compose -f docker/federation/compose.yml down -v --remove-orphans
```

## Notes

- The test runner lives in `docker/federation/test_runner/` (Python + pytest).
- Pleroma is built from `${PLEROMA_CONTEXT}` (defaults to `../../../pleroma`).
- Mastodon uses `${MASTODON_IMAGE}` (defaults to `ghcr.io/mastodon/mastodon:v4.5.3`).
- A placeholder `feddyspice_web` service exists under the `feddyspice` profile for later integration:
  - `docker compose -f docker/federation/compose.yml --profile feddyspice up -d`


# Federation-in-a-box (fedbox)

Repo-local Docker Compose setup that runs **Pleroma + Mastodon** in a private container network behind an internal **Caddy** gateway (HTTP + internal TLS), and executes a small federation smoke test.

This environment is intentionally **not production-like**. It exists to make E2E federation tests repeatable.

## Usage

From the repo root:

```bash
docker compose -f docker/federation/compose.yml --profile fedtest up -d --build
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
- `feddyspice_web` is included under the `fedtest` profile and served via the `gateway` Caddy container at `https://feddyspice.test`.
- The fedbox tests cover both deterministic ActivityPub deliveries (via `dm_sender`) and full Pleroma/Mastodon federation flows (follow, post, direct messages, edits, deletes, interactions).
- If Docker fails to create the `federation` network due to exhausted address pools, set `FEDBOX_SUBNET` (e.g. `FEDBOX_SUBNET=10.88.0.0/16`) and retry.

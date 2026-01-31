# Agent instructions

This repo is intended to become a minimal single-user Fediverse server in Zig.

## Project rules

- Default to **TDD**: write a failing test first, then implement, then refactor.
- Keep the project **small**: prefer Zig stdlib, avoid large frameworks, avoid unnecessary dependencies.
- Database is **SQLite**. Schema changes must include migrations and tests.
- Keep `CHANGELOG.md` updated (add entries under “Unreleased” as part of each change).
- Changes should be small and topical (easy to review and revert).
- Format Zig code with `zig fmt`.

## Repo conventions (proposed)

- Zig code lives in `src/`
- Unit/integration tests live next to code or under `src/` via `test` blocks
- Docker E2E lives in `docker/federation/`

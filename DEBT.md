# Technical debt / refactoring notes

This file tracks “good future refactors” and known risks. Add items whenever you notice something that should be improved, but isn’t worth changing right now.

## Architecture / DRY

- [ ] Finish splitting `src/http.zig` into a small router + feature modules (for maintainability and faster iteration).
  - [x] Shared helpers extracted to `src/util/*` (`htmlEscapeAlloc`/`textToHtmlAlloc`, URL builders, remote account API ID mapping).
  - [x] HTTP `Request`/`Response` types moved to `src/http_types.zig` to avoid import cycles while splitting handlers.
  - [x] Core handlers split into `src/http/*` (discovery/instance/pages/oauth/accounts/statuses/timelines/activitypub).
  - [ ] Move remaining handlers still living in `src/http.zig` (media, notifications, conversations, misc compat endpoints).
- [x] DRY federation delivery code (“sign + POST” loops) via shared helpers in `src/federation.zig`.
- [ ] Store explicit recipient/mention metadata at post-create time (at least for `visibility=direct`) and base delivery on stored addressing rather than reparsing text.

## Performance / robustness

- [x] Avoid `std.heap.page_allocator` per request in `src/server.zig` response header building (use stack + request arena).
- [x] Outbound fetches enforce a maximum response size (`FEDDYSPICE_HTTP_MAX_BODY_BYTES`) and allow per-request overrides (`FetchOptions.max_body_bytes`).

## Security

- [x] Verify inbound ActivityPub inbox requests using HTTP Signatures + `Digest` (including `hs2019`, `content-type`, `content-length`, and reverse-proxy host handling).
- [x] Sanitize remote HTML: do not store/re-serve untrusted `object.content` without sanitization (XSS risk).
- [ ] Header-injection hardening: validate/strip control characters (`\r`, `\n`, etc.) from any user-controlled header values (e.g. redirects) before sending responses.

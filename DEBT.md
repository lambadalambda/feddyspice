# Technical debt / refactoring notes

This file tracks “good future refactors” and known risks. Add items whenever you notice something that should be improved, but isn’t worth changing right now.

## Architecture / DRY

- `src/http.zig` (~8k LOC) should be split into a small router + feature modules (e.g. `oauth`, `accounts`, `statuses`, `timelines`, `activitypub`) for maintainability and faster iteration.
- Shared helpers are duplicated across `src/http.zig` and `src/federation.zig`:
  - `htmlEscapeAlloc` / `textToHtmlAlloc`
  - `baseUrlAlloc` + related URL helpers
  - `remote_actor_id_base` constant + remote account ID helpers
  - Consider extracting to `src/util/*.zig` and importing from both.
- Federation delivery code has repeated “sign + POST” loops (Create/Delete, public/private/direct variants). Extract a single helper like:
  - `deliverSignedActivity(activity_json, recipients)` where recipients map to inbox URLs + host headers.
  - Goal: federation behavior depends on computed **addressing** (`to`/`cc`), not the activity type.
- Direct-message recipient selection currently parses plaintext `@user@domain` mentions from the status text. Long-term:
  - Store explicit recipient/mention metadata at post-create time.
  - Base delivery on stored addressing rather than reparsing text.

## Performance / robustness

- `src/server.zig` allocates response header arrays via `std.heap.page_allocator` per request; consider using the request arena (or stack/static headers) to reduce alloc churn.
- Outbound fetches (`src/transport.zig`) have no maximum response size and currently read entire bodies into memory; add a `max_body_bytes` guard (especially for WebFinger + actor-doc fetches) to prevent OOM on malicious/buggy remotes.

## Security

- Inbound ActivityPub is effectively unauthenticated:
  - We don’t verify HTTP Signatures for incoming inbox requests.
  - The `http.Request` type currently doesn’t carry arbitrary headers, so verification isn’t possible yet.
  - High priority: plumb request headers through `src/server.zig` → `src/http.zig` and verify signatures/digests for federation POSTs.
- Remote HTML is trusted:
  - We store and re-serve `object.content` from remote Notes without sanitization.
  - Risk: XSS if clients render unsanitized HTML. Consider server-side sanitization (or store both sanitized HTML + plain text fallback).
- Header-injection hardening:
  - Any user-controlled header values (e.g. redirects, content types) should be validated/stripped for control characters (`\r`, `\n`, etc.) before being used in response headers.


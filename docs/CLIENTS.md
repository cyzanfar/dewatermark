# Typed API clients

The HTTP API publishes OpenAPI 3.1 at `/openapi.json`. A canonical snapshot is
checked in at [`schemas/openapi-v1.json`](../schemas/openapi-v1.json), and CI
fails when it drifts from the server implementation.

Generate Python and TypeScript clients with the immutable OpenAPI Generator
container:

```bash
./scripts/generate_clients.sh ./generated-clients
```

The generator image is pinned by multi-platform digest. The script resolves the
Docker bind mount to an absolute path and refuses a symlink or non-empty output
directory so stale files cannot survive regeneration. Generated output is
deliberately ignored by Git: review it, run its tests, and publish it in a
separate release process if desired. The API document contains no default
server. Every client application must explicitly supply a base URL, and
non-loopback servers require bearer authentication.

For local Python use, prefer the in-process `dewatermark` API. For browser and
Node Unicode sanitation, use `@cyzanfar/dewatermark-unicode`; it never starts an
HTTP request.

Regenerate the snapshot after an API change:

```bash
python scripts/export_openapi.py --write
python scripts/export_openapi.py --check
```

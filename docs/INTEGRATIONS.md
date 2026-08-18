# Integrations

## One-shot CLI

```bash
uvx dewatermark check .
pipx run dewatermark sanitize < input.txt
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/cyzanfar/text-watermark-remover
    rev: v0.7.0
    hooks:
      - id: dewatermark-check
```

## GitHub code scanning

```yaml
name: Dewatermark scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: cyzanfar/text-watermark-remover@v0.7.0
        with:
          paths: |
            .
          output: dewatermark.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: >-
          always() &&
          (github.event_name == 'push' ||
           github.event.pull_request.head.repo.full_name == github.repository)
        with:
          sarif_file: dewatermark.sarif
```

Use `v0.7.0` to follow this release; pin a full commit SHA when your threat
model requires an immutable third-party action. The `paths` input is
newline-delimited, treats every line as a literal path, and cannot inject
scanner options.

## HTTP/OpenAPI

```bash
dewatermark serve --host 127.0.0.1 --port 8765
curl -s http://127.0.0.1:8765/sanitize -H 'content-type: application/json' -d '{"text":"he\u200bllo"}'
```

Binding outside loopback requires `DEWATERMARK_SERVER_API_KEY`. Clients must send it as a bearer token. The service never logs source text. OpenAPI is at `/openapi.json`.

The checked-in OpenAPI 3.1 snapshot is `schemas/openapi-v1.json`. Verify drift
with `python scripts/export_openapi.py --check`; generate pinned Python and
TypeScript SDKs with `scripts/generate_clients.sh`. See
[`CLIENTS.md`](CLIENTS.md).

## MCP and AI agents

```bash
pip install 'dewatermark[agents]'
dewatermark-mcp
```

```json
{"mcpServers":{"dewatermark":{"command":"dewatermark-mcp"}}}
```

The portable agent skill inspects first and requires consent before lossy or
networked operations. In a source checkout it is at
`skills/remove-text-watermarks`. To locate or copy the versioned workflow
bundled in an installed wheel, run:

```bash
dewatermark skill path
dewatermark skill install --output ./remove-text-watermarks
```

Point your agent's skill loader at that directory, or copy it with the agent's
normal skill-install workflow.

Recommended tool order: `inspect`, `plan`, `apply`, then `verify`. The plan
digest must be passed back unchanged. Set `require_verified=true` when an agent
must reject rather than retain an unverified statistical rewrite.

## Container

```bash
docker build -t dewatermark .
docker run --rm dewatermark capabilities
docker run --rm -e DEWATERMARK_SERVER_API_KEY=change-me -p 8765:8765 \
  dewatermark serve --host 0.0.0.0 --port 8765
```

The container runs as an unprivileged user. Its safe default prints local
capabilities and exits instead of exposing an unauthenticated service.

The release workflow publishes images to the GitHub Container Registry with
provenance and an SPDX SBOM. For version `0.7.0`:

```bash
docker pull ghcr.io/cyzanfar/text-watermark-remover:0.7.0
```

## Editor integrations

The repository contains local-only proof-of-concept integrations for VS Code
and JetBrains IDEs under `integrations/`. Both invoke the installed
`dewatermark` CLI with `shell=false`, a credential-stripped environment,
bounded output and deadlines, and local-only scanner commands that do not
request network access. The configured executable remains inside the editor's
trust boundary; these plugins are process isolation, not an OS sandbox.
Diagnostics are read-only; the safe-profile quick fix is always an explicit
user action.

```bash
cd integrations/vscode && npm test && npm run package
cd integrations/jetbrains
./gradlew --no-daemon --dependency-verification=strict \
  test buildPlugin verifyPlugin
```

These source packages are not yet marketplace publications. Review their
README files before local installation.

## Shared scanner policy

Editor plugins, CI, and local commands discover the nearest
`.dewatermark.toml` or `[tool.dewatermark.scan]` table. Use `--no-config` to
force built-in defaults or `--config PATH` to select an exact file. CLI flags
are explicit overrides; repeatable exclusions and suppressions are additive.

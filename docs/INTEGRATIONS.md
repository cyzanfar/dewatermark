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
    rev: v0.5.0
    hooks:
      - id: dewatermark-check
```

## GitHub code scanning

```yaml
- uses: cyzanfar/text-watermark-remover@v0.5.0
  with: {paths: ., output: dewatermark.sarif}
- uses: github/codeql-action/upload-sarif@v4
  with: {sarif_file: dewatermark.sarif}
```

## HTTP/OpenAPI

```bash
dewatermark serve --host 127.0.0.1 --port 8765
curl -s http://127.0.0.1:8765/sanitize -H 'content-type: application/json' -d '{"text":"he\u200bllo"}'
```

Binding outside loopback requires `DEWATERMARK_SERVER_API_KEY`. Clients must send it as a bearer token. The service never logs source text. OpenAPI is at `/openapi.json`.

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
`skills/remove-text-watermarks`. To locate the copy bundled in an installed
wheel, run:

```bash
python -c "from importlib.resources import files; print(files('dewatermark').joinpath('skills/remove-text-watermarks'))"
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

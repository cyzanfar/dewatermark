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
    rev: v0.4.0
    hooks:
      - id: dewatermark-check
```

## GitHub code scanning

```yaml
- uses: cyzanfar/text-watermark-remover@v0.4.0
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

The portable agent skill at `skills/remove-text-watermarks` inspects first and requires consent before lossy or networked operations.

## Container

```bash
docker build -t dewatermark .
docker run --rm -e DEWATERMARK_SERVER_API_KEY=change-me -p 8765:8765 dewatermark
```

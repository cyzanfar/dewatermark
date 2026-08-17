---
name: remove-text-watermarks
description: Inspect, explain, and remove hidden Unicode text artifacts with dewatermark while preserving meaning and privacy. Use when a user asks to check pasted text or repository files for zero-width characters, Unicode tags, variation selectors, bidi controls, exotic spaces, homoglyphs, or AI/LLM text watermarks; also use when configuring detector-scoped assurance, the CLI, JSON API, SARIF scanner, HTTP/OpenAPI, or MCP server. Do not treat a changed string as proof that an undisclosed vendor watermark was removed.
---

# Remove Text Watermarks

Use the installed `dewatermark` package to inspect before changing text, choose the least destructive mode, and report limitations honestly.

## Workflow

1. Check availability with `dewatermark capabilities`. If unavailable, suggest `pip install dewatermark` or run it through `uvx dewatermark`.
2. Inspect pasted text with `dewatermark inspect --detector unicode`. For files or repositories, use `dewatermark check PATH --format json`.
3. Explain actionable, contextual, and informational findings. Never infer the author, model, or vendor from an invisible character alone.
4. For a transformation, create a content-bound plan with `dewatermark plan`. Review its detector, lossiness, permissions, quality policy, verification availability, limits, and digest.
5. Apply only the exact reviewed plan with `dewatermark apply --plan-digest DIGEST --consent`. Network use and model downloads require separate explicit flags. Keep the safe Unicode profile unless the user explicitly accepts lossy Latin-oriented normalization.
6. Verify source and candidate with `dewatermark verify`, then report `detection_status`, `transformation_status`, `verification_status`, and `claim_scope` separately.

## Safe commands

```bash
printf '%s' "$TEXT" | dewatermark analyze --format json
printf '%s' "$TEXT" | dewatermark sanitize --format json
dewatermark check . --format sarif --output dewatermark.sarif
dewatermark inspect --input input.txt --detector unicode
dewatermark plan --input input.txt --mode sanitize --detector unicode
```

Do not place sensitive text in shell arguments or logs. Prefer stdin or local files. Do not use `--fix`, aggressive sanitization, remote processing, or model downloads without clear user authorization.

## Claims

Distinguish deterministic Unicode cleanup from statistical watermark mitigation. State the named scheme, detector, threshold, text length, model, and quality constraint for efficacy claims. Anthropic confirms marking for supported Claude models launched on or after August 2, 2026, but its public technical detector guidance is forthcoming; report Claude as unsupported rather than guessing its mechanism. Never promise universal removal.

---
name: remove-text-watermarks
description: Inspect, explain, and remove hidden Unicode text artifacts with dewatermark while preserving meaning and privacy. Use when a user asks to check pasted text or repository files for zero-width characters, Unicode tags, variation selectors, bidi controls, exotic spaces, homoglyphs, or AI/LLM text watermarks; also use when configuring the dewatermark CLI, JSON API, SARIF scanner, or MCP server. Do not treat the skill as proof that an undisclosed vendor watermark was removed.
---

# Remove Text Watermarks

Use the installed `dewatermark` package to inspect before changing text, choose the least destructive mode, and report limitations honestly.

## Workflow

1. Check availability with `dewatermark capabilities`. If unavailable, suggest `pip install dewatermark` or run it through `uvx dewatermark`.
2. Inspect pasted text with `dewatermark analyze --format json`. For files or repositories, use `dewatermark check PATH --format json`.
3. Explain the categories and positions found. Never infer the author, model, or vendor from an invisible character alone.
4. Use `dewatermark sanitize` for deterministic Unicode cleanup. Keep the default `safe` profile unless the user explicitly accepts lossy normalization for Latin-oriented text.
5. Use `dewatermark remove --dry-run --mode MODE --format json` before statistical rewriting. Model downloads and remote processing require explicit user consent.
6. Verify the cleaned output with another analysis and summarize what changed.

## Safe commands

```bash
printf '%s' "$TEXT" | dewatermark analyze --format json
printf '%s' "$TEXT" | dewatermark sanitize --format json
dewatermark check . --format sarif --output dewatermark.sarif
dewatermark remove --mode auto --dry-run --format json < input.txt
```

Do not place sensitive text in shell arguments or logs. Prefer stdin or local files. Do not use `--fix`, aggressive sanitization, remote processing, or model downloads without clear user authorization.

## Claims

Distinguish deterministic Unicode cleanup from statistical watermark mitigation. State the named scheme, detector, threshold, text length, model, and quality constraint for efficacy claims. Never promise universal removal or claim Anthropic/Claude-specific coverage without a public scheme and independent evidence.

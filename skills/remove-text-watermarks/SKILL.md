---
name: remove-text-watermarks
description: Inspect, explain, and remove hidden Unicode text artifacts with dewatermark while preserving meaning and privacy. Use when a user asks to check pasted text or repository files for zero-width characters, Unicode tags, variation selectors, bidi controls, exotic spaces, homoglyphs, or AI/LLM text watermarks; also use when configuring detector-scoped assurance, the CLI, JSON API, SARIF scanner, HTTP/OpenAPI, or MCP server. Do not treat a changed string as proof that an undisclosed vendor watermark was removed.
---

# Remove Text Watermarks

Use the installed `dewatermark` package to inspect before changing text, choose the least destructive mode, and report limitations honestly.

## Workflow

1. Check availability with `dewatermark capabilities`. If unavailable, suggest `pip install dewatermark` or run it through `uvx dewatermark`. Before using a statistical detector, run `dewatermark detectors doctor`; treat synthetic or uncalibrated fixtures as contract tests only.
2. Inspect pasted text with `dewatermark inspect --detector unicode`. For files or repositories, use `dewatermark check PATH --format json`. For an unsaved editor buffer, pipe it through `dewatermark check --stdin-path FILE --format json` so the repository policy still applies.
3. Explain actionable, contextual, and informational findings. Never infer the author, model, or vendor from an invisible character alone.
4. For a transformation, create a content-bound plan with `dewatermark plan`. Review its detector, lossiness, permissions, required and advisory quality gates, verification availability, limits, and digest. Use `--require-verified` when retaining an unverified statistical rewrite would violate the user's request.
5. Apply only the exact reviewed plan with `dewatermark apply --plan-digest DIGEST --consent`. Network use and model downloads require separate explicit flags. Keep the safe Unicode profile unless the user explicitly accepts lossy Latin-oriented normalization.
6. Verify source and candidate with `dewatermark verify`, then report `detection_status`, `transformation_status`, `verification_status`, and `claim_scope` separately.

## Detector-guided statistical workflow

Use this only when the operator has installed a detector for the exact scheme,
tokenizer, key or configuration, and threshold in scope.

1. Run `dewatermark localize --detector NAME` to identify content-free character ranges. Treat `localized_exploratory` as an editing hint, not proof.
2. Require a different, calibrated held-out detector before attempting a verified rewrite. Bundled reference fixtures and uncalibrated adapter packs are not sufficient.
3. Run `dewatermark mitigate` only with explicit transformation consent and explicit network/model flags when needed. Name every strategy and set tight candidate/query limits.
4. Accept changed text only when the result is `verified`. Every rollback or abstention must preserve the exact source.
5. Report the named detectors, configuration fingerprints, quality outcomes, search limits, and claim scope from the content-free receipt.

```bash
dewatermark localize --input input.txt --detector PRIMARY
dewatermark mitigate --input input.txt --detector PRIMARY \
  --verifier HELD_OUT --strategy REWRITER --consent
```

The one-shot `mitigate` command enforces consent but is not a signed approval
workflow. Use the separate plan/apply flow when a human or external system must
review and bind exact settings before execution.

## Safe commands

```bash
printf '%s' "$TEXT" | dewatermark analyze --format json
dewatermark check . --format sarif --output dewatermark.sarif
dewatermark check --stdin-path src/app.py --format json < unsaved-buffer.txt
dewatermark detectors doctor
dewatermark inspect --input input.txt --detector unicode
dewatermark plan --input input.txt --mode sanitize --detector unicode
```

Do not place sensitive text in shell arguments or logs. Prefer stdin or local files. Do not use `--fix`, aggressive sanitization, remote processing, or model downloads without clear user authorization.

## Claims

Distinguish deterministic Unicode cleanup from statistical watermark mitigation. State the named scheme, detector, key/configuration fingerprint, threshold, effective detector-token length, calibration population, model, and quality constraint for efficacy claims. Never promote a green conformance fixture into a production claim. Anthropic confirms marking for supported Claude models launched on or after August 2, 2026, but its public technical detector guidance is forthcoming; report Claude as unsupported rather than guessing its mechanism. Never promise universal removal.

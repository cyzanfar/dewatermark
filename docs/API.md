# API reference

## Pure discovery

- `capabilities(config=None) -> dict`: installed features without network/model loading.
- `plan(mode="auto", config=None) -> ExecutionPlan`: request requirements without side effects.
- `removal_result_schema() -> dict`: JSON Schema for tool registration.
- `analyze(text) -> dict`: versioned Unicode forensic report.
- `sanitize(text, profile="safe") -> str`: deterministic Unicode hygiene.

## Processing

- `remove(text, mode="auto", ..., config=None) -> RemovalResult`
- `remove_many(texts, ...) -> list[BatchItemResult]`: ordered, concurrent outcomes.
- `await aremove(text, ...) -> RemovalResult`: asynchronous wrapper with cancellation signaling.
- `Dewatermark(config)`: scoped facade and context manager; `close()` clears model caches.

`RemovalResult.to_dict()` is JSON-compatible schema `1.0`. Batch items retain
successful siblings when one input fails. Remote calls, model downloads, input
characters, output tokens, concurrency, and retries have explicit config bounds.

Set `DewatermarkConfig(event_handler=callback)` for metadata-only pipeline,
HTTP retry/latency, fallback, and provider token-usage events. Events never
contain source text, prompts, response bodies, headers, URLs, or credentials;
observer failures are logged and do not interrupt processing.

## CLI exit codes

- `0`: all requested work completed.
- `2`: invalid arguments, input, or configuration.
- `3`: processing backend unavailable or denied.
- `4`: processing failure or partial JSONL input failure.

The CLI writes results to stdout and errors to stderr. It never prompts.

## Extensions

See `dewatermark.protocols` for scorer, rewriter, detector, quality-gate, and
chunker contracts. Register factories with `register_provider`, or publish them
under the `dewatermark.providers` Python entry-point group.

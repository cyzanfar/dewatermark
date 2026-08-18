# API reference

## Pure discovery

- `capabilities(config=None) -> dict`: installed features without network/model loading.
- `plan(mode="auto", config=None) -> ExecutionPlan`: request requirements without side effects.
- `public_schema(name) -> dict`: retrieve any packaged JSON contract by its
  stable CLI name.
- `removal_result_schema()`, `evidence_receipt_schema()`,
  `detector_capability_schema()`, and `command_detector_schema()`: core
  version-1 contracts.
- `analyze(text) -> dict`: versioned Unicode forensic report.
- `sanitize(text, profile="safe") -> str`: deterministic Unicode hygiene.
- `inspect(text, detector="unicode") -> DetectionEvidence`: named-detector evidence.
- `inspect_text(text, detector="unicode") -> dict`: content-bound agent envelope.
- `create_plan(text, ..., detector=..., require_verified=...) -> dict`: side-effect-free plan and digest.
- `verify_text(source, candidate, detector=...) -> dict`: paired evidence or explicit abstention.
- `discover_detector_capabilities()` / `doctor_detectors()`: static inventory
  and claim-boundary checks that never load a plugin or model.
- `run_reference_conformance()`: dependency-free synthetic contract vectors;
  this is not an efficacy benchmark.
- `agent_skill_path()` / `materialize_agent_skill(path)`: locate or safely copy
  the bundled inspect-plan-apply-verify workflow.
- `ScannerConfig`, `resolve_scanner_config()`, and `path_is_selected()`: share
  repository scan policy with in-memory editor buffers.
- `benchmark_*_schema()`: packaged JSON contracts for sample registries,
  observations, evidence bundles, and independent replication records.

`dewatermark schema --kind NAME` accepts `removal-result`, `evidence-receipt`,
`detector-capability`, `command-detector`, `benchmark-sample-registry`,
`benchmark-observation-set`, `benchmark-evidence-bundle`,
`benchmark-replication-record`, and `openapi`. The OpenAPI document describes
the HTTP transport and its optional-on-loopback bearer-authentication hook.
Python callers can retrieve that document as `openapi_document()` or
`public_schema("openapi")`.

## Processing

- `remove(text, mode="auto", ..., config=None) -> RemovalResult`
- `assure(text, mode=..., detector=...) -> RemovalResult`: detector-scoped alias.
- `apply_plan(text, plan_digest, ..., consent=True) -> dict`: apply exactly a reviewed plan.
- `remove_many(texts, ...) -> list[BatchItemResult]`: ordered, concurrent outcomes.
- `await aremove(text, ...) -> RemovalResult`: asynchronous wrapper with cancellation signaling.
- `Dewatermark(config)`: scoped facade and context manager; `close()` clears model caches.
- `QualityGateBinding(gate, required=True)`: bind a learned or task gate to acceptance policy.
- `BidirectionalNLIGate(adapter, min_entailment=...)`: require entailment both ways.
- `AtomicClaimQAGate`, `EntityLinkingGate`, `CitationGroundingGate`, and
  `TaskContractGate`: strict aggregate pairwise-adapter gates.
- `CachedTransformersNLIAdapter`: cached-only optional NLI reference adapter; never downloads.

`RemovalResult.to_dict()` is JSON-compatible schema `1.0`. Batch items retain
successful siblings when one input fails. Remote calls, model downloads, input
characters, output tokens, concurrency, and retries have explicit config bounds.
The legacy result envelope remains compatible; assurance fields are additive in
`report`, and the full evidence receipt is available as `result.receipt`, the
serialized `receipt` field, and `report.metadata["assurance"]`.

Plan options are validated and expanded to canonical defaults before a digest is
issued, so equivalent Python, CLI, HTTP, and MCP requests share one binding. The
observable extension-state fingerprint is deterministic across fresh processes
and is a one-way content commitment, not authentication or secret storage.

Set `DewatermarkConfig(event_handler=callback)` for metadata-only pipeline,
HTTP retry/latency, fallback, and provider token-usage events. Events never
contain source text, prompts, response bodies, headers, URLs, or credentials;
observer failures are logged and do not interrupt processing.

## CLI exit codes

- `0`: all requested work completed.
- `1`: `dewatermark check` found actionable suspicious Unicode.
- `2`: invalid arguments, input, or configuration.
- `3`: processing backend unavailable or denied.
- `4`: processing failure or partial JSONL input failure.

The CLI writes results to stdout and errors to stderr. It never prompts.
`dewatermark check --stdin-path FILE` labels an in-memory stdin buffer and
applies the nearest repository policy without reading `FILE` from disk.

## Extensions

See `dewatermark.protocols` for scorer, rewriter, detector, quality-gate,
semantic-scorer, and chunker contracts. Every text receiver requires a literal
static `CapabilityManifest` with the matching kind. Consent and manifest checks
run before construction and text access; registered factories receive a config
projection with application API keys removed.

Register rewriter and scorer factories with `register_provider`, or publish
them under the `dewatermark.providers` Python entry-point group. Content-bound
plans bind each active extension registration and observable static-state
fingerprint, then recheck it before first use. Replacing or mutating reviewed
state invalidates the plan until the extension is re-registered and replanned.
Extensions irrelevant to the selected mode are ignored.

For isolated independent detectors, prefer `CommandDetector` and a static
`CapabilityManifest`. Planning never imports an unloaded detector entry point;
trusted plugins must be registered or explicitly loaded first.
In-process extensions are trusted Python dependencies, not sandboxed code. See
[`EXTENSIONS.md`](EXTENSIONS.md) for the complete boundary and reporting rules.
See [`QUALITY_GATES.md`](QUALITY_GATES.md) for quality adapter contracts and
content-free per-gate receipt outcomes.

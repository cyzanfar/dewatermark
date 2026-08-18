# API reference

## Pure discovery

- `capabilities(config=None) -> dict`: installed features without network/model loading.
- `plan(mode="auto", config=None) -> ExecutionPlan`: request requirements without side effects.
- `public_schema(name) -> dict`: retrieve any packaged JSON contract by its
  stable CLI name.
- `removal_result_schema()`, `evidence_receipt_schema()`,
  `localization_result_schema()`, `mitigation_result_schema()`,
  `detector_capability_schema()`, `command_detector_schema()`, and
  `command_strategy_schema()`: core version-1 contracts.
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
- `list_adapter_packs()`, `adapter_pack_manifest(name)`, and
  `materialize_adapter_pack(name, path)`: inspect or copy the packaged KGW,
  Unigram, and SynthID adapter material without running it.
- `agent_skill_path()` / `materialize_agent_skill(path)`: locate or safely copy
  the bundled inspect-plan-apply-verify workflow.
- `ScannerConfig`, `resolve_scanner_config()`, and `path_is_selected()`: share
  repository scan policy with in-memory editor buffers.
- `benchmark_*_schema()`: packaged JSON contracts for sample registries,
  observations, evidence bundles, comparator registries, protocol manifests,
  local run configuration, private input corpora, and independent replication
  records.

`dewatermark schema --kind NAME` accepts `removal-result`, `evidence-receipt`,
`localization-result`, `mitigation-result`, `detector-capability`,
`command-detector`, `command-strategy`, `benchmark-sample-registry`,
`benchmark-observation-set`, `benchmark-evidence-bundle`,
`benchmark-replication-record`, `benchmark-comparator-registry`,
`benchmark-protocol-manifest`, `benchmark-run-config`, `benchmark-input-corpus`,
and `openapi`. Matching Python helpers include
`localization_result_schema()`, `mitigation_result_schema()`, and
`command_strategy_schema()`, plus `benchmark_comparator_registry_schema()`,
`benchmark_protocol_manifest_schema()`, `benchmark_run_config_schema()`, and
`benchmark_input_corpus_schema()`. The OpenAPI document describes the HTTP transport
and its optional-on-loopback bearer-authentication hook. Python callers can
retrieve it as `openapi_document()` or `public_schema("openapi")`.

## Detector-guided processing

- `DetectorSession(primary_detector, verifier_detectors=(), config=None,
  max_queries=None)`: request-scoped detector cache and query budget.
- `DetectorSession.score(text)`: score one string with the primary detector.
- `DetectorSession.score_many(texts)`: score an ordered batch after checking
  that every cache miss fits within the remaining budget.
- `DetectorSession.verify(source, candidate)`: require primary clearance and a
  compatible before/after result from every distinct held-out verifier.
- `localize(text, session, window_characters=1200,
  stride_characters=600, familywise_alpha=0.01) -> LocalizationReport`:
  return content-free character ranges from native attribution or bounded
  window scoring.
- `mitigate(text, primary_detector, strategies, *, verifier_detectors=(),
  config=None, limits=None, source_localization=()) -> MitigationResult`:
  run deterministic, quality-gated candidate search with exact rollback.
- `SearchLimits`: bound rounds, beam width, candidates, transform calls,
  detector queries, candidate characters, and final verification attempts.
- `CandidateStrategy`, `CandidateProposal`, `StrategyBinding`, and
  `StrategyContext`: build in-process candidate generators.
- `registered_strategy(name, config=None)`: adapt a registered transformer for
  detector-guided search.
- `CommandStrategy`, `command_strategy_manifest()`,
  `strategy_configuration_sha256()`, and `make_command_strategy_factory()`:
  run candidate generation through the bounded JSON command protocol.

`MitigationResult.status` is `verified`, `abstained`, or `rolled_back`. Only
`verified` can contain changed text. Every other result contains the exact
source value. The receipt is content-free: it records hashes, detector
observations, edit counts, quality outcomes, trace decisions, and resource
counts, but not rejected candidates.

See [Detector-guided mitigation](DETECTOR_GUIDED_MITIGATION.md) for the decision
rules and [Configuration](CONFIGURATION.md#detector-guided-search-limits) for
the effective limits.

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
Credential-shaped state and named private paths are rejected; extensions must
keep secrets in operator-managed channels because low-entropy content addresses
can be guessed.

Set `DewatermarkConfig(event_handler=callback)` for metadata-only pipeline,
HTTP retry/latency, fallback, and provider token-usage events. Events never
contain source text, prompts, response bodies, headers, URLs, or credentials;
observer failures are logged and do not interrupt processing.

## CLI, HTTP, and MCP surfaces

The command line exposes the new workflow directly:

```bash
dewatermark localize --input source.txt --detector SEARCH_DETECTOR
dewatermark mitigate --input source.txt \
  --detector SEARCH_DETECTOR \
  --verifier HELD_OUT_DETECTOR \
  --strategy CANDIDATE_GENERATOR \
  --consent
```

`localize` accepts window size, stride, family-wise error rate, detector-query
limit, and separate network/model-download permissions. `mitigate` also accepts
round, beam, candidate, transform-call, detector-query, and verification limits.
Repeat `--verifier` or `--strategy` to provide more than one.

HTTP uses `POST /localize` and `POST /mitigate`. `/mitigate` requires a consent
object:

```json
{
  "text": "source text",
  "detector": "search-detector",
  "verifiers": ["held-out-detector"],
  "strategies": ["candidate-generator"],
  "consent": {
    "transformation": true,
    "network": false,
    "model_download": false
  },
  "limits": {
    "max_candidates": 24,
    "max_detector_queries": 64
  }
}
```

The optional MCP server exposes structured `localize` and `mitigate` tools with
the same rules. Install it with `pip install "dewatermark[agents]"`. MCP
`mitigate` requires `consent=true`; network and model download remain separate
arguments. Capability discovery reports both operations without loading a
model, plugin, or command.

## CLI exit codes

- `0`: all requested work completed.
- `1`: `dewatermark check` found actionable suspicious Unicode.
- `2`: invalid arguments, input, or configuration.
- `3`: processing backend unavailable or denied.
- `4`: processing failure or partial JSONL input failure.

For `mitigate`, a verified result and a `source_not_detected` abstention exit
with `0`. Rollback, unavailable verification, and other unsuccessful processing
exit with `4`.

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
`CapabilityManifest`. For isolated candidate generation, use
`CommandStrategy`; its strings remain untrusted until the central optimizer
accepts one. Planning never imports an unloaded detector entry point or starts
a command. Trusted plugins must be registered or explicitly loaded first.
In-process extensions are trusted Python dependencies, not sandboxed code. See
[`EXTENSIONS.md`](EXTENSIONS.md) for the complete boundary and reporting rules.
See [`QUALITY_GATES.md`](QUALITY_GATES.md) for quality adapter contracts and
content-free per-gate receipt outcomes.

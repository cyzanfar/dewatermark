# Quality assurance gates

Every rewrite candidate is untrusted. The central pipeline first applies the
dependency-free checks for truncation, repetition, numbers, units, dates, URLs,
email addresses, quotations, negation, modality, entity-like spans, citations,
code, Markdown/HTML structure, and JSON shape. Optional learned or task-specific
gates are additive: no extension can erase a deterministic failure or commit a
candidate itself.

## Fail-closed policy

Configure v0.6 gates with `QualityGateBinding`:

```python
from dataclasses import replace

from dewatermark.config import DewatermarkConfig
from dewatermark.quality import QualityGateBinding
from dewatermark.quality_gates import BidirectionalNLIGate

config = replace(
    DewatermarkConfig(),
    quality_gates=(
        QualityGateBinding(BidirectionalNLIGate(reviewed_nli_adapter)),
        QualityGateBinding(review_only_gate, required=False),
    ),
)
```

A required gate accepts only `passed`. `failed`, `abstained`, exceptions,
malformed results, missing consent, missing resource accounting, and an expired
deadline all reject the candidate. An advisory gate records the same typed
outcome without overriding the required policy. Once one required prerequisite
fails, later gates are recorded as `prerequisite_failed` without receiving text.

The older single `quality_gate=` hook remains supported, but it is now additive
to the built-in gate. It cannot replace the central deterministic checks.

## Bidirectional NLI

`BidirectionalNLIGate` evaluates both:

1. source entails candidate, guarding against unsupported additions;
2. candidate entails source, guarding against omissions.

Both probabilities, their minimum, the configured threshold, and the final
status are recorded. The adapter contract is:

```python
class NLIAdapter:
    capability = CapabilityManifest(
        identifier="my-reviewed-nli",
        kind="quality_gate",
        network_required=False,
        model_download_possible=False,
        metadata={"resource_accounting": "model"},
    )

    def available(self) -> bool: ...
    def entailment_probability(self, premise: str, hypothesis: str) -> float: ...
```

For a local model, call `current_request_context().record_model_access(...)`
for each evaluation. For a remote endpoint, declare `network_required=True`
and route each physical attempt through the request context's
`before_remote_call(...)`; otherwise the gate returns
`remote_usage_not_accounted`. Remote text processing still requires explicit
request consent. Generic extensions never receive application credentials.

`CachedTransformersNLIAdapter` is the safe reference adapter. It imports Torch
and Transformers only during evaluation and always passes
`local_files_only=True` to tokenizer and model loading. It never downloads a
model. Cache and review a sequence-classification NLI model separately, then:

```python
from dewatermark.quality_gates import (
    BidirectionalNLIGate,
    CachedTransformersNLIAdapter,
)

adapter = CachedTransformersNLIAdapter("org/reviewed-nli-revision")
gate = BidirectionalNLIGate(adapter, min_entailment=0.82)
```

An absent dependency, uncached model, unknown entailment label, or inference
failure becomes a required-gate error; there is no fallback to an unreviewed
model and no implicit network access. Inputs longer than the configured NLI
token limit are rejected instead of being scored after silent truncation.

## Claim, entity, citation, and task checks

`AtomicClaimQAGate`, `EntityLinkingGate`, `CitationGroundingGate`, and
`TaskContractGate` consume an adapter with:

```python
class PairwiseAdapter:
    capability = CapabilityManifest(..., kind="quality_gate")

    def available(self) -> bool: ...
    def assess(self, source: str, candidate: str) -> PairwiseAssessment: ...
```

`PairwiseAssessment` contains only a finite aggregate score and the number of
checked items. Claim text, answers, entities, citations, test output, prompts,
and provider responses must remain inside the adapter. Use `TaskContractGate`
for JSON Schema validation, unit tests, executable examples, exact output
contracts, or application-specific validators. A zero-item assessment abstains;
it can never establish preservation.

These adapters are interfaces, not claims that generic NLI or an LLM judge
proves factual equivalence. Calibrate thresholds on held-out matched rewrites,
publish the model and prompt revisions, and keep task correctness in benchmark
denominators.

## Planning, privacy, and receipts

`create_plan` binds every gate's static manifest, implementation identity,
required/advisory policy, privacy declarations, and consent requirements without
invoking the gate. `quality_gate_conformance(gate)` performs a content-free
static inspection and does not import optional dependencies.

Evidence receipts expose one `quality.gate_outcomes[]` record per executed or
skipped gate. Records contain identifiers, capability digests, status, scores,
thresholds, checked-item counts, and enumerated reason codes—not source or
candidate fragments. All gates share the request cancellation flag, deadline,
remote-call ledger, model-access ledger, and privacy consent.

In-process adapters remain trusted Python dependencies rather than sandboxes.
Their manifests are enforceable cooperative declarations; review their code and
pin their dependencies before enabling them.

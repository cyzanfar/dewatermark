# Detector-guided mitigation

Detector-guided mitigation uses a named detector to search for a small,
quality-safe edit. It is for a known watermark scheme and configuration. It is
not a generic authorship test, and it does not prove that every possible
watermark is gone.

The safe rule is simple: a changed string is returned only when the primary
detector, every required quality check, and at least one distinct held-out verifier all
accept it. Every other outcome returns the exact source string.

## How the workflow runs

1. A `DetectorSession` scores the source with the primary detector.
2. `localize()` can ask that session for likely signal ranges. Native detector
   ranges are used when available. Otherwise, the text is checked in overlapping
   windows.
3. One or more strategies propose candidate strings. Proposals are untrusted;
   a strategy cannot approve its own output.
4. The central optimizer runs the package's quality checks and scores passing
   candidates with the primary detector.
5. The smallest passing edit is checked against the source by the held-out
   verifier or verifiers. They are not used to guide the search.
6. `mitigate()` returns the changed candidate only if every verifier reports
   `verified_cleared`. Otherwise it returns the exact source string.

"Held out" here means that a verifier is not exposed to search feedback or used
to rank candidates. The runtime also rejects repeated aliases, configurations,
implementations, static states, and object instances as distinct evidence. Each
verifier must declare `calibrated=true` and `independent=true` before its
positive-before, clear-after pair can support `verified_cleared`. The primary
and every verifier must also declare the same `watermark_target_sha256`, which
binds the watermark scheme, generation key identifier, tokenizer, and embedding
configuration separately from each detector implementation's own configuration.
This compatibility check happens before any verifier receives text.

The primary detector may be useful for development even when it is not
calibrated. Its result alone never approves a changed output.

## Detector sessions

`DetectorSession` is the only detector-query boundary used by the adaptive
search. It provides:

- a hard query budget;
- a hard four-million-character aggregate cap for overlapping fallback windows;
- detector-policy-and-text-digest caching, where valid cache hits do not spend
  the budget and policy drift fails closed;
- atomic batch preflight, so an oversized batch fails before a partial run;
- the same consent, timeout, cancellation, and resource accounting used by
  other package operations; and
- a content-free ledger containing counts and hashes, not source or candidate
  text.

A session belongs to one request context. Reusing it from another request is an
error.

```python
from dewatermark import DetectorSession, localize

session = DetectorSession("my-search-detector", max_queries=32)
report = localize(
    text,
    session,
    window_characters=1200,
    stride_characters=600,
    familywise_alpha=0.01,
)
```

Localization first requires a positive full-document result. Detector-supplied
character ranges are preferred, but they are confirmatory only when every range
has a p-value and the capability declares calibrated family-wise localization
error control. Fallback windows require calibrated p-values and a Bonferroni
correction. All other ranges are `localized_exploratory`: useful editing hints,
not controlled statistical evidence. Reports contain half-open character
offsets and detector statistics, never the text inside a range.

A native-attribution capability makes that contract explicit with
`metadata.localization_calibrated=true` and
`metadata.localization_error_control="familywise"`. These are reviewed adapter
claims, so production evidence must still identify the calibration artifact.

Python callers can pass `report.spans` to
`mitigate(source_localization=report.spans)`. Without that argument, mitigation
forwards only native ranges returned by the primary detector; it does not run
fallback window localization automatically. CLI, HTTP, and MCP localization is
a separate review operation and those mitigation calls do not currently accept
client-supplied ranges.

## Mitigation from Python

```python
from dewatermark import DewatermarkConfig, SearchLimits, mitigate, registered_strategy

config = DewatermarkConfig(
    allow_remote_processing=False,
    allow_model_download=False,
    max_detector_queries=64,
    max_search_candidates=24,
)

result = mitigate(
    text,
    "my-search-detector",
    [registered_strategy("my-candidate-generator", config)],
    verifier_detectors=["my-held-out-detector"],
    config=config,
    limits=SearchLimits(
        max_rounds=2,
        beam_width=4,
        max_candidates=24,
        max_transform_calls=24,
        max_detector_queries=64,
        max_verification_candidates=8,
    ),
)

if result.status == "verified":
    cleaned = result.cleaned_text
else:
    assert result.cleaned_text == text
```

Candidate order, beam ranking, and tie-breaking are deterministic for the same
detectors, strategies, configuration, and seed. Determinism does not make an
external model deterministic; that adapter must honor the supplied seed if
repeatability is required.

## Result meanings

| Status | Meaning | Returned text |
| --- | --- | --- |
| `verified` | The named primary cleared, all required quality checks passed, and every distinct held-out verifier returned `verified_cleared` | Selected candidate |
| `abstained` | Search did not start because the source was not detected, a detector was unavailable, a verifier was missing, or an initial budget was unavailable | Exact source |
| `rolled_back` | Search started, but no candidate completed all required quality and verification checks | Exact source |

The receipt contains detector observations, hashes, edit counts, strategy names,
reason codes, a content-free search trace, and resource counts. Rejected
candidate text is not included. A `verified` result is scoped to the named
detector configurations; it is not an authorship conclusion or a universal
watermark-removal claim.

## Candidate strategies

A strategy may be an in-process `CandidateStrategy`, an existing registered
transformer wrapped by `registered_strategy()`, or a bounded
`CommandStrategy`. Every strategy receives deterministic context with the
current primary-detector result and optional source ranges. It returns candidate
strings only. The optimizer decides whether any candidate is safe to use.

`context_aware_strategy()` is the built-in local option for native attribution.
It proposes a bounded sequence of small English lexical edits at, or within a
configurable number of tokens of, supplied signal spans. Its configuration and
fixed lexicon revision are bound into its capability identity. It returns no
candidates when spans or supported edits are absent, and it has no acceptance
path of its own: central quality gates, primary clearance, and an independent
held-out verifier remain mandatory.

Use the command strategy for tools with separate or conflicting dependencies.
It uses immutable argv, no shell, a small environment, a versioned JSON request,
bounded output, and redacted failures. The executable is still trusted code;
use an operating-system sandbox or container when it is not trusted. See the
[extension guide](EXTENSIONS.md#bounded-command-strategies) and the
[command-strategy schema](../schemas/command-strategy-protocol-v1.json).

## CLI, HTTP, and MCP

The same rules are available on every supported surface:

- CLI: `dewatermark localize` and `dewatermark mitigate`
- HTTP: `POST /localize` and `POST /mitigate`
- MCP: `localize` and `mitigate`
- JSON Schemas: `localization-result`, `mitigation-result`, and
  `command-strategy`

`mitigate` requires explicit transformation consent. Network access and model
downloads are separate opt-ins. CLI and MCP calls accept those permissions as
booleans; HTTP mitigation places them in the `consent` object.

For available bounds and environment settings, see
[Configuration](CONFIGURATION.md#detector-guided-search-limits). For detector
requirements and the non-production reference packs, see
[Detectors](DETECTORS.md) and [Reference detectors](REFERENCE_DETECTORS.md).

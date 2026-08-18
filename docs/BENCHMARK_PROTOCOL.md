# DewatermarkBench protocol

The benchmark measures detector-scoped mitigation and quality preservation. It
does not attempt to certify that text is human-authored or universally
watermark-free.

This document is the target protocol. A feature existing in the evaluation
harness is not, by itself, evidence that a published result exercised that
feature. A result is protocol-conformant only when its machine-readable bundle
records every required condition and the required controls were actually run.

## Coverage and conformance

The matrix below describes the current source tree, not a performance result.
`Implemented` means the harness can record or calculate the item; `partial`
means an operator or external workflow must supply some of it; and `not yet`
means a public result must not claim that part of the protocol.

| Area | Target protocol | Current source coverage | Tracked public evidence |
| --- | --- | --- | --- |
| Reproducible identity | Content-address every consequential input, implementation, prompt set, and dependency revision | **Implemented for current runs:** [`eval/manifest.py`](../eval/manifest.py) binds arguments, packages, prompts, the complete evaluator and library trees, canonical Unicode policy, source commit/dirty state, adapter sidecars, and local executable/script digests; unresolved identities cannot resume | The historical Unicode v0.4 report predates this manifest and remains labelled partial |
| Independent splits | Disjoint calibration, development, and final-test examples | **Implemented for protocol observations:** the canonical sample registry rejects prompt/document clusters or key fingerprints crossing split boundaries; the legacy generator runner still exposes its seeded exploratory cohorts separately | No tracked statistical result |
| Matched controls | Paired watermarked and same-generator unwatermarked outputs, transformed nulls, and human controls | **Implemented as an enforceable input contract:** matched nulls must bind the same generator/decoding configuration and positive sample; human inputs are kept local and published only as licensed, dated, domain/matching-rule-bound digests | Unicode v0.4 uses original synthetic covers, not generator or human controls |
| Held-out keys | Pre-register development keys and evaluate unseen keys/configurations | **Implemented as a fail-closed partition contract:** every non-secret fingerprint belongs to exactly one split and final-test coverage requires a pre-access freeze digest | None |
| Length coverage | Run every required detector-token length bin | **Implemented:** registered and observed source lengths must agree, the five bins are canonical, and full coverage requires every final-test task × language × cohort matrix cell | Unicode v0.4 is character-channel fixture coverage only |
| Task coverage | Prose, factual QA, summarization, translation, code, mathematics, and structured data with task-specific checks | **Implemented as a registry and observation contract:** each sample must declare every checker kind required by its task and full final-test Cartesian coverage is enforced | No reviewed task corpus or tracked run |
| Language coverage | Pre-registered multilingual and multiscript matrix | **Implemented as a registry and observation contract:** English, another Latin script, Arabic, Indic, Chinese, and Korean groups are explicit and enforced across the final matrix | The cross-runtime Unicode golden corpus is a regression suite, not multilingual mitigation evidence |
| Detector statistics | AUROC and TPR at fixed FPRs with uncertainty and adequate matched nulls | **Implemented:** empirical estimability checks, disjoint calibration/test nulls, Wilson intervals, prompt/document-cluster AUROC intervals, paired cluster pre/post intervals, and content-addressed score tables | No tracked statistical result |
| Negative effects | False insertion plus registered cross-detector transfer/confusion checks | **Implemented when observations are supplied:** matched and human-control false insertion, primary/cross confusion, and composite success retain failures and abstentions in the primary denominator | None |
| Quality preservation | Deterministic gates, bidirectional semantic/factual checks, protected spans, and task correctness | **Partial:** central deterministic gates, typed fail-closed bidirectional NLI, claim-QA, entity, citation, and task adapter interfaces now exist, including a cached-only NLI reference adapter; calibrated reference configurations, human validation, and the full task battery are not yet published | None |
| Human evaluation | Matched human-authored controls and blinded, pre-registered review with agreement reporting | **Implemented as local-only tooling:** packet creation requires explicit text-artifact consent, separates the blinded A/B packet from its method key, and reports assignment-cluster-bootstrap Krippendorff agreement; a real reviewed packet is still required | None |
| Resource accounting | Runtime, peak memory, model size, queries, generated tokens, and cost | **Implemented with explicit missingness:** legacy runs capture feasible process/model counters and protocol observations require per-sample time, memory, query, token, and cost fields | None |
| Artifact handling | Consent-gated text artifacts, aggregate JSON, append-only checkpoints, resumability, immutable bundles, and replay | **Implemented:** content-free observation sets and aggregates, canonical registry binding, SHA-256 artifact verification, atomic bundles, permission-gated replay, and cross-bound replication records; generated/review text is never eligible as a public bundle artifact | Unicode v0.4 has a machine-readable aggregate companion, but predates current run manifests |

The only tracked quantitative artifact today is the
[Unicode v0.4 fixture regression](../benchmarks/unicode-v0.4.md). It is a
50-case synthetic covert-channel check and is not a statistical watermark
benchmark. There is currently no tracked result that satisfies the full
statistical protocol.

## Machine-enforced evidence workflow

The legacy `dewatermark-eval` command remains useful for exploratory English
prose experiments. It does not become protocol-complete merely because the
new contracts exist. Comparative evidence uses three inert, content-free JSON
layers:

1. [`eval/protocol-registry-v1.json`](../eval/protocol-registry-v1.json) fixes
   the task, language, split, control, and effective-token-bin vocabulary.
2. A sample registry binds every local input by digest and records its split,
   held-out key fingerprint, task checkers, and human-control provenance.
3. An observation set binds named detector/condition results to those samples.
   [`eval/observations.py`](../eval/observations.py) derives fixed-FPR metrics,
   all-attempt denominators, strata, cross-detector confusion, telemetry, and
   an explicit coverage declaration.

The public JSON contracts are
[`benchmark-sample-registry-v1.json`](../schemas/benchmark-sample-registry-v1.json),
[`benchmark-observation-set-v1.json`](../schemas/benchmark-observation-set-v1.json),
[`benchmark-evidence-bundle-v1.json`](../schemas/benchmark-evidence-bundle-v1.json),
and
[`benchmark-replication-record-v1.json`](../schemas/benchmark-replication-record-v1.json).
No detector, model, plugin, socket, or download is touched during discovery,
validation, planning, or aggregation.

Run the deterministic offline conformance workflow first:

```bash
dewatermark-evidence reference-protocol --output-directory reference-run
dewatermark-evidence verify reference-run/evidence.json
dewatermark-evidence replay reference-run/evidence.json
# Built-in reference recipe only; executes offline into a fresh workspace.
dewatermark-evidence replay reference-run/evidence.json --workspace reproduced-run --execute
```

Replay never publishes argv or host paths: bundles contain only a recipe
SHA-256 plus permission/timeout declarations. Execution uses the matching
built-in reference recipe or an explicitly supplied bounded local recipe. It
does not invoke a shell and refuses escaping or existing result paths, but it
is not an OS sandbox; use a fresh disposable workspace.

The fixture deliberately uses synthetic scores and labels itself
`synthetic_harness_fixture_not_performance_evidence`. It tests the plumbing;
it says nothing about removal efficacy. Assemble real, frozen artifacts with:

```bash
dewatermark-evidence assemble \
  --sample-registry evidence/sample-registry.json \
  --observations evidence/observations.json \
  --output evidence/evidence.json \
  --purpose frozen_evaluation
```

`assemble` refuses raw text/credential fields, missing coverage declarations,
changed effective lengths, duplicate observations, non-finite scores, unsafe
artifact paths, and mutated identities. The resulting bundle still marks
comparative eligibility false. A separate operator can produce a cross-bound
replication record, but its detached-signature digest is only a declaration;
cryptographic identity and independence verification remain external.
`best_in_class_eligible` always remains false because that additionally needs a
frozen comparator registry and a multiple-comparison-aware analysis.

## Experimental units

Each condition fixes and records:

- scheme and implementation revision;
- generator, tokenizer, decoding configuration, and watermark strength;
- lowercase SHA-256 key or non-secret configuration fingerprint;
- threat model and detector-query budget;
- transform, model, seed, edit budget, and resource limits;
- domain, language, task, and detector-token length bin.

Use paired watermarked and same-generator unwatermarked outputs from matched
prompts, plus human-authored controls. Calibration, development, and final test
sets must be disjoint. Include held-out keys wherever possible.

For key-based schemes, publish only one-way SHA-256 fingerprints, never key
identifiers or key material. The split manifest must still prove that final-test keys were not
used for threshold selection, prompt development, attack tuning, or model
selection. When a scheme offers only one public key, label the result
`known-key` and do not generalize it to a held-out-key threat model.

## Required coverage

- Length bins: `<64`, `64-127`, `128-255`, `256-511`, and `512+` effective
  detector tokens.
- Tasks: open-ended prose, factual QA, summarization, translation, code,
  mathematics, and structured data.
- Languages/scripts: English, another Latin-script language, Arabic or Persian,
  an Indic language, Chinese, and Korean.
- Unicode controls: emoji sequences, joining controls, RTL text, combining
  marks, compatibility characters, and ideographic variation sequences.

## Success definition

A sample counts as detector-verified mitigation only when:

1. The source was positive under a named compatible detector.
2. The candidate crossed a pre-registered threshold calibrated on an independent
   split.
3. Every semantic, factual, protected-span, and structural gate passed.
4. The candidate did not create a positive under the registered cross-detector
   checks.
5. The evidence receipt is reproducible from its manifest.

Failures and abstentions stay in the denominator. A transformed negative
control becoming positive is counted as false insertion or spoofing.

## Required reporting

- AUROC and TPR before/after at fixed FPRs with confidence intervals;
- detector-verified mitigation rate and score distribution;
- false insertion rate and cross-detector confusion matrix;
- character/token edit rate and protected-span failure rate;
- bidirectional entailment, atomic-claim/QA, entity, number, unit, citation, and
  structure preservation;
- task-specific correctness, including parsing/tests for code and structured
  data;
- blinded human review on a pre-registered representative subset;
- runtime, memory, model size, remote queries, generated tokens, and cost;
- failures by scheme, key, model, language, task, length, and threat model.

Generic embedding similarity or an LLM judge alone is not an acceptance gate.

## Artifact policy

Publish manifests, aggregate JSON, and confidence intervals. Generated text is
excluded by default and requires explicit artifact consent. Protocol-conformant
checkpoints must be content-addressed by every consequential parameter, prompt
digest, dependency revision, adapter digest, and source commit. Incompatible
resume data must be rejected rather than silently reused.

Public performance claims must link to a machine-readable result bundle and a
command or container that reproduces it.

Each published bundle must also declare protocol coverage field by field.
Missing coverage is represented as `not_run`, `not_available`, or
`not_applicable` with a reason; it must not be silently omitted. At minimum,
record the source commit, content-addressed run ID, canonical policy/config
digests, detector and adapter manifests, split identifiers, and aggregate
sample counts. A report lacking those fields may remain as a historical
regression artifact, but it is not eligible for comparative performance claims.

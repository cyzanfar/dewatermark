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
| Independent splits | Disjoint calibration, development, and final-test examples | **Partial:** statistical threshold and test nulls use distinct seeded populations; strength calibration has a separate seed namespace, but there is no general dataset split registry | No tracked statistical result |
| Matched controls | Paired watermarked and same-generator unwatermarked outputs, transformed nulls, and human controls | **Partial:** generated matched nulls and transformed nulls are implemented; human controls are not | Unicode v0.4 uses original synthetic covers, not generator or human controls |
| Held-out keys | Pre-register development keys and evaluate unseen keys/configurations | **Not yet:** adapters can expose configuration fingerprints, but the harness does not orchestrate or enforce key splits | None |
| Length coverage | Run every required detector-token length bin | **Partial:** arbitrary length sweeps are implemented; required-bin completion is not enforced | Unicode v0.4 is character-channel fixture coverage only |
| Task coverage | Prose, factual QA, summarization, translation, code, mathematics, and structured data with task-specific checks | **Not yet:** current prompts exercise English prose generation only | None |
| Language coverage | Pre-registered multilingual and multiscript matrix | **Not yet** in the statistical harness | The cross-runtime Unicode golden corpus is a regression suite, not multilingual mitigation evidence |
| Detector statistics | AUROC and TPR at fixed FPRs with uncertainty and adequate matched nulls | **Implemented:** empirical estimability checks, bootstrap AUROC intervals, and Wilson intervals | No tracked statistical result |
| Negative effects | False insertion plus registered cross-detector transfer/confusion checks | **Implemented when detectors are registered:** primary and cross-detector score tables, confusion counts, and composite-success denominators are materialized separately; absent external detectors remain explicitly not run | None |
| Quality preservation | Deterministic gates, bidirectional semantic/factual checks, protected spans, and task correctness | **Partial:** central deterministic gates and optional learned metrics exist; NLI, atomic-claim/QA, and the full task battery do not | None |
| Human evaluation | Matched human-authored controls and blinded, pre-registered review with agreement reporting | **Not yet** | None |
| Resource accounting | Runtime, peak memory, model size, queries, generated tokens, and cost | **Partial:** manifests and request receipts record some configuration/resource facts; benchmark-wide telemetry is incomplete | None |
| Artifact handling | Consent-gated text artifacts, aggregate JSON, append-only checkpoints, and resumability | **Implemented** for new harness runs, including content-addressed no-text score tables for positive, held-out-null, and calibration cohorts; generated text remains opt-in | Unicode v0.4 has a machine-readable aggregate companion, but predates current run manifests |

The only tracked quantitative artifact today is the
[Unicode v0.4 fixture regression](../benchmarks/unicode-v0.4.md). It is a
50-case synthetic covert-channel check and is not a statistical watermark
benchmark. There is currently no tracked result that satisfies the full
statistical protocol.

## Experimental units

Each condition fixes and records:

- scheme and implementation revision;
- generator, tokenizer, decoding configuration, and watermark strength;
- key or non-secret configuration fingerprint;
- threat model and detector-query budget;
- transform, model, seed, edit budget, and resource limits;
- domain, language, task, and detector-token length bin.

Use paired watermarked and same-generator unwatermarked outputs from matched
prompts, plus human-authored controls. Calibration, development, and final test
sets must be disjoint. Include held-out keys wherever possible.

For key-based schemes, publish only non-secret key identifiers or salted
fingerprints. The split manifest must still prove that final-test keys were not
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

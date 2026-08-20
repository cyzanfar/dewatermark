# Step-function plan and current status

## What the package can honestly say

This package receives text after generation. It normally does not have the
provider's private key, production detector, generation record, or retrieval
database. A statistical result can therefore say only that named detector
configurations changed from positive to clear while configured quality checks
passed.

It cannot prove that text is human-written. It cannot prove that every
watermark is absent. It cannot transfer a result from one tokenizer, key,
threshold, or provider to another.

Anthropic has described embedded marking for supported Claude models as a
version of SynthID-Text, but has not published the deployed configuration,
keys, calibrated thresholds, or detector contract used here. Claude therefore
remains `unsupported` with status `unsupported_pending_spec`.
Unicode cleanup and generic rewriting are not evidence of Claude watermark
removal. The same rule applies to any private provider scheme without a
compatible detector.

## What is implemented

### Safe text cleanup

- The default Unicode sanitizer removes documented hidden or risky artifacts
  without broad compatibility folding.
- The `aggressive` profile is explicitly lossy.
- Forensic inspection never changes the input.
- Quotes, links, email addresses, numbers, code, markup, structured data, and
  large content changes are protected by central quality checks.

### Exact public reference configurations

- The package keeps small word-level KGW, Unigram, and tournament fixtures for
  offline integration tests.
- The packaged KGW and Unigram packs add exact natural-text reference profiles
  with pinned upstream revisions, content-addressed configuration material,
  checked conformance records, and closed 256-word vocabularies.
- Unknown words and short inputs return typed `unsupported` or
  `insufficient_evidence` results instead of a guessed score.
- Both exact profiles remain `calibrated=false` and
  `production_detection=false`. Exact conformance for one public configuration
  is not an efficacy result.
- Each pack also includes a sealing tool and command adapter for an exact local
  Hugging Face tokenizer snapshot and an owner-only POSIX key file. The
  reference adapter fails closed where it cannot verify equivalent file
  permissions. Sealing records the public configuration and file digests
  without publishing the key. A sealed adapter still starts uncalibrated and
  non-independent.

See [Reference detectors](REFERENCE_DETECTORS.md) for the exact limits.

### Detector-guided search with rollback

- `DetectorSession` provides one request-scoped cache, detector-query budget,
  deterministic query order, and content-free ledger.
- `localize()` prefers detector-supplied ranges. Its fallback window search
  uses Bonferroni correction only for calibrated p-values and otherwise labels
  output exploratory.
- `mitigate()` asks one or more strategies for candidates, runs every candidate
  through the same quality policy, scores it with the primary detector, and
  orders passing candidates by edit size and stable tie-breakers.
- Held-out verifiers do not guide candidate generation or ranking. The runtime
  checks that they are distinct and requires every one to be calibrated,
  independent, positive on the source, and clear on the candidate.
- Only a fully verified candidate is returned. Missing verification, residual
  evidence, detector failure, budget exhaustion, bad quality, and empty search
  all return the exact source value.
- Receipts include hashes, typed outcomes, edit counts, and resource usage, not
  source text or rejected candidates.

See [Detector-guided mitigation](DETECTOR_GUIDED_MITIGATION.md) for the full
flow.

### Safer extension boundary

- Registered transformer providers can be used as candidate strategies, but
  they cannot approve their own output.
- `CommandStrategy` provides a versioned, bounded JSON process protocol for
  candidate generators with separate dependencies.
- Static discovery does not start the command. Runtime uses immutable argv, no
  shell, a small environment, bounded output, explicit network/model consent,
  and redacted failures.
- The executable remains trusted code; containers or operating-system
  isolation are still needed for untrusted repositories.

The workflow is available through Python, `dewatermark localize`,
`dewatermark mitigate`, `POST /localize`, `POST /mitigate`, and the `localize`
and `mitigate` MCP tools. Versioned JSON Schemas cover localization results,
mitigation results, and the command-strategy protocol.

### Existing rewrite methods

- The built-in [BIRA-style](https://arxiv.org/abs/2509.23019) mode uses a
  self-information approximation, negative token bias, bounded retries,
  adaptive backoff, and quality-gated acceptance.
  It is not the paper authors' reference implementation.
- The built-in [SIRA-inspired](https://arxiv.org/abs/2505.05190) mode masks
  selected high-information tokens, creates a separate reference rewrite,
  fills the selected spans, and rejects unresolved or quality-failing output.
  It is not the paper authors' reference implementation.
- Long text is split at structure-aware boundaries and reconstructed in order.
- Remote processing and model downloads are separate, off-by-default choices.

## What is not yet evidence

The implementation now has the control flow needed for a defensible test. It
does not ship real production-watermark efficacy results. The checked-in tiny
fixtures prove protocol behavior only.

Before publishing a comparative or “best” claim, run a frozen protocol with
licensed models and detectors:

| Watermark family | Independent check needed |
| --- | --- |
| KGW and Unigram variants | Original author implementation plus another maintained implementation such as MarkLLM |
| SynthID Text | Google reference or a compatible Transformers implementation for the exact public configuration |
| Distortion-free schemes | Compatible Kuditipudi/Christ-style implementation |
| Semantic schemes | Named SemStamp, SIR/SemaMark, or PostMark configuration |
| Learned AI-text detection | At least one independently trained detector with a defined operating point |
| Retrieval provenance | Provider-held generation corpus; report as provenance, not a removable text signal |

For each claimed configuration:

1. Freeze prompts, models, tokenizers, keys, thresholds, strategies, quality
   checks, and comparator versions before the final run.
2. Separate calibration, development, and final-test data.
3. Match controls by generator, decoding settings, domain, language, and
   detector-token length.
4. Include 100–2,000 token length bands and report every failure and abstention
   in the denominator.
5. Report fixed-false-positive-rate detection results with confidence
   intervals, plus factual, semantic, formatting, and task checks.
6. Test held-out keys or configurations where the threat model permits it.
7. Use a frozen comparator registry and a multiple-comparison-aware analysis.
8. Have an independent operator replay and publish the content-free evidence
   bundle.

The evaluation harness can validate the matrix, assemble content-free
observations, compute fixed-FPR cluster results, record resource use, prepare
blinded-review material, and replay evidence. Those tools do not create the
required datasets, detector access, human judgments, or compute.

At very low false-positive rates, sample size matters. With zero observed false
positives, the approximate 95% upper bound is `3/n`. A stable empirical estimate
therefore needs enough independent null samples for the claimed operating point,
or a separately justified exact null distribution.

## Remaining product work

- Publish a licensed multilingual and multi-domain matrix, including code,
  mathematics, factual QA, summarization, translation, and structured data.
- Publish matched human-control selection rules and contamination risks without
  redistributing restricted text.
- Run blinded human review alongside automated task checks.
- Execute known-key, held-out-key, reference-detector, and cross-detector runs
  as separate results.
- Obtain an independent replay before using comparative language.

Track protocol coverage in [Benchmark protocol](BENCHMARK_PROTOCOL.md). An
implemented code path counts as tooling. Only a completed, inspectable run
counts as evidence.

## Comparison boundary

`guillaumemeyer/watermarks-remover` covers more than text: file routing, image
regeneration, C2PA/EXIF/XMP/document metadata, an HTTP service, Docker images,
and operational deployment features. This project now goes deeper on named
statistical text detectors, constrained candidate search, held-out
verification, exact rollback, and reproducible measurement. That difference is
a product focus, not proof of better removal. Comparative claims require the
frozen benchmark above.

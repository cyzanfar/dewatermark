# Step-function implementation plan and status

## Threat model

This package operates on text supplied after generation. It has no access to a
provider's private watermark key, detector, generation history, or retrieval
database. A result therefore means only that a named detector score changed at
a named operating point while configured quality constraints passed.

Anthropic now confirms embedded text marking for supported Claude models
launched on or after August 2, 2026, but has not published its text algorithm,
keys, detector, threshold, or technical verification guidance. Claude must
therefore remain `unsupported_pending_spec`; Unicode cleanup or generic
rewriting cannot substantiate a Claude-removal claim. Claude, Gemini,
reference SynthID, OpenAI, and other vendor surfaces must not be presented as
interchangeable watermark algorithms.

## Implemented step-function changes

- Safe Unicode sanitation is the default. Compatibility folding and UTS #39
  skeleton replacement are isolated behind the explicitly lossy `aggressive`
  profile. Forensics remains non-mutating.
- The built-in BIRA-style approximation uses a self-information proxy
  suppression set, negative logit bias, bounded retries, adaptive bias backoff,
  repetition checks, and deterministic quality-gated acceptance. It is not the
  authors' reference implementation.
- The built-in SIRA-inspired approximation masks a proportional set of
  high-self-information tokens, produces an independent reference rewrite,
  performs reference-assisted infill, and rejects unresolved or quality-failing
  output. It is not the authors' reference implementation.
- Generated outputs cannot silently drop numbers, URLs, emails, quoted strings,
  or large amounts of content. These gates are necessary but not sufficient for
  semantic equivalence.
- Long text is chunked at structure-aware boundaries and reconstructed exactly.
- Remote processing is deny-by-default and requires explicit consent.
- `auto` uses failure-aware fallback instead of treating dependency import as a
  successful rewrite.
- The evaluator uses matched transformed nulls, minimum-null estimability rules,
  Wilson intervals, length sweeps, and independent JSON command adapters.
- Built-in watermark implementations are labelled as internal references or
  approximations rather than vendor validation.

## External validation required before a best-in-class claim

Code support and empirical evidence are different deliverables. The following
matrix must be run with sufficient compute and licensed model/detector access:

| Family | Required independent implementation |
| --- | --- |
| KGW variants / Unigram | MarkLLM and original author implementation |
| SynthID-Text | Google reference or Transformers implementation |
| Distortion-free | Kuditipudi/Christ-compatible implementation |
| Semantic | SemStamp, SIR/SemaMark, PostMark |
| Learned AI detection | At least one independently trained detector |
| Retrieval provenance | Provider-held generation corpus; report as non-removable |

For each: calibrate initial watermark strength, evaluate 100–2,000 token lengths,
use at least 1,000 matched nulls for 0.1% FPR, report confidence intervals, and
pair every detection result with semantic/factual quality results. A 1e-5 FPR
claim requires at least 100,000 empirical nulls or a separately justified exact
null distribution.

## Quality upgrades for consequential deployments

The dependency-free gates catch catastrophic corruption. Higher-stakes use also
needs bidirectional NLI, claim extraction plus QA consistency, entity linking,
code/markup-aware protection, blinded human review, and a judge independent of
the rewrite model. These are intentionally pluggable evaluation concerns rather
than hard dependencies of the text-cleaning core.

## Protocol-closure roadmap

The following work remains before this repository can publish a
protocol-complete comparative benchmark. These are evidence milestones, not
claims about the current package:

1. **Multilingual matrix:** add independently reviewed prompts and matched
   controls for another Latin-script language, Arabic or Persian, an Indic
   language, Chinese, and Korean. Record language, script, locale, tokenizer,
   and detector-token length per sample; report every stratum, including
   failures and abstentions.
2. **Task registry:** add factual QA, summarization, translation, code,
   mathematics, and structured-data tasks with pre-registered correctness
   checks. Keep open-ended prose as its own task rather than treating one prompt
   collection as representative of all generated text.
3. **Human-control corpus:** construct license-compatible, time-matched,
   domain-matched human controls that never pass through the generator or
   rewrite model. Publish selection rules and document contamination and
   memorization risks without redistributing restricted text.
4. **Blinded review packets:** export randomized source/candidate pairs without
   method labels, collect semantic, factual, fluency, and formatting judgments,
   and report reviewer eligibility, exclusions, agreement, and uncertainty.
   Human review supplements task checks; it does not replace them.
5. **Held-out-key evaluation:** register disjoint tuning and final-test keys or
   configurations for every key-based scheme. Attacks, thresholds, prompts, and
   model selection must be frozen before final keys are revealed. Known-key and
   held-out-key results must be reported separately.
6. **Reference and cross-detector runs:** pin independent adapters for each
   claimed scheme, run the registered cross-detector matrix, and publish
   content-addressed manifests plus aggregate JSON. Internal reference schemes
   remain development fixtures, not external validation.
7. **Independent replication:** have a separate operator reproduce the frozen
   run from the published command or container and attach a signed replication
   record before using comparative or best-in-class language.

Progress against these items should be reflected in the compliance matrix in
[`BENCHMARK_PROTOCOL.md`](BENCHMARK_PROTOCOL.md). A code path counts as
implemented coverage; only a completed, inspectable run counts as evidence.

## Comparison boundary

`guillaumemeyer/watermarks-remover` has a substantially broader product surface:
file routing, image regeneration, C2PA/EXIF/XMP/document metadata, an HTTP
service, Docker images, and operational hardening. This package is designed to
be deeper specifically on statistical text attacks and defensible measurement.
It should not claim overall superiority without implementing and testing those
non-text capabilities too.

# Step-function implementation plan and status

## Threat model

This package operates on text supplied after generation. It has no access to a
provider's private watermark key, detector, generation history, or retrieval
database. A result therefore means only that a named detector score changed at
a named operating point while configured quality constraints passed.

Anthropic now confirms embedded text marking for supported Claude models
launched on or after August 2, 2026, but has not published its text algorithm,
keys, detector, threshold, or technical verification guidance. Claude must
therefore return an `unsupported` detection outcome, with capability metadata
status `unsupported_pending_spec`; Unicode cleanup or generic rewriting cannot
substantiate a Claude-removal claim. Claude, Gemini, reference SynthID, OpenAI,
and other vendor surfaces must not be presented as interchangeable watermark
algorithms.

## Implemented step-function changes

- Safe Unicode sanitation is the default. Compatibility folding and UTS #39
  skeleton replacement are isolated behind the explicitly lossy `aggressive`
  profile. Forensics remains non-mutating.
- The built-in [BIRA](https://arxiv.org/abs/2509.23019)-style approximation uses a self-information proxy
  suppression set, negative logit bias, bounded retries, adaptive bias backoff,
  repetition checks, and deterministic quality-gated acceptance. It is not the
  authors' reference implementation.
- The built-in [SIRA](https://arxiv.org/abs/2505.05190)-inspired approximation masks a proportional set of
  high-self-information tokens, produces a separate reference rewrite,
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
report confidence intervals, and pair every detection result with
semantic/factual quality results. The harness requires at least 20 expected
tail events in both matched-null samples and independent clusters for a stable
empirical estimate: 20,000 at 0.1% FPR and 2,000,000 at 1e-5 FPR. Smaller
populations may establish only threshold estimability, not stable-tail evidence;
a separately justified exact null distribution is the alternative.

## Quality upgrades for consequential deployments

The dependency-free gates catch catastrophic corruption. Higher-stakes use can
now configure fail-closed bidirectional NLI, claim extraction plus QA
consistency, entity linking, citation grounding, task contracts,
code/markup-aware protection, blinded human review, and a judge independent of
the rewrite model. These are intentionally pluggable evaluation concerns rather
than hard dependencies of the text-cleaning core; public claims still require
calibrated reference configurations and human validation.

## Protocol-closure evidence work

The source tree now contains the canonical registries, full-matrix validator,
content-free observation assembler, fixed-FPR cluster inference, blinded-review
packet tooling, resource accounting, immutable evidence/replay CLI, and
replication schema. Those code paths close the tooling gaps; they do not create
the real data or evidence. The following experiments and independent work
remain before this repository can publish a protocol-complete comparison:

1. **Publish the multilingual matrix:** supply independently reviewed prompts
   and matched controls for another Latin-script language, Arabic or Persian,
   an Indic language, Chinese, and Korean. Record language, script, locale,
   tokenizer, and detector-token length per sample; report every stratum,
   including failures and abstentions.
2. **Populate the canonical task registry:** supply factual QA, summarization,
   translation, code, mathematics, and structured-data inputs plus the
   registered correctness checks. The assembler already refuses incomplete
   final-test task/language/length/control cells.
3. **Publish a human-control selection manifest:** construct
   license-compatible, time-matched, domain-matched human controls that never
   pass through the generator or rewrite model. Publish selection rules and
   document contamination and memorization risks without redistributing
   restricted text.
4. **Run blinded review:** use the implemented consent-gated packet/key split,
   collect semantic, factual, fluency, and formatting judgments, and publish
   only its content-free agreement manifest. Human review supplements task
   checks; it does not replace them.
5. **Execute held-out-key evaluation:** register disjoint tuning and final-test
   keys or configurations for every key-based scheme. Attacks, thresholds,
   prompts, and model selection must be frozen before final keys are revealed.
   Known-key and held-out-key results must be reported separately.
6. **Execute reference and cross-detector runs:** pin independent adapters for
   each claimed scheme, run the registered cross-detector matrix, and publish
   content-addressed manifests plus aggregate JSON. Internal reference schemes
   remain development fixtures, not external validation.
7. **Obtain independent replication:** have a separate operator use
   `dewatermark-evidence replay`, publish the reproduced bundle, and attach a
   cross-bound replication record. A detached signature digest may be declared,
   but signature verification remains the publisher's external responsibility.
   Do this before comparative language. “Best” additionally requires a frozen
   comparator registry and multiplicity-aware analysis.

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

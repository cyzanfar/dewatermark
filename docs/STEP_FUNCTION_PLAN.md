# Step-function implementation plan and status

## Threat model

This package operates on text supplied after generation. It has no access to a
provider's private watermark key, detector, generation history, or retrieval
database. A result therefore means only that a named detector score changed at
a named operating point while configured quality constraints passed.

There is no publicly documented Claude-specific text-watermark scheme. Claude,
Anthropic, Gemini, SynthID, OpenAI, and other vendor names must not be presented
as interchangeable watermark algorithms.

## Implemented step-function changes

- Safe Unicode sanitation is the default. Compatibility folding and UTS #39
  skeleton replacement are isolated behind the explicitly lossy `aggressive`
  profile. Forensics remains non-mutating.
- BIRA uses a self-information proxy suppression set, negative logit bias,
  bounded retries, adaptive bias backoff, repetition checks, and deterministic
  quality-gated acceptance.
- SIRA masks a proportional set of high-self-information tokens, produces an
  independent reference rewrite, performs reference-assisted infill, and rejects
  unresolved or quality-failing output.
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

## Comparison boundary

`guillaumemeyer/watermarks-remover` has a substantially broader product surface:
file routing, image regeneration, C2PA/EXIF/XMP/document metadata, an HTTP
service, Docker images, and operational hardening. This package is designed to
be deeper specifically on statistical text attacks and defensible measurement.
It should not claim overall superiority without implementing and testing those
non-text capabilities too.

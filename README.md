# dewatermark

[![PyPI version](https://img.shields.io/pypi/v/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![Python versions](https://img.shields.io/pypi/pyversions/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![CI](https://github.com/cyzanfar/dewatermark/actions/workflows/ci.yml/badge.svg)](https://github.com/cyzanfar/dewatermark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Remove Unicode text watermarks and mitigate published statistical LLM
watermarks with quality-constrained rewriting.

It does **not** claim to remove an Anthropic/Claude-specific watermark. Anthropic
has not publicly documented a deployed Claude text-watermark scheme or detector.
Unknown vendor systems, provider-side retrieval, and semantic provenance may
remain detectable after rewriting.

## What it does

- Removes unambiguous zero-width, tag-block, variation-selector, and exotic-space
  covert channels with a deterministic safe profile.
- Offers explicitly lossy compatibility and cross-script confusable folding for
  Latin-oriented text through the aggressive profile.
- Mitigates published statistical watermark families through local or explicitly
  authorized remote rewriting, with deterministic quality gates and fallbacks.
- Provides forensic analysis, dry-run planning, batch and async APIs, a provider
  extension system, and a matched-control evaluation harness.

Unicode cleanup is deterministic. Statistical mitigation depends on the named
scheme, detector, model, configuration, text length, and quality constraint.

## Install

The current stable release is
[v0.3.0](https://github.com/cyzanfar/dewatermark/releases/tag/v0.3.0):

```bash
pip install dewatermark
pip install "dewatermark[local]"   # local self-information scorer + BIRA
pip install "dewatermark[eval]"    # evaluation models
```

Install the latest development version from `main` only when you need unreleased
changes:

```bash
pip install "git+https://github.com/cyzanfar/dewatermark.git"
```

## Quickstart

```python
import dewatermark

text = "he\u200bllo"

# Safe by default: removes unambiguous covert controls without folding valid
# emoji shaping, RTL controls, compatibility characters, or confusables.
clean = dewatermark.sanitize(text)
forensics = dewatermark.analyze(text)

result = dewatermark.remove(text, mode="auto")
print(result.cleaned_text)
print(result.report)

# Explicitly lossy Latin-text canonicalization:
canonical = dewatermark.sanitize(text, profile="aggressive")
```

Model downloads are also opt-in. Preload one explicitly with
`dewatermark download-model`, or set `allow_model_download=True` when constructing
a configuration.

## Command line and agents

The CLI never prompts and supports stdin, stable JSON, JSONL batches, dry runs,
and capability discovery:

```bash
printf 'he\u200bllo' | dewatermark sanitize --format json
dewatermark capabilities
dewatermark remove --mode auto --dry-run --format json
dewatermark remove --mode sanitize --format jsonl < requests.jsonl
dewatermark schema
```

Python callers can inspect `dewatermark.capabilities()` and
`dewatermark.plan(mode)` without network access, model loading, or downloads.
`remove_many()` preserves batch order and `aremove()` integrates with async agent
runtimes. Results carry a versioned JSON schema with explicit status, backend,
fallback, warnings, and stage details.

Remote processing is deny-by-default because source text may be sensitive:

```python
from dewatermark import Dewatermark, DewatermarkConfig

dw = Dewatermark(DewatermarkConfig(
    lm_backend="fireworks",
    fireworks_api_key="fw-...",
    allow_remote_processing=True,
))
result = dw.remove(text, mode="bias_inversion", beta=6.0)
```

## Removal modes

- `sanitize`: Unicode cleanup only. `safe` is the default profile;
  `aggressive` enables lossy NFKC/confusable folding.
- `bias_inversion`: BIRA-style surprisal proxy set, negative logit bias,
  adaptive bias backoff/restarts, and deterministic quality gates.
- `sira`: proportional self-information masking, reference rewrite, targeted
  infill, and quality-gated acceptance.
- `paraphrase` / `full`: structural and cross-lingual rewriting baselines.
- `adversarial`: best-of-N SIRA candidates. Its surprisal score is a weak
  selection heuristic, not proof that a watermark was removed.
- `auto`: BIRA first, quality/failure-aware fallback to paraphrasing, then
  sanitize-only when no rewrite backend is usable.

Long inputs are split at paragraph/sentence boundaries and reconstructed
exactly at chunk boundaries. Local models use CUDA/MPS automatically when
available. A 7B–14B instruction model is recommended for rewrite quality; the
0.5B default demonstrates the mechanism but should not be expected to reproduce
published attack results.

## Safety and quality behavior

Every generated candidate is rejected if it is empty, truncated/expanded past
configured bounds, repetitive, contains mask placeholders, or drops numbers,
URLs, email addresses, or quoted strings. These deterministic checks catch
catastrophic failures but do not prove semantic equivalence; production users
should add NLI, claim-QA, and human review for consequential content.

Important configuration:

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `DEWATERMARK_LM_BACKEND` | `auto` | `local`, `fireworks`, or automatic selection |
| `DEWATERMARK_LOCAL_LM` | `Qwen/Qwen2.5-0.5B-Instruct` | Local scorer/rewriter |
| `DEWATERMARK_ALLOW_MODEL_DOWNLOAD` | `false` | Explicit model acquisition consent |
| `DEWATERMARK_FIREWORKS_AI_API_KEY` | — | Fireworks scorer/rewriter |
| `DEWATERMARK_LLM_API_KEY` | — | OpenAI-compatible paraphrase/SIRA endpoint |
| `DEWATERMARK_ALLOW_REMOTE_PROCESSING` | `false` | Consent to transmit source text |
| `DEWATERMARK_SANITIZE_PROFILE` | `safe` | `safe` or explicitly lossy `aggressive` |
| `DEWATERMARK_MAX_CHUNK_CHARS` | `12000` | Rewrite chunk bound |
| `DEWATERMARK_MAX_INPUT_CHARS` | `1000000` | Per-request input bound |
| `DEWATERMARK_MAX_REMOTE_CALLS` | `16` | Per-operation remote-call budget |
| `DEWATERMARK_MAX_OUTPUT_TOKENS` | `2048` | Generated-token budget |
| `DEWATERMARK_MAX_CONCURRENCY` | `4` | Batch worker bound |
| `DEWATERMARK_REQUEST_TIMEOUT` | `120` | Per-request timeout ceiling |
| `DEWATERMARK_QUALITY_MIN_LENGTH_RATIO` | `0.70` | Candidate acceptance bound |
| `DEWATERMARK_QUALITY_MAX_LENGTH_RATIO` | `1.35` | Candidate acceptance bound |

Unprefixed v0.2 names remain compatibility aliases during the 0.3 release line.

## Evaluation

The harness uses matched transformed nulls, refuses to estimate an empirical FPR
without at least `ceil(1/FPR)` null samples, provides confidence intervals, and
supports length sweeps. Independent official implementations can be connected
through the JSON command-adapter contract in `eval/adapters.py`.

```bash
dewatermark-eval --skip-statistical --output results.md

# Expensive research run. 1e-5 FPR is deliberately reported as not estimable
# unless at least 100,000 matched nulls are supplied.
DEWATERMARK_ALLOW_REMOTE_PROCESSING=true dewatermark-eval \
  --samples 100 --null-samples 1000 \
  --lengths 100,250,500,1000,2000 \
  --modes bias_inversion,sira,full \
  --model-revision MODEL_COMMIT --allow-model-download \
  --json-output results.json --checkpoint progress.jsonl
```

The [evaluation guide](eval/README.md) and
[research plan](docs/STEP_FUNCTION_PLAN.md) explain the evidence requirements and
why no universal efficacy result is claimed. The runner uses strict failure
handling by default and records configuration, package versions, hardware,
prompt hashes, checkpoints, and machine-readable results.

## Extending and contributing

Third-party scorers and rewriters can implement the structural interfaces in
`dewatermark.protocols`, register in-process, or publish through the
`dewatermark.providers` entry-point group. See [extension documentation](docs/EXTENSIONS.md),
[architecture](docs/ARCHITECTURE.md), and [contributor guide](CONTRIBUTING.md).

## Scope limitations

- No public Claude-specific scheme is available to target or verify.
- Retrieval-based provenance cannot be removed from text.
- Token surprisal does not reliably identify semantic, post-processing,
  cryptographic, learned, or undisclosed watermarks.
- Detector success must be stated for a named scheme, key/configuration,
  operating threshold, text length, and quality constraint—not as universal
  “watermark removal.”

## License

The package code is MIT-licensed; see [LICENSE](LICENSE). The generated
confusables table incorporates Unicode data distributed under the
[Unicode License v3](UNICODE_LICENSE.txt).

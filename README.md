# dewatermark — Text Watermark Remover and Assurance Toolkit

[![PyPI version](https://img.shields.io/pypi/v/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![Python versions](https://img.shields.io/pypi/pyversions/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![CI](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/cyzanfar/text-watermark-remover?style=social)](https://github.com/cyzanfar/text-watermark-remover/stargazers)

**Detect and remove hidden Unicode text-watermark artifacts locally, then
evaluate named statistical LLM-watermark mitigations with explicit detectors,
quality gates, and reproducible evidence.** Use it from Python, the CLI,
pre-commit, GitHub code scanning, HTTP/OpenAPI, Docker, or an MCP-compatible AI
agent.

[Try the private browser playground](https://cyzanfar.github.io/text-watermark-remover/)
· [Install from PyPI](https://pypi.org/project/dewatermark/)
· [Explore integrations](docs/INTEGRATIONS.md)

If this saves you time, consider [starring the repository](https://github.com/cyzanfar/text-watermark-remover)—it helps other developers find a careful alternative to unverifiable universal-removal claims.

Anthropic now [confirms embedded text marking](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content)
for supported models launched on or after August 2, 2026, but says technical
detection guidance is forthcoming. `dewatermark` therefore reports Claude as
`unsupported_pending_spec`: it does **not** pretend that Unicode cleanup or a
generic paraphrase removed a Claude watermark. Unknown vendor systems,
provider-side retrieval, and semantic provenance may remain detectable.

## What it does

- Classifies each suspicious code point as actionable, contextual, or
  informational before applying a context-aware safe Unicode policy.
- Offers explicitly lossy compatibility and cross-script confusable folding for
  Latin-oriented text through the aggressive profile.
- Separates `detected`, `transformed`, and `verified` outcomes so a changed
  string is never silently represented as proof of removal.
- Uses content-bound `inspect -> plan -> apply -> verify` operations, explicit
  consent, request-wide budgets, central quality gates, and content-free
  evidence receipts.
- Connects pinned independent detectors through a bounded JSON-command adapter
  with static manifests and golden-vector conformance tests.
- Provides forensic analysis, reversible edit manifests, batch and async APIs,
  a provider extension system, and a matched-control evaluation harness.
- Scans repositories, emits SARIF, and integrates with pre-commit, HTTP/OpenAPI,
  Docker, and MCP-compatible AI agents.

## What “removed” means

| Outcome | Defensible interpretation |
| --- | --- |
| `unicode_sanitized` | Literal artifacts covered by the versioned Unicode policy were cleared |
| `mitigation_verified` | A named, calibrated, independent detector was positive before, below its registered threshold after, and every configured quality gate passed |
| `mitigation_unverified` | Text changed and passed gates, but compatible independent verification was unavailable |
| `unsupported_scheme` | The requested private or incompatible scheme cannot currently be tested |
| `rejected_quality` | Generated candidates were discarded; the source was retained |

None of these outcomes classifies authorship or proves that text is universally
watermark-free. See the [assurance model](docs/ASSURANCE.md) and
[detector policy](docs/DETECTORS.md).

## Scoped deterministic fixture evidence

The deterministic aggressive-profile fixture benchmark removes all 50 embedded
payloads across five Unicode covert-channel families.

| Fixture family | Removed |
| --- | ---: |
| Zero-width binary | 10/10 |
| Variation selectors | 10/10 |
| Tags block | 10/10 |
| Cross-script homoglyphs | 10/10 |
| Exotic spaces | 10/10 |
| **Total** | **50/50** |

See the provenance-limited historical [tracked report](benchmarks/unicode-v0.4.md)
and rerun the current harness with
`PYTHONPATH=src python eval/run_eval.py --skip-statistical`. This fixture result
is not evidence about statistical or undisclosed vendor watermarks.

Unicode cleanup is deterministic. Statistical mitigation depends on the named
scheme, detector, model, configuration, text length, and quality constraint.

## Install

```bash
pip install dewatermark
pip install "dewatermark[local]"   # local self-information scorer + BIRA
pip install "dewatermark[eval]"    # evaluation models
pip install "dewatermark[agents]"  # MCP server on Python 3.10+
```

Install `main` only when you intentionally want unreleased changes:

```bash
pip install "git+https://github.com/cyzanfar/text-watermark-remover.git"
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
print(result.report.transformation_status)
print(result.receipt.claim_scope)

# Explicitly lossy Latin-text canonicalization:
canonical = dewatermark.sanitize(text, profile="aggressive")
```

Model downloads are also opt-in. Preload one explicitly with
`dewatermark download-model`, or set `allow_model_download=True` when constructing
a configuration.

For automation, use the content-bound two-phase API:

```python
from dewatermark import apply_plan, create_plan, inspect_text, verify_text

inspection = inspect_text(text, detector="unicode")
reviewed = create_plan(text, mode="sanitize", detector="unicode")
applied = apply_plan(
    text,
    reviewed["plan_digest"],
    mode="sanitize",
    detector="unicode",
    consent=True,
)
verification = verify_text(text, applied["result"]["cleaned_text"])
```

The SHA-256 plan digest binds the input, mode, detector, options, permissions,
quality policy, model identifiers, resource bounds, and verification policy. It
is an integrity binding, not an authentication signature.

## Command line and agents

The CLI never prompts and supports stdin, stable JSON, JSONL batches, dry runs,
and capability discovery:

```bash
printf 'he\u200bllo' | dewatermark sanitize --format json
dewatermark capabilities
dewatermark inspect --input input.txt
dewatermark plan --input input.txt --mode sanitize
dewatermark apply --input input.txt --mode sanitize --plan-digest DIGEST --consent
dewatermark verify --source-input input.txt --candidate-input output.txt
dewatermark remove --mode sanitize --format jsonl < requests.jsonl
dewatermark schema
dewatermark check .
dewatermark check . --format sarif --output dewatermark.sarif
dewatermark serve                    # local HTTP + OpenAPI
dewatermark-mcp                      # MCP stdio server
```

Python callers can inspect `dewatermark.capabilities()` and create a content-bound
plan without network access, model loading, plugin imports, or downloads.
`remove_many()` preserves batch order and `aremove()` integrates with async agent
runtimes. Results carry a versioned JSON schema with explicit status, backend,
fallback, warnings, and stage details.

## Repository scanning

`dewatermark check` reports exact files, lines, columns, categories, and code
points. Contextual and known-legitimate observations are opt-in with
`--all-findings`; the default reports actionable evidence. It never modifies
files unless `--fix` is passed explicitly. Fixes are atomic and include a
reversible edit manifest. Baselines, suppressions, and unified-diff filtering
keep repository adoption practical. SARIF output
can appear as annotations in GitHub code scanning, and the included pre-commit
hook blocks hidden characters before they enter a commit. See the
[integration recipes](docs/INTEGRATIONS.md).

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

The BIRA/SIRA modes are experimental proxy implementations, not drop-in
reproductions of every paper or proof against a vendor deployment. Use a pinned
external detector adapter for any efficacy claim.

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
| `DEWATERMARK_DETECTOR_PROVIDER` | — | Named detector for scoped verification |
| `DEWATERMARK_REQUIRE_VERIFIED` | `false` | Reject statistical candidates without compatible verification |
| `DEWATERMARK_MAX_REMOTE_CALLS` | `16` | Request-wide physical HTTP-attempt budget; `0` disables remote calls |
| `DEWATERMARK_MAX_OUTPUT_TOKENS` | `2048` | Generated-token budget |
| `DEWATERMARK_MAX_CONCURRENCY` | `4` | Batch worker bound |
| `DEWATERMARK_MAX_BATCH_ITEMS` | `1000` | Maximum items accepted by one batch call |
| `DEWATERMARK_RANDOM_SEED` | `13` | Recorded reproducibility seed |
| `DEWATERMARK_REQUEST_TIMEOUT` | `120` | Per-request timeout ceiling |
| `DEWATERMARK_QUALITY_MIN_LENGTH_RATIO` | `0.70` | Candidate acceptance bound |
| `DEWATERMARK_QUALITY_MAX_LENGTH_RATIO` | `1.35` | Candidate acceptance bound |

Unprefixed v0.2 names remain deprecated compatibility aliases; new integrations
should use the `DEWATERMARK_*` names.

## Evaluation

The harness uses matched transformed nulls, refuses to estimate an empirical FPR
without at least `ceil(1/FPR)` null samples, provides confidence intervals, and
supports length sweeps. Independent official implementations can be connected
through the JSON command-adapter contract in `eval/adapters.py`.

```bash
dewatermark-eval --skip-statistical --output results.md

# Expensive research run. 1e-5 FPR is deliberately reported as not estimable
# unless at least 100,000 matched nulls are supplied.
dewatermark-eval --allow-network \
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
Independent detectors can use the versioned
[`CommandDetector`](docs/DETECTORS.md) protocol, which executes tuple argv with
`shell=False`, bounds time/stdout/stderr, redacts failures, and verifies pinned
configuration and golden vectors.

Good first contributions include detector adapters, editor integrations,
Unicode fixtures from real systems, and benchmark replications. Review the
[roadmap](ROADMAP.md) or open a
[feature proposal](https://github.com/cyzanfar/text-watermark-remover/issues/new/choose).

## How this differs from broad “watermark remover” projects

`dewatermark` deliberately goes deep on **text evidence**. For example,
[`guillaumemeyer/watermarks-remover`](https://github.com/guillaumemeyer/watermarks-remover)
also handles images, files, EXIF/XMP/C2PA, and document metadata; this package
does not. Its differentiator is detector-scoped text outcomes, contextual
Unicode safety, central acceptance gates, agent consent flows, evidence
receipts, and statistically disciplined evaluation. Choose or combine tools
according to the artifact surface you actually need.

## Scope limitations

- Claude text marking is confirmed, but its public technical detector and
  verification procedure are not yet available.
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

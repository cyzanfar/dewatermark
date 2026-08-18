# dewatermark — Text Watermark Remover and Assurance Toolkit

[![PyPI version](https://img.shields.io/pypi/v/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![Python versions](https://img.shields.io/pypi/pyversions/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![CI](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cyzanfar/text-watermark-remover/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/cyzanfar/text-watermark-remover?style=social)](https://github.com/cyzanfar/text-watermark-remover/stargazers)

**Detect and remove hidden Unicode text-watermark artifacts locally, then
evaluate named statistical LLM-watermark mitigations with explicit detectors,
quality gates, and reproducible evidence.** Use it from Python, the CLI,
pre-commit, GitHub code scanning, HTTP/OpenAPI, Docker, or an MCP-compatible AI
agent.

[Try the private browser playground](https://cyzanfar.github.io/text-watermark-remover/)
· [Install from PyPI](https://pypi.org/project/dewatermark/)
· [Explore integrations](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/INTEGRATIONS.md)

If this saves you time, consider [starring the repository](https://github.com/cyzanfar/text-watermark-remover)—it helps other developers find a careful alternative to unverifiable universal-removal claims.

> **Development status:** this README documents the unreleased `0.6.0` source
> tree. The PyPI badge points to the latest published stable version. Until a
> `v0.6.0` tag exists, install `main` only if you intentionally want the release
> candidate.

Anthropic now [confirms embedded text marking](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content)
for supported models launched on or after August 2, 2026, but says technical
detection guidance is forthcoming. `dewatermark` therefore reports Claude as
an `unsupported` detection outcome, with capability metadata status
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
- Connects operator-supplied, pinned independent detectors through a bounded
  JSON-command adapter with static manifests and golden-vector conformance
  tests.
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
watermark-free. See the [assurance model](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/ASSURANCE.md) and
[detector policy](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/DETECTORS.md).

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

See the provenance-limited historical [tracked report](https://github.com/cyzanfar/text-watermark-remover/blob/main/benchmarks/unicode-v0.4.md)
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

The zero-dependency browser sanitizer is packaged for npm as an ESM module.
Until the first registry release, build the exact package from a checkout:

```bash
mkdir -p /tmp/dewatermark-npm
npm pack ./web --pack-destination /tmp/dewatermark-npm
cd /path/to/your-app
npm install /tmp/dewatermark-npm/cyzanfar-dewatermark-unicode-0.6.0.tgz
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
quality policy, model identifiers, resource bounds, verification policy, and
observable extension identity/state. The extension binding is checked again
before first use, and equivalent requests produce a stable digest across fresh
CLI processes. The state fingerprint is a one-way content commitment, not
secret storage. The plan digest is an integrity binding, not an authentication
signature or a sandbox for trusted in-process Python.

## Command line and agents

The CLI never prompts and supports stdin, stable JSON, JSONL batches, dry runs,
and capability discovery:

```bash
printf 'he\u200bllo' | dewatermark sanitize --format json
dewatermark capabilities
dewatermark detectors list          # static, side-effect-free inventory
dewatermark detectors doctor        # audit pins and claim boundaries
dewatermark detectors conformance   # run synthetic golden vectors
dewatermark detectors packs         # inspect pinned external adapter packs
dewatermark inspect --input input.txt
dewatermark plan --input input.txt --mode sanitize
dewatermark apply --input input.txt --mode sanitize --plan-digest DIGEST --consent
dewatermark verify --source-input input.txt --candidate-input output.txt
dewatermark remove --mode sanitize --format jsonl < requests.jsonl
dewatermark schema
dewatermark check .
dewatermark check . --format sarif --output dewatermark.sarif
dewatermark check --stdin-path src/app.py --format json < unsaved-buffer.txt
dewatermark serve                    # local HTTP + OpenAPI
dewatermark-mcp                      # MCP stdio server
dewatermark skill path               # locate the bundled agent workflow
dewatermark skill install --output ./remove-text-watermarks
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
[integration recipes](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/INTEGRATIONS.md).

Teams can commit a `.dewatermark.toml` policy (or use
`[tool.dewatermark.scan]` in `pyproject.toml`) so the same extensions,
cross-platform excludes, size bounds, dispositions, and suppressions apply on
developer machines and in editor plugins, pre-commit, and CI:

```toml
[scan]
exclude = ["generated/**", "fixtures/intentional/**"]
extensions = ["py", "js", "ts", "md", "txt"]
max_file_bytes = 2000000
dispositions = ["actionable"]
```

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
- `bias_inversion`: [BIRA](https://arxiv.org/abs/2509.23019)-style surprisal proxy set, negative logit bias,
  adaptive bias backoff/restarts, and deterministic quality gates.
- `sira`: [SIRA](https://arxiv.org/abs/2505.05190)-inspired proportional self-information masking, reference rewrite, targeted
  infill, and quality-gated acceptance.
- `paraphrase` / `full`: structural and cross-lingual rewriting baselines.
- `adversarial`: best-of-N SIRA candidates. Its surprisal score is a weak
  selection heuristic, not proof that a watermark was removed.
- `auto`: BIRA first, quality/failure-aware fallback to paraphrasing, then
  sanitize-only when no rewrite backend is usable.

The BIRA/SIRA modes are experimental proxy implementations, not drop-in
reproductions of every paper or proof against a vendor deployment. Use a pinned
external detector adapter for any efficacy claim.

## Detector lab

`dewatermark detectors` separates three things that are often blurred together:

- dependency-free KGW-, Unigram-, and tournament-style **synthetic fixtures**
  that validate integration and abstention behavior but are neither calibrated
  nor production detectors;
- a pinned upstream KGW token-ID adapter pack with real upstream golden-vector
  conformance, still deliberately uncalibrated and not a natural-language
  detector; and
- a fail-closed SynthID Text manifest template that cannot claim support until
  an operator supplies exact keys, tokenizer, configuration, calibration, and
  independent conformance evidence.

Use `dewatermark detectors scaffold --pack kgw --output ./kgw-adapter` to copy
a pack without overwriting anything. See the
[reference detector guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/REFERENCE_DETECTORS.md). A green fixture is a
contract test—not an efficacy result.

Long inputs are split at paragraph/sentence boundaries and reconstructed
exactly at chunk boundaries. Local models use CUDA/MPS automatically when
available. A 7B–14B instruction model is recommended for rewrite quality; the
0.5B default demonstrates the mechanism but should not be expected to reproduce
published attack results.

## Safety and quality behavior

Every generated candidate is rejected if it is empty, truncated/expanded past
configured bounds, repetitive, contains mask placeholders, or drops numbers,
URLs, email addresses, quoted strings, citations, or protected structure.
Optional typed gates add bidirectional NLI, atomic claim/QA, entity linking,
citation grounding, and task-contract checks. Required gates fail closed when
their adapter is unavailable, malformed, over budget, or cannot account for its
work. The package never downloads a learned quality model implicitly; use a
pinned cached model or your own calibrated adapter, and retain human review for
consequential text. See the [quality-gate guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/QUALITY_GATES.md).

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
without at least `ceil(1/FPR)` null samples, and labels a tail estimate stable
only with at least `20 * ceil(1/FPR)` null samples and independent clusters. It
provides confidence intervals and length sweeps. Independent official
implementations can be connected through the JSON command-adapter contract in
`eval/adapters.py`.

```bash
run_dir=$(mktemp -d)
dewatermark-eval --skip-statistical \
  --output "$run_dir/results.md" \
  --checkpoint "$run_dir/progress.jsonl"

# Exploratory statistical run. A 1e-5 FPR is not estimable below 100,000
# matched nulls and is not labelled stable below 2,000,000 independent null
# samples and clusters.
dewatermark-eval --allow-network \
  --samples 100 --null-samples 1000 \
  --lengths 100,250,500,1000,2000 \
  --modes bias_inversion,sira,full \
  --model-revision MODEL_COMMIT --allow-model-download \
  --json-output "$run_dir/results.json" \
  --checkpoint "$run_dir/statistical-progress.jsonl"
```

Checkpoints are append-protected. Reuse one only with `--resume`; otherwise
choose a fresh output directory as above.

The [evaluation guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/eval/README.md) and
[research plan](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/STEP_FUNCTION_PLAN.md) explain the evidence requirements and
why no universal efficacy result is claimed. The runner uses strict failure
handling by default and records configuration, package versions, hardware,
prompt hashes, checkpoints, and machine-readable results.

## Extending and contributing

Third-party scorers and rewriters can implement the structural interfaces in
`dewatermark.protocols`, register in-process, or publish through the
`dewatermark.providers` entry-point group. See [extension documentation](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/EXTENSIONS.md),
[architecture](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/ARCHITECTURE.md), and [contributor guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/CONTRIBUTING.md).
Independent detectors can use the versioned
[`CommandDetector`](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/DETECTORS.md) protocol, which executes tuple argv with
`shell=False`, bounds time/stdout/stderr, redacts failures, and verifies pinned
configuration and golden vectors.

Good first contributions include detector adapters, editor integrations,
Unicode fixtures from real systems, and benchmark replications. Review the
[roadmap](https://github.com/cyzanfar/text-watermark-remover/blob/main/ROADMAP.md) or open a
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

The package code is MIT-licensed; see [LICENSE](https://github.com/cyzanfar/text-watermark-remover/blob/main/LICENSE). The generated
confusables table incorporates Unicode data distributed under the
[Unicode License v3](https://github.com/cyzanfar/text-watermark-remover/blob/main/UNICODE_LICENSE.txt).

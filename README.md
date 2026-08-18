# dewatermark — Text Watermark Remover for Hidden Unicode

[![PyPI version](https://img.shields.io/pypi/v/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![Python versions](https://img.shields.io/pypi/pyversions/dewatermark.svg)](https://pypi.org/project/dewatermark/)
[![CI](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/cyzanfar/text-watermark-remover/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cyzanfar/text-watermark-remover/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/cyzanfar/text-watermark-remover?style=social)](https://github.com/cyzanfar/text-watermark-remover/stargazers)

`dewatermark` is a Python text watermark remover for suspicious hidden Unicode
characters. It can clean one string or scan a whole repository. Basic cleanup
runs locally, gives the same result every time, and needs no model or network
connection.

For statistical LLM watermarks, it can run experiments and check the result
with a detector built for that watermark. It never treats changed text as proof
that every watermark is gone, and it does not claim to remove a vendor
watermark when no compatible detector is available.

[Try the browser playground (text stays in your browser)](https://cyzanfar.github.io/text-watermark-remover/)
· [View on PyPI](https://pypi.org/project/dewatermark/)
· [Explore integrations](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/INTEGRATIONS.md)

> **Development version:** this page describes the unreleased `0.6.0` source.
> Install the current source as shown below to use these exact APIs. Until
> `v0.6.0` is published, `python -m pip install dewatermark` installs the latest
> stable release, whose API is older.

## Install

Python 3.9 or newer is required. Install the version documented on this page:

```bash
python -m pip install "git+https://github.com/cyzanfar/text-watermark-remover.git"
dewatermark --version
```

The core package includes Unicode cleanup, analysis, repository scanning, and
the CLI. After `v0.6.0` is released, the normal stable install will be:

```bash
python -m pip install dewatermark
```

Optional features can be installed from a source checkout:

```bash
python -m pip install -e ".[local]"   # local model-backed rewriting
python -m pip install -e ".[eval]"    # research and evaluation tools
python -m pip install -e ".[agents]"  # MCP server; Python 3.10+
```

Models are not downloaded automatically, even when an optional package is
installed.

## Clean hidden Unicode

```python
import dewatermark

text = "he\u200bllo"  # contains an invisible zero-width character
clean = dewatermark.sanitize(text)

print(repr(text))   # 'he\u200bllo'
print(repr(clean))  # 'hello'
```

`sanitize()` returns a string. Its default `safe` profile removes or normalizes
characters covered by the policy while preserving recognized emoji,
right-to-left, and writing-system contexts.

Use `analyze()` when you want to inspect the text without changing it:

```python
report = dewatermark.analyze(text)
print(report)
```

The `aggressive` profile also normalizes compatibility characters and look-alike
letters. It is intentionally lossy, so use it only when that tradeoff is
acceptable:

```python
clean = dewatermark.sanitize(text, profile="aggressive")
```

## Command line

```bash
python -c "print('he\u200bllo', end='')" | dewatermark sanitize
# hello

python -c "print('he\u200bllo', end='')" | dewatermark analyze
dewatermark check .
```

The first command writes cleaned text. `analyze` reports findings without
changing the input. `check` scans files and changes nothing unless you pass
`--fix`; it exits with status `1` when it finds actionable hidden Unicode.

## Choose the right tool

| Goal | Start here |
| --- | --- |
| Remove clearly suspicious Unicode | `sanitize()` or `dewatermark sanitize` |
| Inspect text without changing it | `analyze()` or `dewatermark analyze` |
| Scan a repository | `dewatermark check PATH` |
| Get a JSON-ready report of what changed | `remove(..., mode="sanitize").to_dict()` |
| Try model-backed rewriting | [Statistical LLM watermarks](#statistical-llm-watermarks-advanced) |
| Verify a statistical watermark | [Verify with a detector](#verify-statistical-watermarks-with-a-detector) |
| Review exact text and settings before applying | [Agents and automation](#agents-and-automation) |
| Use editors, CI, HTTP, MCP, or Docker | [Integrations](#integrations) |

## What the results mean

Unicode cleanup and statistical watermark testing are separate operations.

| Result | Meaning |
| --- | --- |
| `unicode_sanitized` | Policy-covered characters were removed or normalized |
| `mitigation_verified` | A named independent detector scored above its tested threshold before rewriting and below it afterward, and every configured quality check passed |
| `mitigation_unverified` | Text changed and passed quality checks, but compatible verification was unavailable |
| `unsupported_scheme` | The requested watermark cannot currently be tested |
| `rejected_quality` | Rewritten candidates failed quality checks, so the original text was kept |

These results do not identify who wrote the text and do not prove that it is
universally watermark-free. See the
[assurance model](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/ASSURANCE.md)
for the full status contract.

## Scan files and repositories

```bash
dewatermark check .
dewatermark check . --fix
dewatermark check . --format sarif --output dewatermark.sarif
```

The scanner reports the file, line, column, Unicode code point, and reason for
each finding. `--fix` modifies files in place using atomic replacement; edit
details are available in the JSON and Python reports. You can share one
`.dewatermark.toml` policy across local development, pre-commit, CI, and the
editor integrations.

See the
[integration guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/INTEGRATIONS.md)
for shared policies, ignore lists, checking only changed lines, pre-commit, and
GitHub code scanning.

## Privacy and safety

- `sanitize`, `analyze`, repository scanning, and listing installed features run
  locally without a learned model.
- Managed model downloads run only after `dewatermark download-model`,
  `allow_model_download=True`, or the matching environment setting.
- Managed remote backends send text only when
  `allow_remote_processing=True` is set separately.
- The default Unicode profile preserves contextual characters. The
  `aggressive` profile may change legitimate text.
- Model-generated rewrites are treated as candidates. They are accepted only
  after the configured quality checks pass.
- Errors and result receipts omit source text and credentials. Configuration
  output also hides credentials. `analyze()` intentionally returns annotated
  input, so treat its output as sensitive.
- Third-party Python extensions are trusted code and keep the permissions of
  the current process; this package is not an operating-system sandbox.

See the
[configuration guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/CONFIGURATION.md)
and [quality-check guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/QUALITY_GATES.md)
for advanced settings.

## Statistical LLM watermarks (advanced)

Removing hidden Unicode is deterministic. Statistical watermark removal is
experimental: the result depends on how the watermark was created, which
detector checks it, and the text being tested.

`remove()` provides several research modes:

- `sanitize` performs Unicode cleanup only.
- `bias_inversion` and `sira` are experimental implementations inspired by the
  [BIRA](https://arxiv.org/abs/2509.23019) and
  [SIRA](https://arxiv.org/abs/2505.05190) papers.
- `paraphrase`, `full`, and `adversarial` provide rewrite baselines.
- `auto` chooses an available mode and falls back safely when a backend cannot
  run.

These modes are not proof against a vendor deployment. Use a compatible,
independent detector for any removal claim. Model downloads and remote text
processing remain disabled until enabled separately.

## Verify statistical watermarks with a detector

```bash
dewatermark detectors list
dewatermark detectors doctor
dewatermark detectors conformance
dewatermark detectors packs
```

The included KGW-, Unigram-, and tournament-style detectors are small test
cases for integration code, not production detectors. The KGW pack checks known
token examples, and the SynthID pack is only a disabled template until its
required configuration and independent tests are supplied.

A passing conformance test means the integration passes its known test cases.
It does not prove that the tool removes a production watermark. See the
[detector guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/DETECTORS.md)
and [reference detector guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/REFERENCE_DETECTORS.md).

### Current Claude limitation

Anthropic has
[confirmed text marking](https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content)
for supported Claude models, but it has not published the detector and
verification procedure needed for an independent test. `dewatermark` therefore
returns `unsupported`; its capability metadata records
`status=unsupported_pending_spec`. It does not claim that Unicode cleanup or a
generic rewrite removes a Claude watermark.

## Agents and automation

Use the review-before-apply API when a person or agent wants to inspect the
exact text and settings before execution:

```python
from dewatermark import apply_plan, create_plan, inspect_text, verify_text

text = "he\u200bllo"
inspection = inspect_text(text, detector="unicode")
plan = create_plan(text, mode="sanitize", detector="unicode")
applied = apply_plan(
    text,
    plan["plan_digest"],
    mode="sanitize",
    detector="unicode",
    consent=True,
)
verification = verify_text(
    text,
    applied["result"]["cleaned_text"],
    detector="unicode",
)

print(inspection["detector_evidence"]["status"])  # detected
print(verification["verification_status"])         # verified_cleared
```

The plan digest changes when the input or approved settings change, so
`apply_plan` rejects stale or mismatched plans. It does not authenticate the
approver or turn third-party Python plugins into sandboxed code.

The same workflow is available through the CLI, HTTP/OpenAPI, and MCP. See the
[agent workflow guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/AGENT_WORKFLOWS.md)
or locate the bundled skill with:

```bash
dewatermark skill path
dewatermark skill install --output ./remove-text-watermarks
```

## Integrations

- **Browser and unreleased npm package:** use the
  [browser playground](https://cyzanfar.github.io/text-watermark-remover/),
  where text stays in the browser, or package the browser module from source.
- **Editors:** local-only VS Code and JetBrains integrations are included.
- **Git hooks and CI:** use pre-commit, the composite GitHub Action, or SARIF
  output for GitHub code scanning.
- **Services and agents:** run the local HTTP/OpenAPI server, MCP stdio server,
  or generated API clients.
- **Containers:** build the non-root Docker image; it does not start a network
  server unless you configure one.

All setup instructions are in the
[integration guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/INTEGRATIONS.md).

## Test results and evaluation

The checked-in Unicode fixture report records 50 of 50 embedded examples
removed across five known hidden-character families using the intentionally
lossy `aggressive` profile. This only tests those examples; it says nothing
about statistical or undocumented vendor watermarks.

The evaluation tools keep setup data separate from final test data and count
errors as failures. No tracked statistical result currently satisfies the full
benchmark protocol.

See the
[Unicode fixture report](https://github.com/cyzanfar/text-watermark-remover/blob/main/benchmarks/unicode-v0.4.md),
[evaluation guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/eval/README.md),
and [benchmark protocol](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/BENCHMARK_PROTOCOL.md).

## Extending and contributing

Rewriting backends, detectors, quality checks, and ways to split long input can
be added without changing the package's core. Start with the
[extension guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/EXTENSIONS.md),
[architecture](https://github.com/cyzanfar/text-watermark-remover/blob/main/docs/ARCHITECTURE.md),
and [contributor guide](https://github.com/cyzanfar/text-watermark-remover/blob/main/CONTRIBUTING.md).

Good first contributions include detector adapters, editor integrations,
Unicode examples from real systems, and independent benchmark replications.
See the [roadmap](https://github.com/cyzanfar/text-watermark-remover/blob/main/ROADMAP.md)
or open a
[feature proposal](https://github.com/cyzanfar/text-watermark-remover/issues/new/choose).

If the project is useful to you, consider
[starring it on GitHub](https://github.com/cyzanfar/text-watermark-remover).

## Scope limits

- The deterministic sanitizer covers known Unicode artifacts, not every
  possible text watermark.
- Statistical results apply only to the named detector and configuration used
  for that run.
- Editing text cannot erase records kept by a model provider or matching
  service.
- This project handles text. It does not remove image watermarks, EXIF/XMP,
  C2PA, or document metadata.
- Claude remains unsupported until a compatible public detector and procedure
  are available.

## License

The package is MIT-licensed; see
[LICENSE](https://github.com/cyzanfar/text-watermark-remover/blob/main/LICENSE).
The generated confusables table includes Unicode data covered by the
[Unicode License v3](https://github.com/cyzanfar/text-watermark-remover/blob/main/UNICODE_LICENSE.txt).

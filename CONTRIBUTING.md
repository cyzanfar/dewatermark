# Contributing

Thank you for improving dewatermark. Contributions should preserve meaning,
privacy defaults, reproducibility, and the distinction between a robustness
experiment and a universal removal claim.

## Development setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check src tests eval adapters scripts examples
.venv/bin/ruff format --check src tests eval adapters scripts examples
.venv/bin/mypy src/dewatermark
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
cd web && npm run check && cd ..
python scripts/export_openapi.py --check
```

No unit test may require network access or an uncached model. Add provider tests
through mocks or contract fixtures. Mark expensive reproducibility runs as
external artifacts rather than unit tests.

Changes under `integrations/` must also run their native package checks:

```bash
cd integrations/vscode && npm ci && npm test && npm run package
cd integrations/jetbrains && ./gradlew --no-daemon \
  --dependency-verification=strict test buildPlugin verifyPlugin
```

If you change the Unicode policy, regenerate the browser table and run the
cross-runtime golden tests:

```bash
node web/generate-policy.mjs --check
python -m pytest tests/test_unicode_cross_runtime.py
```

Represent intentionally suspicious characters in Python test source with
Unicode escapes. CI runs the repository scanner against its own source and
documentation, so a newly introduced literal actionable character fails the
build unless it is deliberately suppressed or baselined.

## Change expectations

- Add tests for behavioral changes and public extension points.
- Update `CHANGELOG.md` under **Unreleased**.
- Keep public results JSON-serializable and schema-versioned.
- Preserve additive schema-1 compatibility; new claim semantics belong in the
  assurance fields rather than redefining legacy `success`.
- Never log source text, credentials, model prompts, or provider responses.
- Keep remote processing and model downloads opt-in.
- Route every transformer candidate through the central quality and detector
  acceptance path.
- Keep capability discovery static and side-effect-free. Loading plugin code is
  an execution step, not a listing step.
- Identify watermark scheme, detector, key/configuration, length, FPR, and
  quality constraints in efficacy claims.

## Detector and transformer contributions

New integrations must include a static capability manifest, a pinned upstream
source and license, golden vectors, deterministic contract tests, and explicit
privacy/resource declarations. Detectors must declare threshold direction,
minimum effective length, calibration provenance, and whether generation and
detection share an implementation.

Heavy or conflicting research stacks should use the JSON command-adapter
boundary. Adapter errors must be redacted; never return raw stderr or provider
response bodies in public reports.

Run `dewatermark detectors doctor` for static claim checks and
`dewatermark detectors conformance` for the bundled synthetic vectors. Passing
those vectors establishes only adapter compatibility. A production detector
also needs a pinned tokenizer/key/configuration, held-out calibration, adequate
matched controls, and an independent replication record.

## Benchmark contributions

Follow [`docs/BENCHMARK_PROTOCOL.md`](docs/BENCHMARK_PROTOCOL.md). Calibration,
attack development, and final testing must use disjoint data. Keep failures and
quality rejections in the denominator, include transformed nulls and false
insertion measurements, and attach the machine-readable manifest used to
produce every table.

Run the offline evidence reference and verify its resulting bundle whenever the
protocol, observation, metric, schema, or replay code changes. A synthetic
reference run proves the tooling contract only; it must never be described as
natural-language detector efficacy.

```bash
evidence_root="$(mktemp -d)"
dewatermark-evidence reference-protocol \
  --output-directory "$evidence_root/source"
dewatermark-evidence verify "$evidence_root/source/evidence.json"
dewatermark-evidence replay "$evidence_root/source/evidence.json" \
  --workspace "$evidence_root/replay" --execute
dewatermark-evidence verify \
  "$evidence_root/replay/reproduced/evidence.json"
```

Public benchmark submissions must validate the sample registry, content-free
observation set, evidence bundle, and replication schemas. Never commit raw
prompts, source/candidate text, private paths, credentials, caches, checkpoints,
or generated result directories.

See `docs/ARCHITECTURE.md` for boundaries and `docs/EXTENSIONS.md` for provider
contracts. Public compatibility is governed by `docs/COMPATIBILITY.md`.

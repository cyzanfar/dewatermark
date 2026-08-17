# Contributing

Thank you for improving dewatermark. Contributions should preserve meaning,
privacy defaults, reproducibility, and the distinction between a robustness
experiment and a universal removal claim.

## Development setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check src tests eval
.venv/bin/mypy src/dewatermark
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

No unit test may require network access or an uncached model. Add provider tests
through mocks or contract fixtures. Mark expensive reproducibility runs as
external artifacts rather than unit tests.

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

## Benchmark contributions

Follow [`docs/BENCHMARK_PROTOCOL.md`](docs/BENCHMARK_PROTOCOL.md). Calibration,
attack development, and final testing must use disjoint data. Keep failures and
quality rejections in the denominator, include transformed nulls and false
insertion measurements, and attach the machine-readable manifest used to
produce every table.

See `docs/ARCHITECTURE.md` for boundaries and `docs/EXTENSIONS.md` for provider
contracts. Public compatibility is governed by `docs/COMPATIBILITY.md`.

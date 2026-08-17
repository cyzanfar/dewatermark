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

## Change expectations

- Add tests for behavioral changes and public extension points.
- Update `CHANGELOG.md` under **Unreleased**.
- Keep public results JSON-serializable and schema-versioned.
- Never log source text, credentials, model prompts, or provider responses.
- Keep remote processing and model downloads opt-in.
- Identify watermark scheme, detector, key/configuration, length, FPR, and
  quality constraints in efficacy claims.

See `docs/ARCHITECTURE.md` for boundaries and `docs/EXTENSIONS.md` for provider
contracts. Public compatibility is governed by `docs/COMPATIBILITY.md`.

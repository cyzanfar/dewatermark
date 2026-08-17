# Changelog

This project follows Semantic Versioning. Public changes are recorded here.

## [0.5.0] - 2026-08-17

- Serialized removal results now include the content-free evidence receipt as
  an additive `receipt` field; the object remains available as `result.receipt`.

### Added

- Detector-scoped assurance states for detection, transformation, and
  verification, plus content-free evidence receipts and claim scopes.
- Content-bound `inspect`, `plan`, `apply`, and `verify` APIs across Python,
  CLI, HTTP/OpenAPI, and MCP. Plans bind consequential policy and require an
  exact digest plus explicit transformation consent.
- A bounded JSON command-detector protocol with static capability manifests,
  configuration fingerprints, strict response validation, and redacting
  golden-vector conformance reports.
- A canonical Unicode policy shared by Python and the browser, contextual
  dispositions, byte/code-point/grapheme offsets, reversible edit manifests,
  document-bound edit hashes, and cross-runtime golden tests.
- Scanner baselines, suppressions, changed-line filtering, atomic fixes,
  permission/BOM/newline preservation, and SARIF fingerprints.
- Content-addressed evaluation manifests and checkpoints, held-out calibration,
  confidence intervals, false-insertion accounting, cross-detector hooks, and
  explicit offline policy for learned metrics.
- CI coverage for Python 3.9–3.14, macOS/Windows, MCP, browser parity, optional
  extras, offline socket denial, installed artifacts, SBOMs, dependency review,
  audits, CodeQL, and release provenance attestations.

### Changed

- Every built-in and provider rewrite now crosses the same whole-document
  quality gate; protected facts, polarity, code, JSON, Markdown, and document
  structure receive stronger deterministic checks.
- Every text-receiving extension—transformer, scorer, quality gate, semantic
  scorer, chunker, and detector—now requires a static capability manifest and
  fails closed before construction or text access when its kind, privacy, model,
  or secret requirements cannot be enforced. Plans ignore extensions that the
  selected mode cannot execute.
- Content-bound plans bind extension capability digests, implementation
  fingerprints, and monotonic registration revisions, rejecting replacement
  even when self-declared manifest fields remain unchanged.
- Remote calls, generated tokens, deadlines, cancellation, model access, and
  batches now use request-scoped limits and privacy-safe accounting.
- Loopback HTTP processing now requires the same explicit opt-in as every other
  endpoint; local network placement is not treated as consent.
- Repository scanning reports only actionable evidence by default; contextual
  and informational observations are available with `--all-findings`.
- Anthropic/Claude production marking is represented as
  `unsupported_pending_spec` until public technical detection guidance exists.
- The Docker image runs as a non-root user and defaults to local capability
  output; external server binds require an API key.

### Fixed

- Restored Python/browser Unicode-policy parity for emoji, joining controls,
  variation selectors, bidi text, and byte-order marks.
- Prevented provider metadata from forging pipeline fields or bypassing central
  acceptance gates; arbitrary strings, non-finite numbers, and custom gate
  reasons are redacted from public results.
- Prevented plans from importing untrusted detector entry points.
- Prevented generic provider, scorer, and detector factories from receiving
  application API keys, and removed detector-constructor retry behavior.
- Replaced the obsolete MCP server integration with the official FastMCP API.
- Redacted provider bodies, adapter stderr, command arguments, and credentials
  from public failures and artifacts.
- Isolated command-detector child environments from ambient credentials and
  made secret-requiring adapters fail closed because no secret channel exists.

## [0.4.0] - 2026-08-16

- Added repository scanning, SARIF, pre-commit, a GitHub Action, local
  HTTP/OpenAPI and MCP surfaces, a browser playground, Docker, an agent skill,
  and a deterministic five-family Unicode fixture benchmark.
- Repositioned the project around the accurate term “open-source AI text
  watermark remover” while documenting statistical and vendor limitations.

## [0.3.0]

- Added PyPI Trusted Publishing and Unicode data licensing.
- Added typed result models, provider protocols and entry points, capability
  planning, events, batches, async processing, model lifecycle controls, an
  agent CLI, namespaced environment variables, and a packaged evaluator.

## [0.2.0]

- Added safe Unicode profiles, quality-constrained BIRA/SIRA proxies, chunking,
  remote privacy controls, and empirical matched-null evaluation.

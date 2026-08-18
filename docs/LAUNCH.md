# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and test named text-watermark detectors

I built an MIT-licensed Python toolkit that inspects contextual Unicode covert channels, removes policy-covered artifacts, and evaluates named statistical-watermark mitigations. The v0.6 release candidate separates detection, transformation, and verification; returns content-free evidence receipts; and gives agents a consent-bound inspect → plan → apply → verify workflow over CLI, HTTP/OpenAPI, and MCP. It adds static detector discovery, golden-vector conformance, a pinned upstream KGW token-ID fixture pack, fail-closed quality-gate contracts, reproducible evidence schemas, local editor integrations, and a private browser playground. The KGW fixtures validate the integration contract rather than natural-language efficacy. Anthropic confirms marking for supported new Claude models but has not yet published technical detector guidance, so the toolkit explicitly abstains instead of claiming Claude removal. I would especially value independent detector adapters, calibrated benchmark runs, and replications.

## Developer communities

**Title:** Open-source text-watermark assurance toolkit with CLI, SARIF, MCP, and local editor checks

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it, or test a mitigation against a named independent detector without confusing “changed” with “verified.” The default cleanup is deterministic and local; lossy normalization, downloads, remote rewriting, and learned quality gates are opt-in. What detector or integration would make this useful in your workflow?

## Short social post

Dewatermark v0.6 release candidate: an open-source text-watermark remover and assurance toolkit. Inspect hidden Unicode locally, scan repos and editor buffers, validate detector adapters against golden vectors, and build content-free evidence bundles through consent-bound Python/CLI/HTTP/MCP workflows. The included statistical fixtures are contract tests, not universal or vendor-specific removal claims; every outcome says what changed, what was verified, and what remains unknown.

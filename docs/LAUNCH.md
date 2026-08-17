# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and research LLM text watermarks

I built an MIT-licensed Python toolkit that finds and removes contextual Unicode covert channels and evaluates named statistical watermark mitigations. The new release separates detection, transformation, and verification; returns content-free evidence receipts; and gives agents a consent-bound inspect → plan → apply → verify workflow over CLI, HTTP/OpenAPI, and MCP. It includes a bounded external-detector protocol, SARIF scanner, pre-commit hook, and private browser playground. Anthropic now confirms Claude marking for supported new models, but its technical detector guidance is forthcoming, so the toolkit explicitly abstains instead of claiming Claude removal. I would especially value independent detector adapters and benchmark replications.

## Developer communities

**Title:** Open-source text watermark inspector with CLI, SARIF, MCP, and a local browser tool

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it. The default cleanup is deterministic and local; lossy normalization, downloads, and remote rewriting are opt-in. What integration would make this useful in your workflow?

## Short social post

Released dewatermark v0.5: an open-source AI text watermark remover and assurance toolkit. Inspect hidden Unicode locally, scan repos with SARIF/pre-commit, connect named independent detectors, and use consent-bound Python/CLI/HTTP/MCP workflows. No universal or vendor-specific magic claims—every outcome says what changed, what was verified, and what remains unknown.

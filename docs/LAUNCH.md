# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and test named text-watermark detectors

I built an MIT-licensed Python toolkit that finds and cleans suspicious hidden Unicode, scans repositories, and tests statistical watermark changes with a named detector. Version 0.6.0 clearly separates what was found, what changed, and what was actually verified. It also adds a review-before-apply workflow for agents through Python, the CLI, HTTP/OpenAPI, and MCP; detector test cases; a pinned KGW token example pack; quality checks; repeatable evidence files; local editor integrations; and a browser playground where text stays in the browser. The KGW examples test the integration, not real-world removal. Anthropic confirms marking for supported new Claude models but has not published the detector details needed for an independent test, so the tool reports Claude as unsupported instead of claiming removal. I would especially value independent detector adapters, calibrated benchmark runs, and replications.

## Developer communities

**Title:** Open-source text-watermark assurance toolkit with CLI, SARIF, MCP, and local editor checks

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it, or test a mitigation against a named independent detector without confusing “changed” with “verified.” The default cleanup is deterministic and local; lossy normalization, downloads, remote rewriting, and learned quality gates are opt-in. What detector or integration would make this useful in your workflow?

## Short social post

Dewatermark v0.6.0 is an open-source text-watermark remover and testing toolkit. Find and clean hidden Unicode locally, scan repositories and editor buffers, test detector integrations against known examples, and create privacy-safe evidence files through Python, the CLI, HTTP/OpenAPI, or MCP. The included statistical examples test integrations; they are not proof of universal or vendor-specific watermark removal. Every result says what changed, what was verified, and what remains unknown.

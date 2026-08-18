# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and test named text-watermark detectors

I built an MIT-licensed Python toolkit that finds and cleans suspicious hidden Unicode, scans repositories, and tests statistical watermark changes with named detectors. Version 0.7.0 adds bounded signal localization and a minimal-change optimizer that returns the exact source unless quality checks, the primary detector, and a distinct held-out detector all accept the result. It also includes exact KGW and Unigram reference configurations, strict local command adapters, a resumable benchmark runner, and Python, CLI, HTTP/OpenAPI, and MCP contracts. The included statistical configurations test integrations; they are deliberately uncalibrated and are not evidence of production or vendor-specific removal. I would especially value calibrated detector adapters, full benchmark runs, and independent replications.

## Developer communities

**Title:** Open-source text-watermark assurance toolkit with CLI, SARIF, MCP, and local editor checks

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it, or test a mitigation against a named independent detector without confusing “changed” with “verified.” The default cleanup is deterministic and local; lossy normalization, downloads, remote rewriting, and learned quality gates are opt-in. What detector or integration would make this useful in your workflow?

## Short social post

Dewatermark v0.7.0 is an open-source, verification-first text-watermark mitigation toolkit. Find and clean hidden Unicode locally, locate signals from compatible detectors, search for the smallest quality-preserving rewrite, and require independent held-out verification before accepting changed text. Use it through Python, the CLI, HTTP/OpenAPI, or MCP. The included KGW and Unigram configurations are uncalibrated integration references, not proof of universal or vendor-specific removal. Every result says what changed, what was verified, and what remains unknown.

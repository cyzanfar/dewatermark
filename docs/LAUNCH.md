# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and test named text-watermark detectors

I built an MIT-licensed Python toolkit that finds and cleans suspicious hidden Unicode, scans repositories, and tests statistical watermark changes with named detectors. Version 0.8.0 adds content-addressed, operator-scoped mitigation profiles; bounded detector contribution spans; and a deterministic context-aware minimal-edit strategy whose candidates still pass through the central quality and held-out-verification boundary. It also includes an operator-sealed SynthID Text research pack and frozen benchmark preregistration. The pack is deliberately uncalibrated, non-independent, non-production, and not evidence of Claude, Gemini, or universal watermark removal. I would especially value calibrated detector adapters, frozen benchmark runs, and independent replications.

## Developer communities

**Title:** Open-source text-watermark assurance toolkit with CLI, SARIF, MCP, and local editor checks

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it, or test a mitigation against a named independent detector without confusing “changed” with “verified.” The default cleanup is deterministic and local; lossy normalization, downloads, remote rewriting, and learned quality gates are opt-in. What detector or integration would make this useful in your workflow?

## Short social post

Dewatermark v0.8.0 is an open-source, verification-first text-watermark mitigation toolkit. It adds operator-scoped mitigation profiles, bounded detector contribution spans, context-aware minimal edits, and a sealed SynthID Text research adapter. Modified text is still accepted only after required quality gates, primary clearance, and a distinct calibrated and independent held-out detector agree; otherwise the exact source is returned. The included statistical packs remain research integrations, not proof of Claude, Gemini, universal, or vendor-specific removal.

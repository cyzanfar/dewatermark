# Community launch kit

Use these as editable drafts. Participate in each community rather than cross-posting identical copy, and disclose that you built the project.

## Hacker News

**Title:** Show HN: Dewatermark – inspect hidden Unicode and research LLM text watermarks

I built an MIT-licensed Python toolkit that finds and removes zero-width characters, Unicode tags, variation selectors, exotic spaces, and other text covert channels. It also includes a quality-constrained research harness for published statistical watermark schemes. The useful new pieces are a private browser playground, SARIF repository scanner, pre-commit hook, local HTTP/OpenAPI API, and MCP tools. It deliberately does not claim to remove an undisclosed Claude/vendor watermark. I would especially value feedback on independent detector adapters and benchmark methodology.

## Developer communities

**Title:** Open-source text watermark inspector with CLI, SARIF, MCP, and a local browser tool

I made dewatermark for developers who need to understand suspicious invisible Unicode before modifying it. The default cleanup is deterministic and local; lossy normalization, downloads, and remote rewriting are opt-in. What integration would make this useful in your workflow?

## Short social post

Released dewatermark v0.4: an open-source AI text watermark remover and research toolkit. Inspect hidden Unicode locally, scan repos with SARIF/pre-commit, call it over Python/CLI/HTTP/MCP, and reproduce named-scheme benchmarks. No universal or vendor-specific magic claims—just inspectable methods and explicit limits.

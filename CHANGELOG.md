# Changelog

This project follows Semantic Versioning. Public changes are recorded here.

## [Unreleased]

## [0.7.0] - 2026-08-18

### Added

- A request-scoped `DetectorSession` with detector-policy-and-text digest
  caching, atomic batch scoring,
  independent detector-query budgets, normalized score direction and p-values,
  and held-out verification that rejects repeated detector identities.
- Content-free signal localization using native detector spans or bounded
  overlapping windows with family-wise p-value correction. Status-only window
  results are explicitly exploratory.
- A deterministic detector-guided optimizer that searches bounded candidate
  sets, applies the central quality gates, selects the smallest passing edit,
  requires a distinct calibrated and independent verifier, and returns the
  exact source on every abstention or rollback.
- Registered-provider and bounded JSON command strategy adapters. Command
  strategies use static manifests, configuration fingerprints, strict JSON,
  scrubbed environments, process-tree cleanup, shared resource accounting, and
  no implicit secret channel.
- `localize` and `mitigate` Python, CLI, HTTP/OpenAPI, and MCP operations, plus
  public localization, mitigation, and command-strategy JSON schemas and
  separate search-candidate and detector-query configuration limits.
- A one-command, resumable KGW benchmark runner that builds matched registered
  samples through bounded adapters, executes a frozen no-attack/reference/
  paraphrase/BIRA/SIRA matrix, records gate failures and abstentions, and emits
  strict content-free observation and evidence artifacts.
- A frozen comparator registry, real-run KGW preregistration, private run/input
  schemas, cluster-level paired sign inference, and fixed-family Holm
  correction that retains unavailable preregistered hypotheses.
- Exact, content-addressed KGW and Unigram natural-text reference configurations
  with pinned author-source conformance, analytical length-aware evidence,
  fail-closed closed-vocabulary fixtures, and offline operator-sealing templates
  for arbitrary local tokenizers and out-of-band private keys. These packs remain
  explicitly uncalibrated and non-production; the reference private-key path
  requires verifiable owner-only POSIX permissions and fails closed on Windows.

### Changed

- Fixed-FPR aggregation now honors lower-is-positive detector manifests, counts
  missing required positive observations as failed attempts, and accepts
  detector-specific effective token counts for cross-detectors.
- Window localization now refuses to promote an inconclusive detector result,
  even when an extension also supplies a low p-value.
- Held-out verification now preflights detector identity, scheme compatibility,
  a complete static decision contract, calibration, independence, and a shared
  `watermark_target_sha256` before any verifier receives source text. Cached
  observations bind the exact detector policy, and policy drift fails closed.
- Nested requests can no longer relax an outer request's network or model-
  download consent; the active request context enforces both permissions at the
  resource boundary.
- Bounded detector and strategy commands now reject credential-bearing argv,
  including secret flags, common token formats, and URL user information.
- Public command configuration now rejects nested credential fields and values,
  credential-bearing URLs, and local paths before computing a public digest.
- Generic detector responses must agree with their declared scheme, score
  direction, threshold operator, threshold, and configuration; paired verifier
  decisions must use one unchanged decision contract.
- Native detector spans remain exploratory unless every span has a p-value and
  the capability declares calibrated family-wise localization error control.
- MCP advertises the same closed, bounded localization and mitigation request
  and result schemas as the runtime instead of permissive generic objects.
- Command detectors can bind explicit threshold-operator, watermark-target, and
  external-implementation digests. Held-out verification requires the complete
  static contract and rejects launcher aliases before either command receives text.
- KGW and Unigram packs now use opaque key IDs with owner-only structured key
  records, strict upstream decision edges, closed-vocabulary fixture labels,
  relative/log-scale conformance comparisons, full runtime/platform pins,
  bounded tokenizer snapshots that reject credential-bearing filenames and
  content before hashing, and atomic pair publication.
- Mitigation receipts and schemas now bind detector roles, policy hashes,
  source/candidate hashes, paired decision evidence, quality acceptance, exact
  rollback, and a narrow claim scope before allowing a `verified` result.
- Benchmark execution now binds matched decoding seeds and private key slots,
  rejects aliased cross-detectors, enforces persistent run-wide budgets, keeps
  failed attempts in denominators, validates artifacts before publication, and
  resumes only from a strict hash-chained checkpoint.
- Existing command-detector v1 manifests and responses remain valid for
  ordinary detection; the new threshold-operator fields are optional at the
  v1 boundary, while held-out verification safely abstains unless the complete
  static decision contract is explicit.
- Detector-session cache hits now enforce the active request deadline and
  cancellation checkpoint before returning cached evidence.
- Evaluation command adapters now use the same credential-bearing argv checks
  as runtime detector and strategy adapters, while retaining operator-managed
  secret-file references.
- Completed benchmark resumes now bind the evidence bundle, observation set,
  sample registry, and run identity back to the hash-chained completion record
  before returning cached results.
- Evaluation adapter identities, static sidecars, and runtime capability metadata
  now reject credential-shaped values, credential-bearing URLs, and private paths
  before public hashing or caching. Human-review and nested protocol metadata are
  likewise validated against closed contracts before a run ID or checkpoint exists.
- Benchmark execution now records counted cancellation checkpoints during
  process execution, aggregation, and final publication; it enforces the
  absolute deadline throughout and applies exact integer and total-work bounds
  to bootstrap computation.
- `aggregation_contract_version` 1.1 binds bootstrap settings, comparator declarations,
  samples, observations, and public results into one reproducible graph.
  Verification recomputes the aggregate exactly and distinguishes legacy
  content-address validity from `aggregate_verified` statistical semantics.
- Cluster sign-test tails now remain finite and fast for thousands of
  discordant pairs without giant integer conversion, with a hard comparator
  work bound. Strict 1.1 observations accept only closed host failure codes;
  unmarked legacy v1 artifacts retain their open-token compatibility.

## [0.6.0] - 2026-08-18

Version `0.5.0` was an unpublished source milestone: it was never tagged or
uploaded to PyPI, and its changes are included in this release.

### Added

- Dependency-free KGW-, Unigram-, and tournament-style research fixtures with
  six golden vectors, explicit non-production manifests, and side-effect-free
  `detectors list`, `doctor`, and `conformance` workflows.
- A pinned upstream KGW token-ID command-adapter pack with source/configuration
  hashes and real upstream positive/control/abstention conformance, plus a
  fail-closed SynthID Text template. Neither is advertised as production or
  vendor detection.
- A machine-enforced benchmark protocol registry, frozen metadata-only sample
  registries, content-free observation sets, fixed-FPR clustered inference,
  blinded human-review packets, resource telemetry, immutable evidence bundles,
  replay recipes, replication records, and four public JSON schemas.
- A scheduled, offline synthetic evidence-conformance replay that verifies
  deterministic bundle identity without presenting fixture scores as efficacy.
- Required/advisory quality-gate bindings and typed bidirectional NLI,
  atomic-claim/QA, entity, citation, and task-contract adapters. The optional
  Transformers NLI reference loads cached files only and never downloads.
- Shared bounded subprocess execution for runtime and evaluation adapters,
  including POSIX process groups and fail-closed Windows Job Object ownership.
- Repository scanner configuration through `.dewatermark.toml` or
  `pyproject.toml`, anchored cross-platform exclusions, custom extensions, and
  `--stdin-path` policy handling for unsaved editor buffers.
- Local-only VS Code and JetBrains inspection packages with explicit safe
  cleanup, strict process/JSON bounds, stale-buffer protection, and real
  packaging/compatibility checks.
- Checked-in OpenAPI 3.1, drift checks, pinned Python/TypeScript client
  generation, an npm-ready zero-dependency Unicode module, a bundled agent-skill
  installer, and signed multi-platform GHCR release automation.
- Digest-pinned container bases, version-pinned container dependencies, Gradle dependency
  verification metadata, Dependabot coverage, Java CodeQL, and npm auditing.
- An evidence-first landing page and research guide, custom-domain setup guide,
  social metadata, an optimized preview image, and expanded integration docs.

### Changed

- Public benchmark bundles and JSON artifacts now enforce closed manifest/result
  vocabularies plus value-level credential and host-path checks before claiming a
  content-free privacy class.
- Learned and third-party quality gates are additive to deterministic central
  acceptance checks; a custom gate can no longer replace or bypass them.
- Required learned gates fail closed on abstention, malformed results,
  unavailable models, missing consent, unaccounted resource use, timeout, or
  cancellation. Per-gate content-free outcomes are bound into plans and receipts.
- Python and browser sanitation now report canonical NFC normalization edits as
  well as policy deletions/replacements, with cross-runtime output/count and
  policy-action parity checks.
- Evaluation identities bind protocol/sample/observation inputs and distinguish
  calibration thresholds from held-out testing, failures, abstentions, false
  insertions, cross-detector outcomes, and replication status.
- Content-bound plans now include a deterministic, content-free fingerprint of
  observable extension class, instance, default, closure, inherited, and
  capability state and recheck that identity before first runtime use.

### Fixed

- Plan digests are now stable across fresh CLI processes, canonicalize equivalent
  default options across Python, HTTP, and MCP, and reject invalid options before
  presenting an execution plan as available.
- HTTP requests now enforce their closed OpenAPI objects, and CLI batch/removal
  failures produce the documented processing exit while JSONL continues after
  redacted per-item errors.
- Extension discovery now rejects case-normalized entry-point name collisions
  instead of selecting an installation-order-dependent provider or detector.
- Mutating a reviewed provider, scorer, detector, quality gate, semantic scorer,
  or chunker can no longer preserve an old plan digest or execute under stale
  consent; explicit re-registration/replanning is required.
- Bounded adapter cleanup now terminates descendant process trees and never
  closes buffered pipes while reader threads may still hold their locks.
- Scanner policy discovery bounds `pyproject.toml` reads and resolves the policy
  from the checked target repository instead of an unrelated caller directory.
- Extension class names, nested capability metadata, models, paths, process
  output, and arbitrary exception text are redacted or content-addressed before
  entering representations, plans, receipts, diagnostics, and benchmark artifacts.
- Resource-using extensions are budget-preflighted before construction or text
  access and rejected when their declared network/model work bypasses the
  request ledger; command detectors conservatively reserve their parent
  subprocess operation.
- Host-local model paths are content-addressed in evaluation manifests,
  checkpoints, runtime metadata, and Markdown reports while public registry
  model identifiers remain reproducible.
- Release workflows validate a shared Python/npm/citation version, and stable
  publishing refuses prerelease or non-SemVer identities until a dated
  changelog release heading exists. Release tags must point to commits on
  `main`, and registry publication is serialized. Python dependency audits no
  longer misclassify the unpublished local distribution as a vulnerable
  dependency.
- Common `.env.*` credential files are ignored while `.env.example` remains
  available as an explicit template, and the feature-request issue form now
  parses as valid YAML.
- The pinned build backend remains installable on the declared Python 3.9
  compatibility floor.
- The packaged KGW adapter capability now matches the exact byte digest of its
  canonical golden-vector fixture, with LF checkouts enforced so that digest is
  stable on Windows.
- The JetBrains integration's strict Gradle verification metadata now includes
  the Linux-resolved Jackson parent POMs and JUnit module descriptors used by
  its plugin and test classpaths.
- Reworked the README around a plain, task-first install and quickstart; moved
  the detailed runtime settings into a dedicated configuration guide.
- Replaced non-resolving public JSON Schema identifiers with directly
  retrievable source URLs.

### Changes carried forward from the unpublished 0.5.0 milestone

- Serialized removal results now include the content-free evidence receipt as
  an additive `receipt` field; the object remains available as `result.receipt`.

#### Added

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

#### Changed

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
- Anthropic/Claude production marking returns an `unsupported` detection
  outcome with capability metadata status `unsupported_pending_spec` until
  public technical detection guidance exists.
- The Docker image runs as a non-root user and defaults to local capability
  output; external server binds require an API key.

#### Fixed

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

# Architecture

The public layer (`dewatermark.__init__`, `cli`, `server`, `mcp_server`) accepts
requests and returns versioned models. `assurance_api` owns the content-bound
inspect/plan/apply/verify contract. `pipeline` orchestrates Unicode hygiene,
untrusted rewrite candidates, central quality gates, named-detector evidence,
and receipts. `request_context` owns request-wide privacy and resource ledgers.
`scoring`, `bira`, `sira`, `paraphraser`, and `fireworks` implement built-in
mechanisms. `protocols`, `providers`, `extension_safety`, and `command_detector`
isolate extensions.

Dependency direction is transport/public API → assurance/orchestration →
protocols/providers → mechanisms. Providers must not import the pipeline.
Evaluation is separately packaged as `dewatermark_eval` and may depend on the
public library.

Privacy boundaries are explicit: local model acquisition requires
`allow_model_download`; remote transmission requires `allow_remote_processing`.
Capability discovery and planning perform neither action.

Detector entry-point names are discoverable without loading their code. A
content-bound plan accepts only a built-in or already-registered static
manifest. Actual detection is separately consent-gated and bounded.

Every extension that can receive text—transformer, scorer, quality gate,
semantic scorer, chunker, or detector—crosses the same static capability check.
The check runs before construction or text access, validates explicit network
and download consent, strips application credentials from factory config, and
requires the factory and instance manifests to match. Content-bound plans bind
the capability plus registration revision and a content-free implementation
fingerprint, so registration replacement invalidates the plan. Extensions that
the selected mode cannot execute are not resolved.

This boundary is policy enforcement, not a Python sandbox. In-process extension
code remains a trusted application dependency; arbitrary malicious code can
bypass cooperative declarations. Extension-provided report strings are treated
as untrusted and redacted at the public result boundary.

Result objects use schema version `1.0`. Common status, acceptance, fallback,
backend, latency, and warning fields are stable. Mechanism-specific values live
under `details` or `metadata`.

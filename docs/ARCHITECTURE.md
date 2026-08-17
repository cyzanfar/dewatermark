# Architecture

The public layer (`dewatermark.__init__`, `cli`) accepts requests and returns
versioned models. `pipeline` orchestrates deterministic Unicode hygiene,
rewriters, quality gates, and verification. `scoring`, `bira`, `sira`,
`paraphraser`, and `fireworks` implement built-in mechanisms. `protocols` and
`providers` isolate third-party implementations. `runtime` performs
side-effect-free discovery and emits metadata-only events.

Dependency direction is public API → orchestration → protocols/providers →
mechanisms. Providers must not import the pipeline. Evaluation is separately
packaged as `dewatermark_eval` and may depend on the public library.

Privacy boundaries are explicit: local model acquisition requires
`allow_model_download`; remote transmission requires `allow_remote_processing`.
Capability discovery and planning perform neither action.

Result objects use schema version `1.0`. Common status, acceptance, fallback,
backend, latency, and warning fields are stable. Mechanism-specific values live
under `details` or `metadata`.

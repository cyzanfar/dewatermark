# Compatibility policy

The project uses Semantic Versioning. Public names exported from
`dewatermark.__all__`, CLI subcommands, provider protocols, exit codes, and
schema-major `1` fields are stable for the 0.x line. Experimental mechanism
internals and `eval` implementation details are not stable.

Deprecations remain available for at least one minor release. The unprefixed
v0.2 environment variables remain compatibility aliases; new integrations should
use `DEWATERMARK_*` names. Python versions are supported from 3.9 through the
latest version validated in CI.

Provider method additions remain optional within a minor release when they do
not affect safety. Starting with 0.6.0, every extension that can receive text must expose
a static capability manifest; manifest-less extensions fail closed before
construction. Removal or reinterpretation of result fields requires a major
schema version.

The removal-result `1.0`, evidence-receipt `1.0`, detector-capability `1.0`,
command-detector protocol `1.0`, benchmark sample-registry `1.0`, observation-set
`1.0`, evidence-bundle `1.0`, and replication-record `1.0` schemas are versioned
independently. Additive optional fields may appear within schema major 1;
existing fields are not removed or reinterpreted. A command adapter with an
incompatible protocol major is rejected before its result can become evidence.

The checked-in OpenAPI document is independently versioned (`info.version`) and
is tested against the server implementation. New optional operations, fields,
or authentication alternatives may be added within an OpenAPI minor; removing
an operation, changing required request semantics, or narrowing a response is a
breaking API change.

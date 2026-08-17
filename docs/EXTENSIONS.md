# Extensions

Implement the structural protocols in `dewatermark.protocols`. Every object that
can receive source or candidate text must expose a literal, static
`CapabilityManifest` before it is registered or called. The accepted manifest
kinds are `transformer`, `scorer`, `quality_gate`, `semantic_scorer`, `chunker`,
and `detector`. Properties, dynamic attributes, callables, and mappings are not
accepted as manifests because reading them could execute extension code.

A rewriter needs `available()` and
`rewrite(text, **options) -> (text, details)`. A scorer needs `available()`,
`self_information(text)`, and `score(text)`. Quality gates, semantic scorers,
chunkers, and detectors use the corresponding protocol and manifest kind.

Register an in-process provider:

```python
from dewatermark import DewatermarkConfig, register_provider, remove

register_provider("example", ExampleRewriter)
config = DewatermarkConfig(rewriter_provider="example")
result = remove("source text", config=config)
```

The registered factory or class must expose its manifest without construction:

```python
from dewatermark import CapabilityManifest

class ExampleRewriter:
    capability = CapabilityManifest(
        identifier="example-rewriter",
        kind="transformer",
        version="1.0.0",
        schemes=("example",),
        network_required=False,
        model_download_possible=False,
    )
```

Extensions without a static manifest, or with the wrong kind, fail closed before
construction and before receiving text, including through the direct Python
API. Network and model-download declarations require the matching explicit
consent. `requires_secret=True` currently fails closed: generic plugins have no
scoped secret channel and are never handed an unrelated application key.

Distributions can publish providers through the `dewatermark.providers` entry
point group:

```toml
[project.entry-points."dewatermark.providers"]
example = "example_package:factory"
```

Factories are called exactly once with a credential-free projection of
`DewatermarkConfig`; `fireworks_api_key` and `llm_api_key` are always `None` at
this boundary. Factories must accept that one config argument, honor its privacy
policy, avoid logging source text, return JSON-compatible details, and expose
deterministic mocked contract tests. Name collisions are rejected.

The instance returned by a factory must expose exactly the same manifest as the
registered factory. Content-bound plans record a manifest digest, an
implementation fingerprint, and a monotonic registration revision. Replacing a
registration—even with the same self-declared fields—invalidates an existing
plan. These identifiers disclose neither source paths nor implementation source.
Extensions configured for a mode that cannot call them (for example a custom
chunker in `sanitize`) are intentionally ignored and do not make that mode fail.

Every rewrite returned by a provider is untrusted and passes through the same
whole-document quality gate as built-in candidates. Provider metadata cannot
override `stage`, `backend`, status, acceptance, warning, or error fields.
Arbitrary strings and non-finite numbers in provider details are redacted.
Custom quality-gate reasons and structure messages are replaced by generic
public outcomes so source or candidate fragments cannot escape through reports.

## Trust boundary

These controls make declaration, consent, planning, and reporting fail closed;
they do not sandbox Python. A registered in-process extension is trusted code
and can lie in its manifest, inspect process memory, or open its own resources.
Review in-process extensions as application dependencies. Prefer the bounded
command-detector adapter for isolated detector implementations, and use an
operating-system sandbox when the executable itself is not trusted.

## Independent detector commands

Use `CommandDetector` when an upstream research implementation has heavy or
conflicting dependencies:

```python
from dewatermark import (
    command_detector_manifest,
    detector_configuration_sha256,
    make_command_detector_factory,
    register_detector,
)

public_config = {"scheme": "example-v1", "key_fingerprint": "sha256:..."}
manifest = command_detector_manifest(
    identifier="example-detector",
    schemes=("example",),
    configuration_sha256=detector_configuration_sha256(public_config),
    threshold=4.0,
    calibrated=True,
    independent=True,
)
factory = make_command_detector_factory(("example-detector", "--json"), manifest)
register_detector("example", factory)
```

The command receives one versioned JSON object on stdin and returns one JSON
object on stdout. It is launched with `shell=False`; time, stdout, and stderr
are bounded; response bodies are redacted from failures. Commands are trusted
local executables, not sandboxes. See
[`schemas/command-detector-protocol-v1.json`](../schemas/command-detector-protocol-v1.json)
and [`examples/detector_adapter.py`](../examples/detector_adapter.py).

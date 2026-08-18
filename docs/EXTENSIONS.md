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

Every resource-using extension also participates in the active request ledger.
Set `network_required=True` for remote work, or set capability metadata
`resource_accounting` to `"model"` or `"network"`. Before construction or text
access, the pipeline rejects a network extension when the request has no
remaining remote-call budget. Each physical in-process HTTP attempt must use
`dewatermark.http.post_json()` or the active request context's
`before_remote_call(...)`; local model work must call
`record_model_access(...)`. An extension that declares accounted work but does
not update the ledger fails closed after invocation. This contract applies to
transformers, scorers, detectors, quality gates, semantic scorers, and chunkers.

The instance returned by a factory must expose exactly the same manifest as the
registered factory. Content-bound plans record a manifest digest, an
implementation fingerprint, a process-keyed fingerprint of observable static
class/instance/default/closure state, and a monotonic registration revision.
Replacing a registration—or mutating reviewed observable state—even with the
same self-declared fields, invalidates an existing plan. Registration state is
rechecked before factory construction, and direct extension state is rechecked
immediately before its first text access. Explicitly re-register changed
factories and create a new plan; create a new plan before reusing a deliberately
stateful direct gate, scorer, or chunker. Fingerprinting is bounded and does not
invoke extension representations, dynamic attributes, or mapping protocols.
These identifiers disclose neither source paths, state values, nor
implementation source.
Extensions configured for a mode that cannot call them (for example a custom
chunker in `sanitize`) are intentionally ignored and do not make that mode fail.

Every rewrite returned by a provider is untrusted and passes through the same
whole-document quality gate as built-in candidates. Provider metadata cannot
override `stage`, `backend`, status, acceptance, warning, or error fields.
Arbitrary strings and non-finite numbers in provider details are redacted.
Custom quality-gate reasons and structure messages are replaced by generic
public outcomes so source or candidate fragments cannot escape through reports.
Learned and task-specific gates use typed, content-free decisions and are always
additive to the built-in policy. See [`QUALITY_GATES.md`](QUALITY_GATES.md) for
bidirectional NLI, claim-QA, entity-linking, citation-grounding, task-contract,
resource-accounting, and fail-closed requirements.

## Trust boundary

These controls make declaration, consent, planning, and reporting fail closed;
they do not sandbox Python. A registered in-process extension is trusted code
and can lie in its manifest, race after validation, derive behavior from opaque
native/module/external state, inspect process memory, or open its own resources.
Observable-state binding closes sequential plan drift; it is not proof of Python
semantics. Review in-process extensions as application dependencies. Prefer the
content-addressed bounded command-detector adapter for isolated detector
implementations, and use an operating-system sandbox when the executable itself
is not trusted.

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
local executables, not sandboxes. A network-declaring command reserves one
parent-ledger operation before launch; because the parent cannot observe the
child's individual sockets, enforce finer query limits inside the adapter or an
OS/container boundary. See
[`schemas/command-detector-protocol-v1.json`](../schemas/command-detector-protocol-v1.json)
and [`examples/detector_adapter.py`](../examples/detector_adapter.py).

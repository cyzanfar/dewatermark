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
implementation fingerprint, a deterministic one-way fingerprint of observable static
class/instance/default/closure state, and a monotonic registration revision.
Replacing a registration—or mutating reviewed observable state—even with the
same self-declared fields, invalidates an existing plan. Registration state is
rechecked before factory construction, and direct extension state is rechecked
immediately before its first text access. Explicitly re-register changed
factories and create a new plan; create a new plan before reusing a deliberately
stateful direct gate, scorer, or chunker. Fingerprinting is bounded and does not
invoke extension representations, dynamic attributes, or mapping protocols.
Credential-shaped fields, credential values, and private absolute paths are
rejected before identity construction. The resulting identifiers do not embed
raw state values or implementation source, but content addresses can still be
guessable: keep every secret in an operator-managed channel, never in extension
state.
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

public_config = {"scheme": "example-v1", "key_id": "operator-key-2026-01"}
watermark_target = {
    "scheme": "example-v1",
    "key_id": "operator-key-2026-01",
    "tokenizer": "example-tokenizer-v1",
    "embedding_config": "example-config-v1",
}
manifest = command_detector_manifest(
    identifier="example-detector",
    schemes=("example",),
    configuration_sha256=detector_configuration_sha256(public_config),
    implementation_sha256="123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    threshold=4.0,
    threshold_operator=">",
    calibrated=True,
    independent=True,
    watermark_target_sha256=detector_configuration_sha256(watermark_target),
)
factory = make_command_detector_factory(("example-detector", "--json"), manifest)
register_detector("example", factory)
```

The target digest must be identical for the primary detector and every held-out
verifier used by `mitigate()`. It identifies the watermarking target without
publishing a secret key. Use an opaque, operator-managed key ID here; do not
publish a hash of a low-entropy key.

For a `CommandDetector` used in held-out verification,
`implementation_sha256` must identify the complete pinned external detector
artifact, including code and any model artifact that can change its decisions.
It does not identify the Python wrapper, detector configuration, target, or
secret key. Different commands that publish the same implementation digest are
treated as aliases. The runtime additionally binds executable/code identity and
normalizes Python comments and formatting to reject obvious aliases. This is a
syntactic screen, not an audit of methodological independence; the operator is
responsible for the `independent=true` declaration. A legacy command manifest without this field still supports
ordinary detection but cannot verify mitigation. Use the exact
`CommandDetector` wrapper: a subclass can add behavior outside the external
implementation commitment and is therefore not accepted for verification.
The public factory identity binds exact non-path argv values but replaces code,
secret-file, and other file/path-looking values with stable role markers; code
bytes are bound by the separate semantic and exact-raw digests. Only direct
reviewed executables and explicitly parsed Python script launches can establish
those digests. Shell, `env`, Node, Perl, Ruby, PowerShell, and other unparsed
dispatch forms may still be used as ordinary trusted commands, but cannot act
as profile-bound or held-out verifiers.

The command receives one versioned JSON object on stdin and returns one JSON
object on stdout. It is launched with `shell=False`; time, stdout, and stderr
are bounded; response bodies are redacted from failures. Commands are trusted
local executables, not sandboxes. A network-declaring command reserves one
parent-ledger operation before launch; because the parent cannot observe the
child's individual sockets, enforce finer query limits inside the adapter or an
OS/container boundary. See
[`schemas/command-detector-protocol-v1.json`](../schemas/command-detector-protocol-v1.json)
and [`examples/detector_adapter.py`](../examples/detector_adapter.py).

Protocol 1.2 detectors may additionally declare bounded native attribution:

```python
manifest = command_detector_manifest(
    # The ordinary identifier, scheme, configuration, threshold, and identity
    # arguments are omitted here only for brevity.
    identifier="example-attributing-detector",
    schemes=("example",),
    configuration_sha256=detector_configuration_sha256(public_config),
    threshold=4.0,
    attribution_kind="token_character_spans",
    maximum_attributions=256,
)
```

An opted-in command receives the same kind and maximum in the request's
`attribution` object and must return an `attributions` array. Each entry contains
only `start`, `end`, and `score`, plus optional numeric `p_value` and `threshold`.
Offsets use Unicode code-point positions (Python string indexes) and half-open
ranges. The adapter rejects unknown per-span fields, text-bearing token values,
non-finite numbers, overlapping or out-of-range spans, and responses beyond either the
declared maximum or `effective_tokens`. The resulting localization is an editing
hint, not a clearance claim; final acceptance still requires the independent
held-out verification path.

## Bounded command strategies

Use `CommandStrategy` when a candidate generator needs a separate Python
environment or has conflicting dependencies. The command proposes strings; it
does not decide whether a string is safe or whether a watermark has cleared.
Only `mitigate()` can accept a proposal after quality checks, primary-detector
scoring, and held-out verification.

Register a command strategy as a normal transformer provider:

```python
import sys
from pathlib import Path

from dewatermark import (
    command_strategy_manifest,
    make_command_strategy_factory,
    register_provider,
    strategy_configuration_sha256,
)

public_config = {"algorithm": "example-candidates-v1"}
manifest = command_strategy_manifest(
    identifier="example-command-strategy",
    schemes=("example",),
    configuration_sha256=strategy_configuration_sha256(public_config),
    network_required=False,
    model_download_possible=False,
)
command = (
    sys.executable,
    str(Path("examples/command_strategy_adapter.py").resolve()),
)
factory = make_command_strategy_factory(command, manifest)
register_provider("example-command", factory)
```

`strategy_configuration_sha256()` accepts literal public JSON and refuses
credential-shaped field names. Put only public settings and fingerprints in
that configuration.

It can then be selected in Python with
`registered_strategy("example-command")` or from the CLI with
`--strategy example-command`.

Construction, manifest access, factory creation, and `available()` do not start
the command. `available()` checks only whether the executable exists. The
command runs only when `generate()` is called inside an active, consent-bound
request.

The request contains:

- protocol version, action, strategy identifier, and exact configuration
  SHA-256;
- effective network, model-download, candidate, character, and output-token
  bounds;
- round number, invocation number, deterministic seed, primary-detector
  feedback, and content-free source ranges; and
- the current source or candidate text.

The response is a closed JSON object containing the same protocol, strategy,
and configuration identity plus an array of candidate strings. Unknown fields,
duplicate JSON keys, non-finite values, invalid UTF-8, oversized output, too
many candidates, or an identity mismatch fail closed. There is no implicit
options channel.

The runtime uses immutable tuple argv, `shell=False`, a stripped environment,
bounded stdout and stderr, the shared request deadline and cancellation checks,
and redacted failures. Network and model access require matching manifest
declarations and explicit request permission. `requires_secret=true` fails
closed because this generic protocol has no secret channel. Put secrets behind
an operator-owned purpose-built adapter instead of in configuration, argv, the
environment, or JSON.

This process boundary limits data and resources, but it is not a sandbox. The
configured executable is trusted by the operator and receives text. Use a
container or operating-system sandbox for untrusted code.

The complete wire contract is
[`schemas/command-strategy-protocol-v1.json`](../schemas/command-strategy-protocol-v1.json).
A runnable offline example is
[`examples/command_strategy_adapter.py`](../examples/command_strategy_adapter.py).
The search and rollback rules are in
[Detector-guided mitigation](DETECTOR_GUIDED_MITIGATION.md).

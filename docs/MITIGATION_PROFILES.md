# Operator-scoped mitigation profiles

A mitigation profile is a content-addressed execution contract for one exact
watermark target. It binds the primary detector, every held-out verifier, the
candidate-strategy portfolio and options, the required quality policy, the
random seed, search limits, and an evidence status. The profile does not contain
text, a key, a key hash, credentials, commands, or filesystem paths.

Profiles make the declared run configuration reproducible and auditable; they
cannot make an opaque external component deterministic, and they do not make a
detector universal. A result remains limited to the named configuration and
watermark target. The opaque `key_id` is an operator label that must be
generated independently of key material. It is not a commitment to, or proof
of, a secret key.

## Safety boundary

`load_mitigation_profile()` and `inspect_mitigation_profile()` are discovery
operations. They read bounded strict JSON and static registrations. For an
exact `CommandDetectorFactory`, they also hash the bounded public
executable/script code while replacing executable, script, secret-file, and
other file/path-looking argv values in the public command-shape digest. Exact
non-path arguments remain bound, so a public mode or behavior flag cannot drift
silently. They do not import an unloaded plugin, construct a
third-party extension, start a command, read an operator key or secret file,
access a model, or open a socket. Inspection may reconstruct the bundled pure
context strategy from its already validated public options so its deterministic
identity can be checked.

`mitigate_with_profile()` is the explicit execution boundary. It requires
`consent=True`, then loads the named components and checks their capability,
implementation, and static-state digests before any detector or strategy sees
text. Network processing and model acquisition remain separate, off-by-default
permissions in `DewatermarkConfig`. Profile limits cannot expand the caller's
request limits. Caller-supplied `source_localization` is rejected because it is
not part of profile v1; the bound primary detector may still return native
localization through its committed detector contract.

Every candidate remains untrusted. The profile cannot bypass central quality
checks, primary clearance, or the distinct held-out-verifier requirement. Any
missing component, digest mismatch, policy drift, exhausted budget, failed gate,
or inconclusive verification returns an error before execution or the exact
source through the normal rollback path.

Exact command-detector bindings additionally record the manifest's validated
external `implementation_sha256` commitment, a semantic `command_code_sha256`,
and an exact-byte `command_code_raw_sha256`. The host wrapper is still bound,
but its shared Python identity is not mistaken for the external detector
implementation. Primary and held-out command detectors must have distinct
external commitments and distinct semantic code identities; comments,
formatting, pass statements, and unused module constants therefore cannot turn
one Python implementation into an independent verifier. The raw identity is
used separately for drift: it changes for every executable or script-byte
change, including comments and dynamically accessed module constants, and is
checked again immediately before an external process can receive text. Code
identity reads are bounded, regular-file-only, and nonblocking.

Only a directly reviewed executable (including a direct Python-shebang script)
or an explicitly parsed Python-interpreter-plus-script form can establish this
identity. Dispatcher and interpreter shapes whose complete code boundary is not
parsed—such as `sh script`, `env python script`, Node, Perl, Ruby, or
PowerShell—fail closed for profile and held-out identity.

For a profile-bound command, the parent repeats the exact raw-code check inside
the bounded launch boundary after it owns the child process and immediately
before writing source to stdin. This closes deterministic replacement between
profile review and input handoff. It is not filesystem isolation: another
process running as the same user may still race a mutation after that final
check. Preventing that race requires true executable/script file-descriptor
pinning (and launching from those descriptors), which this portable command
adapter does not implement. Operators should make reviewed code read-only to
the execution account or enforce an equivalent OS/container boundary.

## Build and execute

Components must first be installed and explicitly registered. Building a
profile only snapshots their static public identities:

```python
from pathlib import Path
import json

from dewatermark import (
    SearchLimits,
    build_mitigation_profile,
    mitigate_with_profile,
)

profile = build_mitigation_profile(
    "operator/synthid-research-v1",
    scheme="synthid-text/public-reference-v1",
    watermark_target_sha256="<64 lowercase hex characters>",
    key_id="opaque-random-operator-label",
    primary_detector="operator-synthid-primary",
    verifier_detectors=["operator-synthid-held-out"],
    strategies=[("context-aware-minimal-edit-v1", {"context_influence": 2})],
    protocol_sha256="<SHA-256 of canonical JSON for eval/protocols/synthid-v1.json>",
    limits=SearchLimits(max_candidates=24, max_detector_queries=64),
)

# Persist only this public object. Keep detector key files and paths elsewhere.
Path("profile.json").write_text(json.dumps(profile.to_dict()), encoding="utf-8")

result = mitigate_with_profile(source, profile, consent=True)
```

The CLI supports the same split between inspection and execution:

```bash
dewatermark profiles inspect profile.json
dewatermark profiles doctor profile.json
dewatermark mitigate --input source.txt --profile profile.json --consent
```

`profiles doctor` is side-effect-free and reports `static_bindings_ready=false`
when a component is unloaded, mismatched, or incompatible with the caller's
declared network/model consent. It does not construct third-party components or
call `available()`, so `runtime_availability` is explicitly `not_checked` and is
resolved only at the consented execution boundary. It does not install
anything. Profile v1 never sets an aggregate-verification claim.

## Evidence state

Profile v1 has exactly one evidence state: `protocol_only_no_results`. It pins
the exact preregistered evaluation protocol, but it cannot attach an evidence
bundle, claim that an aggregate was produced by the profile, or promote an
aggregate result into an execution receipt.

That separation is deliberate. The independent benchmark runner does not load
or execute mitigation profiles and therefore cannot prove that an arbitrary
profile digest corresponds to the detectors, strategies, quality policy, or
limits used for a run. Its generic evidence bundles can still be verified and
replayed through the evaluation API, but those results remain separate from
profile execution. A future additive contract would need to map and validate
every profile component inside the runner before any result binding could be
sound.

## SynthID and Claude boundary

The packaged SynthID lab targets an exact public research configuration. It is
not a Gemini production detector. Anthropic has disclosed that Claude marking
uses a version of SynthID-Text, but the deployed configuration, keys, detector
contract, and calibrated thresholds are not public. Therefore a research
SynthID profile must not be relabeled as `anthropic-claude`, and Claude remains
`unsupported_pending_spec` until a compatible detector contract is available.

# Reference detector stack

The repository now separates three trust levels that are often blurred by
“watermark remover” projects:

| Layer | Purpose | Can verify production removal? |
| --- | --- | --- |
| Built-in word-level references | Fast offline development, examples, agent workflows, and regression vectors | No |
| Pinned upstream adapter packs | Reproduce a named external implementation in an isolated command | Only after scheme-specific conformance and calibration |
| Production/provider detector | Evaluate the exact deployed tokenizer, key, configuration, and threshold | Only with authorized keys, matched controls, and adequate evidence |

## Dependency-free research fixtures

`reference-kgw`, `reference-unigram`, and `reference-tournament` are
deterministic synthetic schemes. They use a documented NFC word tokenizer, a
public fixture key, immutable configuration digests, a minimum effective
length, typed abstention, and six checked-in positive/matched-control vectors.
The tournament fixture is inspired by multilayer tournament ideas but is
explicitly **not SynthID Text**.

Every reference manifest is `calibrated=false`, `independent=false`,
`vendor_equivalent=false`, and `production_detection=false`. Consequently it
can exercise inspection and mitigation plumbing, but it can never produce a
`verified_cleared` conclusion.

```bash
dewatermark detectors list
dewatermark detectors doctor
dewatermark detectors conformance
dewatermark detectors conformance --scheme kgw
```

`list` and `doctor` inspect only static manifests. They do not import detector
entry points, start a command, load a model, read input text, or open a socket.
`conformance` executes only the dependency-free built-ins and returns vector
names plus mismatched field names; vector text is excluded from the report.

```python
from dewatermark import generate_reference_text, inspect

fixture = generate_reference_text("kgw-word-v1", token_count=96, seed=11)
evidence = inspect(fixture, detector="reference-kgw")
assert evidence.status == "detected"
assert evidence.details["vendor_equivalent"] is False
```

## Pinned KGW upstream pack

[`adapters/kgw`](../adapters/kgw) wraps
`jwkirchenbauer/lm-watermarking@82922516930c02f8aa322765defdb5863d07a00e`.
The wrapper contains no detector algorithm. It checks the upstream
`watermark_processor.py` digest before import and accepts public `tNNN` token
fixtures, so integration can be tested offline without acquiring a model or
tokenizer.

This pack establishes a maintained command boundary and immutable upstream
identity; it does not establish natural-language efficacy. Its capability is
independent by implementation lineage but deliberately uncalibrated and
non-production. Operators must create a different identifier after pinning the
real tokenizer files, device/RNG behavior, key, normalization, calibration
population, length-specific thresholds, and passing golden vectors.

## SynthID Text template

[`adapters/synthid`](../adapters/synthid) pins
`google-deepmind/synthid-text@addb4a158143c7c6851a1308f78b89fceed59683`
and the relevant source-file digests. It remains a template with unresolved
configuration and failed conformance by design. The public reference repository
does not provide Gemini production keys, so neither the template nor the
synthetic tournament fixture supports Gemini production detection.

## Process boundary

Runtime and evaluation commands share one bounded subprocess implementation.
It strips ambient credentials at the calling adapter layer, uses immutable argv
with `shell=False`, caps stdout/stderr and wall time, kills POSIX process groups
or Windows Job Object trees (with a `taskkill` fallback), and never closes a
buffered pipe while its reader thread is alive. Error objects contain only a
failure class and optional exit status—never argv, input, stream output, or
environment values.

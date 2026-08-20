# Reference detector stack

The repository has three detector levels. They serve different purposes and
must not be treated as interchangeable.

| Level | Use | Production removal evidence? |
| --- | --- | --- |
| Built-in word fixtures | Fast offline tests and examples | No |
| Exact packaged KGW and Unigram profiles | Check one public algorithm and configuration | No; both are uncalibrated |
| Operator or provider detector | Evaluate the deployed tokenizer, key, configuration, and threshold | Only after independent conformance and matched-null calibration |

## Built-in word fixtures

`reference-kgw`, `reference-unigram`, and `reference-tournament` are small,
deterministic fixtures. They use a documented word tokenizer, public test keys,
fixed configuration digests, typed abstentions, and checked-in vectors. The
tournament fixture is inspired by tournament watermark designs but is not
SynthID Text.

Their manifests set `calibrated=false`, `independent=false`,
`vendor_equivalent=false`, and `production_detection=false`. They can test the
API and mitigation control flow. They cannot produce a `verified_cleared`
result.

```bash
dewatermark detectors list
dewatermark detectors doctor
dewatermark detectors conformance
dewatermark detectors conformance --scheme kgw
```

`list` and `doctor` read static manifests only. They do not import an entry
point, start a command, load a model, read input text, or open a socket.
`conformance` runs the dependency-free built-ins and reports vector names and
mismatched fields without returning vector text.

```python
from dewatermark import generate_reference_text, inspect

fixture = generate_reference_text("kgw-word-v1", token_count=96, seed=11)
evidence = inspect(fixture, detector="reference-kgw")
assert evidence.status == "detected"
assert evidence.details["vendor_equivalent"] is False
```

## Exact natural-text KGW and Unigram profiles

The packaged [`KGW`](../adapters/kgw) and
[`Unigram`](../adapters/unigram) packs each include a dependency-free natural
text detector for one exact public configuration. These are stronger
conformance fixtures than the built-in word schemes, but they are still not
general-purpose detectors.

| Pack | Exact behavior | Decision rule |
| --- | --- | --- |
| KGW | NFC plus casefold, 256-word vocabulary, opaque key ID, `simple_1` green-transition table, repeated-bigram filtering | Higher z-score is positive only when `z > 4.0` |
| Unigram | NFC plus casefold, 256-word vocabulary, opaque key ID and green mask, unique-token finite-population correction | Higher adjusted z-score is positive only when `z > 2.3263478740408408` (`alpha=0.01`) |

Both profiles pin the tokenizer, executable reference material, upstream
revision, threshold record, configuration digest, and conformance record. Their
golden vectors cover a positive sample, a same-length negative control, a
readable positive variant, and a short-text abstention. The conformance record contains only case
names and field mismatches.

The vocabulary is deliberately closed. An unknown word returns `unsupported`.
KGW requires at least 32 unique bigrams; Unigram requires at least 32 unique
tokens. Shorter inputs return `insufficient_evidence`.

The profiles agree with the pinned public implementations for these exact
configurations. That agreement does not carry over to a different tokenizer,
vocabulary, key, runtime, or watermark variant. The thresholds have not been
calibrated on adequate matched natural-text controls. Both manifests therefore
remain `calibrated=false`, `production_detection=false`, and
`vendor_equivalent=false`. They cannot approve a changed mitigation result.

Run the portable checks without a network, model, PyTorch, or Transformers:

```bash
dewatermark detectors packs
dewatermark detectors scaffold --pack kgw --output ./kgw-pack
dewatermark detectors scaffold --pack unigram --output ./unigram-pack
python ./kgw-pack/natural_conformance.py
python ./unigram-pack/natural_conformance.py
```

The KGW pack also keeps the older token-ID adapter around the pinned
`jwkirchenbauer/lm-watermarking` detector. It is useful for command-boundary
tests, not natural-language detection.

## Sealed local Hugging Face operator adapters

Each KGW and Unigram pack also contains `seal_operator.py` and
`operator_adapter.py`. This path lets an operator use arbitrary natural text
with a real tokenizer snapshot and a private key while keeping both local.

Sealing checks and records:

- every file in the local Hugging Face tokenizer snapshot;
- the tokenizer revision and vocabulary size;
- the pinned upstream detector source;
- the Python/platform byte order and every imported numerical/tokenizer runtime version;
- the public detector settings and threshold-evidence digest; and
- an opaque, operator-assigned key ID that is not derived from the private key.

On POSIX, the key must be an owner-only regular file outside the repository
with mode `0600` and a closed structured JSON record containing
`schema_version`, a 32-hex-character `key_id`, and integer `key`. Unigram keys
are restricted to the upstream NumPy 32-bit seed range (`0..4294967295`). The
reference operator adapter fails closed on Windows,
where it cannot prove equivalent ACL isolation; a Windows-specific adapter must
validate that ACL before reading the key. Raw key material is not placed in
argv, the environment, manifests, responses, errors, or object representations.
Runtime tokenizer loading uses
`local_files_only=True` and `trust_remote_code=False`; the adapter never resolves
a model identifier or downloads a tokenizer.

`seal_operator.py` publishes a new directory containing `operator-config.json`
and `operator-capability.json` as one atomic unit. It refuses an existing output
directory. The adapter then runs through the same bounded `CommandDetector`
protocol as other external detectors.

"Sealed" means that the public configuration is bound to exact local material.
It does not mean signed, calibrated, independent, or production-ready. A newly
sealed capability remains `calibrated=false`, `independent=false`,
`production_detection=false`, and `vendor_equivalent=false`. Promote it under a
new identifier only after separate implementation conformance and adequate
matched-null calibration have been reviewed.

Static discovery of a sealed capability does not read its tokenizer, key,
upstream checkout, or model files. Those files are touched only when the
operator explicitly runs detection.

## Sealed SynthID Text research adapter

[`adapters/synthid`](../adapters/synthid) pins a public SynthID Text source
revision and the exact source files used for hashing, masking, and scoring. Its
sealer binds one local tokenizer snapshot, opaque key ID, owner-managed key
file, masking/generation configuration, score definition, effective-length
interval, and public threshold-evidence record. The executable adapter supports
mean and explicit weighted-mean scoring plus bounded token-to-character
contribution ranges for guided candidate generation.

The checked-in vectors establish only same-implementation conformance. Every
newly sealed capability remains uncalibrated and non-independent, and the
public research repository does not contain Gemini or Claude production keys
or configuration. The pack and tournament fixture therefore provide neither
vendor production detection nor verified vendor-watermark removal.

## Process boundary

Detector and strategy commands share the package's bounded subprocess runner.
It uses immutable argv with `shell=False`, limits stdout, stderr, and wall time,
and terminates the process tree on failure. Public errors contain a failure
class and, when safe, an exit status. They do not contain argv, input text,
process output, or environment values.

The executable is operator-trusted code, not a sandbox. Put an untrusted
research repository in a container or operating-system sandbox. See
[Detectors](DETECTORS.md) for registration and calibration rules and
[Detector-guided mitigation](DETECTOR_GUIDED_MITIGATION.md) for how a detector
is used during search.

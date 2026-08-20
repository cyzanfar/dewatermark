# Sealed SynthID Text research adapter

This pack is an executable, offline detector for an **operator-controlled
configuration** of the public
[`google-deepmind/synthid-text`](https://github.com/google-deepmind/synthid-text)
research algorithm. It pins revision
`addb4a158143c7c6851a1308f78b89fceed59683` and the exact source files that
define hashing, masking, and mean scoring. The sealed target also binds the
operator's generation temperature, top-k behavior, tournament leaves, and
first-ngram behavior. Those settings do not change detector g-values, but they
do change the generated distribution and therefore the calibration scope.

This is not a Gemini or Claude detector. Production keys, tokenizer/config
choices, detector models, and calibrated thresholds are not public. A sealed
configuration therefore always declares `calibrated=false`,
`independent=false`, `production_detection=false`, and
`vendor_equivalent=false`.

## Exact scope

`operator_adapter.py` implements the pinned public algorithm's little-endian
signed-int64 hash chain and g-values, bounded context-repetition mask, first-EOS
mask, and mean or explicit weighted-mean formula. Hashing, g-values, and masks
are replayed against the pinned DeepMind source. The final score uses Python
binary64 arithmetic. It is not claimed to be bit-identical to a JAX float32
score near a threshold; thresholds must be calibrated for this sealed wrapper.

The adapter supports one fixed threshold and one effective-length interval per
detector identifier. Command protocol 1.2 binds that threshold in the static
capability, so a response cannot silently choose another length-specific
threshold.

`fixture-cases.json` contains public synthetic token-ID vectors covering both
scores, repeated contexts, EOS masking, and bounded token-to-character
attribution. Run the dependency-free replay:

```bash
python conformance.py
```

The conformance record contains only fixture identifiers, counts, and digests.
It is same-implementation evidence, not independent validation or false-positive
calibration. To reproduce the separate pinned-source replay with local source
and dependencies, run:

```bash
python upstream_conformance.py --upstream-dir /local/synthid-text
```

That command requires exactly PyTorch 2.4.0 and Transformers 4.43.3, verifies
the three source hashes before importing them, runs with no network calls, and
must reproduce `upstream-conformance-record.json`. Its scope is g-values and
repetition/EOS masks, not final-score numeric equivalence or production behavior.

## Private key and public inputs

Keep the key outside the repository in an operator-owned POSIX regular file
with mode `0600`. Its complete value is a closed JSON object:

```json
{
  "schema_version": "1.0",
  "key_id": "0123456789abcdef0123456789abcdef",
  "keys": [12345, 67890, 13579]
}
```

`key_id` is a random, opaque operator label. It must never be derived from the
keys or reused for another key list. The key list length is the watermarking
depth. Key values are unique, non-negative values in the signed-int64 range
because the pinned public hash implementation stores them in `torch.long`.

The sealer also creates a separate owner-only binding record. It binds this key
file to the exact public configuration using a private key-material digest. The
digest stays only in that `0600` private file; it never appears in the public
configuration, capability, reports, logs, or errors. Keep the key and binding
files together under the same private operator controls. An actor able to
replace both private files is outside this local drift-control boundary.

Copy `threshold-evidence.template.json` and replace its example values. The
threshold-evidence file is public and has exactly these fields:

```json
{
  "schema_version": "1.0",
  "evidence_id": "00000000000000000000000000000000",
  "empirical_calibration": false,
  "detector_type": "mean",
  "score": "mean_g_value",
  "threshold_operator": ">",
  "threshold": 0.6,
  "minimum_effective_tokens": 32,
  "maximum_effective_tokens": 4096
}
```

For `weighted_mean`, use `score: "weighted_mean_g_value"`. The sealer checks
the complete closed record before publishing its digest. An operator-provided
evidence file never upgrades the pack's calibration claim.

## Seal one target

Use an already checked-out copy of the upstream repository at the pinned
revision and a complete local Hugging Face tokenizer directory. No model name
or network resource is accepted.

```bash
python seal_operator.py \
  --upstream-dir /local/synthid-text \
  --tokenizer-dir /local/tokenizer-snapshot \
  --tokenizer-revision operator-tokenizer-v1 \
  --key-file /private/synthid-key.json \
  --secret-binding-output /private/synthid-key-binding.json \
  --threshold-evidence /public/threshold-evidence.json \
  --output-dir /public/synthid-mean-v1 \
  --identifier operator/synthid-text-mean-v1 \
  --scheme synthid-text/public-reference-v1 \
  --vocab-size 32000 \
  --eos-token-id 2 \
  --generation-temperature 0.7 \
  --generation-top-k 40 \
  --ngram-len 5 \
  --context-history-size 1024 \
  --watermarking-depth 30 \
  --detector-type mean \
  --threshold 0.6 \
  --minimum-effective-tokens 32 \
  --maximum-effective-tokens 4096 \
  --maximum-attributions 256
```

For `weighted_mean`, pass `--detector-type weighted_mean`. Without
`--weights-json`, the sealer binds the public reference's default linearly
decreasing weights from 10 to 1. A supplied weights file must be a JSON list of
non-negative finite numbers with exactly one entry per depth.

The sealed work bound also requires `(maximum_input_tokens - ngram_len + 1) *
watermarking_depth <= 1,000,000`, limits context history to 65,536 entries, and
never allows more than 512 attribution spans or more spans than the supported
effective-token maximum. The 512-span pack cap keeps worst-case output below
the command detector's default bounded stdout capture.
The default maximum input is 32,768 tokens; lower it for deep watermark targets.

Sealing validates the source hashes, tokenizer file names and contents, private
key permissions/shape, threshold evidence, public conformance corpus, tokenizer
vocabulary/EOS ID, and exact Python/platform/Transformers/tokenizers versions
before publication. Only little-endian runtimes are supported. It exclusively
creates the owner-only binding file, then atomically publishes a new public
directory containing only:

- `operator-config.json`
- `operator-capability.json`

It refuses to replace either destination. If the process reports a publication
failure, it removes the new binding file and staged public files. A process or
host crash can leave an unreferenced private binding file; it cannot expose a
partially published public configuration. The public files contain the opaque
key and binding IDs but never key values or a key-derived digest.

The tokenizer must be a fast tokenizer with a working local offset mapping.
Tokenizer files are read as bounded regular files before their hashes become
public. Secret-like names/content, URL credentials, private absolute paths,
unsafe JSON, and symlinks are rejected. Bounded binary `.model` files are
supported after printable content is screened. Detection then uses
`AutoTokenizer.from_pretrained(..., local_files_only=True,
trust_remote_code=False)` and checks the full snapshot again before tokenizing
text.

The detector receives text, not the token IDs used during generation. The
sealed target therefore binds this exact boundary: generation serializes with
`tokenizer.decode(..., skip_special_tokens=False,
clean_up_tokenization_spaces=False)`, and detection re-tokenizes that UTF-8 text
with `add_special_tokens=False`. A content-free conformance digest binds four
public text-to-token/offset probes. Tokenizer normalization is not generally
invertible, so this pack scores the re-tokenized text IDs and does not claim
that they always equal the generator's original IDs.

## Register and run

Register the generated `operator-capability.json` with a local
`CommandDetector` whose argv invokes:

```text
python operator_adapter.py
  --configuration /public/synthid-mean-v1/operator-config.json
  --upstream-dir /local/synthid-text
  --tokenizer-dir /local/tokenizer-snapshot
  --key-file /private/synthid-key.json
  --secret-file /private/synthid-key-binding.json
```

The adapter accepts only command protocol 1.2 requests whose network and model
download permissions are both false. Its output is a bounded JSON object with
only fixed field names, numeric results, and closed reason codes. It does not
return tokens, masks, text fragments, paths, key material, or dependency error
details. For each unmasked n-gram, it maps the last token back to a half-open
character range and assigns that token's mean or weighted-mean g-value
contribution. It keeps at most the capability's highest-scoring spans, then
returns them in non-overlapping source order. Invalid or unavailable offset
mapping fails closed instead of emitting guessed locations.

Recommended registered names are:

- detector: `operator/synthid-text-mean-v1` or
  `operator/synthid-text-weighted-mean-v1`
- scheme: `synthid-text/public-reference-v1`
- target: the generated capability's `watermark_target_sha256`
- configuration: the generated capability's `configuration_sha256`

These are recommendations, not vendor names. The sealer rejects identifiers
outside the `operator/synthid-text-*` namespace and rejects every other scheme,
so it cannot mint a Claude, Gemini, or other vendor-shaped claim. A different
scorer or threshold needs a new detector configuration, but mean and
weighted-mean detectors share one target when the key, tokenizer, serialization,
and embedding settings are the same. The target excludes scorer weights and
thresholds. The detector implementation commitment separately binds this port,
the pinned source closure, numerical semantics, and runtime versions.

## Mitigation-profile starting point

After registering this detector, a genuinely distinct held-out verifier, and
one or more candidate strategies, build a profile with
`build_mitigation_profile()` using the exact generated scheme, target digest,
and key ID. Start with `protocol_only_no_results`; never mark aggregate evidence
verified until the exact public observation bundle passes semantic replay.

```python
profile = build_mitigation_profile(
    "operator/synthid-text-mean-mitigation-v1",
    scheme="synthid-text/public-reference-v1",
    watermark_target_sha256=capability["metadata"]["watermark_target_sha256"],
    key_id=capability["metadata"]["key_id"],
    primary_detector="operator/synthid-text-mean-v1",
    verifier_detectors=["operator/synthid-text-mean-held-out-v1"],
    strategies=[("context-aware-minimal-edit-v1", {"context_influence": 2})],
    protocol_sha256=protocol_sha256,
)
```

The operator must supply a truly separate verifier bound to the same target and
opaque key ID. Evaluation and calibration should additionally use disjoint
held-out key cohorts. This pack's own capability is non-independent and cannot
by itself satisfy the verified-removal gate.

# Pinned upstream KGW adapter

This pack wraps `WatermarkDetector` from
`jwkirchenbauer/lm-watermarking@82922516930c02f8aa322765defdb5863d07a00e`
(Apache-2.0). It does not copy the detector algorithm. Before import it checks
the pinned `watermark_processor.py` SHA-256, then runs the project’s bounded
JSON command protocol with networking and model downloads disabled.

The checked-in configuration intentionally accepts only public fixture tokens
such as `t17`. It proves that the command boundary and pinned upstream class can
interoperate offline; it does **not** detect natural-language KGW output and is
not calibrated for a false-positive rate. `capability.json` therefore declares
`calibrated=false`, `production_detection=false`, and `vendor_equivalent=false`.

Clone the upstream repository at the exact revision into an isolated
environment and install its dependencies. Register `adapter.py` with argv
`--upstream-dir /absolute/path/to/lm-watermarking` and the static capability.
Run `python conformance.py --upstream-dir /absolute/path/to/lm-watermarking`.
The checked-in positive, matched control, and typed-abstention vectors were
recorded with CPU PyTorch 2.4.1 and the pinned source. Conformance reports only
case names and mismatched fields; it never repeats vector text. Re-run and
retain that report for the exact packaged environment before publishing.

A natural-language adapter must additionally pin the exact tokenizer files,
normalization policy, key, seeding scheme, device RNG behavior, calibration
population, length bins, and thresholds. Create a separate configuration and
capability identifier; do not upgrade this fixture’s claims.

## Exact natural-text reference configuration

`natural_adapter.py` is a second, dependency-free scorer for one exact public
reference configuration. Its NFC/casefold lexicon, 256-token vocabulary,
opaque key identifier, upstream-derived green-transition table, threshold evidence,
and upstream revision are all content-addressed. Four fluent natural-language
vectors cover a positive, same-length negative control, readable positive
variant, and typed
short-text abstention. `natural-conformance-record.json` records agreement with
the pinned author implementation without including vector text or raw key
material.

This is deliberately a **closed-vocabulary conformance profile**, not a useful
detector for arbitrary prose. An unknown lexeme returns `unsupported`; fewer
than 32 unique bigrams returns `insufficient_evidence`. The normal-approximation
threshold has not received empirical matched-null calibration, so
`natural-capability.json` remains `calibrated=false` and
`production_detection=false`. Exact agreement for this profile does not imply
agreement for another tokenizer, vocabulary, key, runtime, or KGW variant.

Run the portable checks without a network, model, PyTorch, or Transformers:

```bash
python natural_conformance.py
python natural_adapter.py < request.json
```

`natural-profile-material.json` hashes the executable reference materials. The
standalone profile is not separately signed; released wheels and source
archives inherit the repository's GitHub OIDC provenance attestation. Verify
the containing distribution before relying on those hashes.

## Arbitrary local tokenizer operator adapter

`operator_adapter.py` supports natural text from a real, local Hugging Face
tokenizer snapshot. It never resolves a model identifier and calls
`AutoTokenizer.from_pretrained(..., local_files_only=True,
trust_remote_code=False)`. Before text is tokenized it checks every tokenizer
file, the exact upstream source, Python/platform byte order and every imported
runtime dependency version, public configuration digest, and an owner-only key
file. Each tokenizer file is limited to 64 MiB; the complete snapshot is
limited to 128 files and 512 MiB. Credential-like filenames, credential-bearing
JSON/text, URL userinfo, and private absolute paths are rejected before any
file digest is published. Bounded binary `.model` artifacts remain supported
after their printable content is screened. Raw key material is absent
from argv, environment, manifests, responses, errors, and representations; argv
contains only the key file's path.

On POSIX, create an operator-owned key file outside the repository with mode
`0600`. Its complete contents are a structured record such as
`{"schema_version":"1.0","key_id":"0123456789abcdef0123456789abcdef","key":15485863}`.
The 32-hex-character `key_id` is an operator-assigned opaque identifier, never a
hash of the key. The sealer also requires `key * (vocab_size - 1)` to fit the
pinned implementation's signed 64-bit token arithmetic. Make an explicit
threshold-evidence JSON record, then run
`seal_operator.py`. The reference adapter fails closed on Windows because it
cannot validate an equivalent owner-only ACL; use a purpose-built adapter that
checks the Windows ACL before reading a key. Sealing
publishes a new directory containing `operator-config.json` and a static
`operator-capability.json` as one atomic unit and refuses an existing output
directory; it never
marks the result calibrated or independent. Register `operator_adapter.py` only
after separate upstream conformance and matched-null calibration. Discovery of
the generated capability does not read the tokenizer, key, model, or upstream
checkout.

The threshold-evidence file is a closed public record with exactly
`schema_version`, a 32-hex-character opaque `evidence_id`,
`empirical_calibration`, `gamma`, `minimum_effective_tokens`, `score` set to
`z_score`, `threshold`, and `threshold_operator` set to `>`. Its numeric fields
must equal the sealing arguments. The sealer publishes only its digest and will
not hash an arbitrary secret-bearing document into public configuration.

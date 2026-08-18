# Pinned Unigram natural-text reference pack

This pack follows `XuandongZhao/Unigram-Watermark` at revision
`b96cdb4d52771e3cbd543a9d9aeeaec8d0790ca2` (MIT). It provides two deliberately
separate integration paths and makes no vendor or universal-removal claim.

## Exact public reference configuration

`natural_adapter.py` independently scores the fixed green mask produced by the
pinned author implementation. The NFC/casefold tokenizer, 256-token vocabulary,
opaque key identifier, derived mask, unique-token finite-population correction,
alpha, and threshold evidence are content-addressed. Four fluent natural-text
vectors cover a positive, same-length negative control, readable positive
variant, and short
abstention. The checked conformance record contains only case names and field
mismatches; it never repeats vector text or raw key material.

The included tokenizer is a **closed-vocabulary conformance fixture**. It is not
the tokenizer of an arbitrary language model. Unknown lexemes return
`unsupported`, and fewer than 32 unique tokens returns
`insufficient_evidence`. The reported p-value uses the published analytical
finite-population correction; it has not been calibrated against an adequate
matched null population. Accordingly `natural-capability.json` declares
`calibrated=false`, `production_detection=false`, and
`vendor_equivalent=false`.

Run the portable profile fully offline:

```bash
python natural_conformance.py
python natural_adapter.py < request.json
```

`natural-profile-material.json` hashes the reference materials. It has no
standalone signature; released project artifacts inherit GitHub OIDC provenance
attestations. Verify the containing wheel or source archive before relying on
the material hashes.

## Arbitrary local tokenizer operator adapter

`operator_adapter.py` is the path for a real local Hugging Face tokenizer and a
private operator key. `seal_operator.py` snapshots every tokenizer file, pins
Python/platform byte order, NumPy, SciPy, tokenizers, PyTorch, Transformers, and
the upstream source, binds an operator-assigned opaque key ID—but never
publishes the key—and emits a static public configuration/capability. Each
tokenizer file is limited to 64 MiB; the whole snapshot is limited to 128 files
and 512 MiB. Credential-like filenames, credential-bearing JSON/text, URL
userinfo, and private absolute paths are rejected before any file digest is
published. Bounded binary `.model` artifacts remain supported after their
printable content is screened. Runtime
uses `local_files_only=True` and `trust_remote_code=False`; it never downloads a
model/tokenizer or opens a socket.

On POSIX, the key must be an owner-only regular file outside the repository
with mode `0600` containing exactly a structured JSON record such as
`{"schema_version":"1.0","key_id":"0123456789abcdef0123456789abcdef","key":15485863}`.
`key_id` is an opaque 32-hex-character operator identifier, not a hash of the
secret. The pinned Unigram implementation uses NumPy's 32-bit seed domain, so
`key` must be between `0` and `4294967295` inclusive. The reference adapter
fails closed on Windows because it
cannot validate an equivalent owner-only ACL; use a purpose-built adapter that
checks the Windows ACL before reading a key. The raw value is absent from argv,
environment, manifests, responses, errors, and representations. Static
discovery does not touch the key, tokenizer, model, or upstream checkout. The
sealer atomically publishes both public files in a new output directory and
refuses an existing directory. A
sealed adapter remains uncalibrated and non-independent until a separate
implementation passes conformance and adequate matched-null evidence is
reviewed.

The threshold-evidence file is a closed public record with exactly
`schema_version`, a 32-hex-character opaque `evidence_id`,
`empirical_calibration`, `alpha`, `fraction`, `minimum_effective_tokens`,
`score` set to `finite_population_adjusted_z_score`, `threshold`, and
`threshold_operator` set to `>`. Its numeric fields must equal the sealing
arguments and analytical quantile. The sealer publishes only its digest and
will not hash an arbitrary secret-bearing document into public configuration.

Rebuild the public derived mask only from an already-pinned local checkout with
`build_natural_profile.py`. That maintenance command accepts a key file, never a
raw key argument, and redacts failure details.

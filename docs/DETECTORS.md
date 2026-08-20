# Detectors

A detector result is meaningful only for its declared scheme and configuration.
That configuration includes an opaque key identifier (never a digest of a
low-entropy secret), tokenizer,
normalization, model or source revision, text-length rule, calibration
population, score direction, threshold, and threshold operator.

## Static capability manifest

Every detector exposes a `CapabilityManifest` before it receives text. Static
discovery must not import a model, run a command, open a socket, download a
file, or load untrusted plugin code.

```json
{
  "identifier": "example/kgw",
  "kind": "detector",
  "version": "1.2.3",
  "schemes": ["kgw"],
  "description": "Pinned independent KGW detector",
  "network_required": false,
  "model_download_possible": false,
  "requires_secret": false,
  "minimum_characters": 400,
  "calibrated": true,
  "independent": true,
  "metadata": {
    "configuration_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "implementation_sha256": "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    "watermark_target_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "minimum_effective_tokens": 100,
    "score_direction": "higher",
    "threshold": 4.0,
    "threshold_operator": ">",
    "calibration": "empirical_holdout",
    "source": "https://example.invalid/reference",
    "license": "Apache-2.0"
  }
}
```

The JSON form is validated by
[`detector-capability-v1.json`](../schemas/detector-capability-v1.json).
Detection fails closed when required configuration, threshold, score direction,
effective length, or calibration metadata is missing or inconsistent.

For held-out mitigation verification, every detector must also publish the same
`watermark_target_sha256`. It is a content hash of the watermarking target—the
scheme, opaque generation key identifier, tokenizer, and embedding settings—not
a hash of detector code or private key material. The runtime checks it, common
scheme support, a complete static decision contract, detector independence,
and duplicate identities before a verifier sees source text.

An exact `CommandDetector` used for held-out verification must also publish
`implementation_sha256`. This digest commits to the complete external detector
implementation: its executable or source and every pinned code or model
artifact that can change its decisions. It is not the Python command wrapper,
detector configuration, watermark target, or secret key. Two command detectors
with the same implementation digest are aliases, not independent verifiers.
The runtime binds two local code identities. A semantic Python-AST identity
normalizes comments, formatting, pass statements, and unused module constants
so cosmetic launcher copies cannot manufacture held-out independence. A
separate exact-raw identity covers every bounded executable and script byte; it
binds scoring caches and postflight checks, so even comment changes or values
read indirectly through `globals()` count as drift. Both readers accept only
bounded regular files and use nonblocking opens, so pipes and other special
files fail identity resolution instead of waiting for a writer. Syntactic
difference is not proof of methodological independence: `independent=true` and
the implementation commitment are trusted operator declarations that require
external review. Older manifests without this field can still run ordinary
detection, but they cannot take part in verified mitigation. Subclasses can add
uncommitted Python behavior, so only the exact `CommandDetector` wrapper is
accepted for this use.

Generic in-process extensions do not receive secrets. A keyed detector should
use an operator-owned command adapter with the key supplied through a dedicated
local file, not a manifest or general application credential.

## What is supported

| Surface | Current support | Limit |
| --- | --- | --- |
| Contextual Unicode artifacts | Built in | Literal code-point evidence, not model attribution |
| KGW and Unigram | Built-in fixtures and packaged reference packs | Reference packs are exact but uncalibrated and non-production |
| Arbitrary local KGW or Unigram tokenizer/key | Sealed operator adapter | Starts uncalibrated and non-independent |
| EXP/ITS and other distortion-free schemes | External adapter | Pin an author or independent implementation |
| SynthID Text | [Sealed operator research adapter](SYNTHID_LAB.md) | Research-only; no Gemini production key or production claim |
| Semantic watermark schemes | External adapter | Embedding model and partition settings are part of the configuration |
| Anthropic Claude production text | `unsupported` with `unsupported_pending_spec` metadata | The SynthID family is disclosed, but deployed configuration, keys, calibrated thresholds, and a detector contract remain pending |
| Other private provider schemes | `unsupported` | Unicode findings or a generic rewrite are not evidence of that scheme |

The dependency-free `reference-kgw`, `reference-unigram`, and
`reference-tournament` detectors are synthetic word-level fixtures. The
packaged KGW and Unigram natural-text profiles match one exact public
configuration but use closed 256-word vocabularies. All remain
`calibrated=false` and cannot verify production removal. See
[Reference detectors](REFERENCE_DETECTORS.md) for the exact boundary and the
sealed local Hugging Face operator path.

## Request-scoped detector use

`DetectorSession` owns detector access for localization and adaptive
mitigation. It caches by detector-policy digest and text digest, applies one
hard query limit, preflights batches before running them, and publishes a
content-free ledger. A detector policy change invalidates the session instead
of reusing old evidence. Public observations record both the text hash and
policy hash. A session cannot be reused across request contexts.

```python
from dewatermark import DetectorSession

session = DetectorSession(
    "search-detector",
    verifier_detectors=["held-out-detector"],
    max_queries=64,
)
observation = session.score(text)
```

The primary detector supplies search feedback. Held-out verifiers are queried
only after the search has selected a candidate. A verifier must be distinct
from the primary and every other verifier by object, declared configuration,
implementation, and static state. Every verifier must report a compatible
positive source and clear candidate through a detector declared both calibrated
and independent.

These checks support a narrow statement: the named configurations cleared the
candidate. They do not establish authorship or the absence of another
watermark.

## Localization

`localize(text, session, ...)` returns likely character ranges without changing
or returning the text in those ranges. It first requires the full document to
be detected. Native detector attribution is preferred. Otherwise, overlapping
windows are scored through the same query budget.

When a calibrated detector gives every window a compatible p-value, the
function applies a Bonferroni correction and may return `localized`. Native
ranges also require p-values and a declared calibrated family-wise error-control
contract (`metadata.localization_calibrated=true` and
`metadata.localization_error_control="familywise"`). A detector that is
uncalibrated or supplies status only may return
`localized_exploratory`; that label is an editing hint, not a controlled
statistical localization result.

See [Detector-guided mitigation](DETECTOR_GUIDED_MITIGATION.md) for the complete
search, verification, and rollback flow.

## Calibration before production use

- Keep calibration, attack development, and final test data separate.
- Match null text by generator, decoding settings, domain, language, and scored
  detector length.
- Record effective scored tokens and repeated-context masking.
- Use the detector's exact score direction and threshold operator.
- Prefer exact or non-asymptotic tests when available.
- Report empirical false-positive rates only when the null sample can resolve
  the requested operating point, and include a confidence interval.
- Test held-out keys or configurations when the threat model permits it.
- Recalibrate after a tokenizer, key, threshold, length rule, or population
  change.

With zero observed false positives, the approximate 95% upper confidence bound
is `3/n`. Very-low false-positive claims therefore need large independent null
sets or a separately justified exact null distribution.

## Command detector boundary

`CommandDetector` is the supported process boundary for a detector with heavy
or conflicting dependencies. Its manifest is available to planning without
starting the executable. Detection then:

1. checks network, model-download, input, and request budgets;
2. runs immutable tuple argv with `shell=False`;
3. sends one versioned JSON request and captures bounded stdout and stderr;
4. checks detector identity, scheme, configuration fingerprint, threshold,
   score direction, finite values, status consistency, and effective tokens;
5. returns scoped evidence or a redacted failure.

Command protocol 1.1 and newer detectors must declare and return
`threshold_operator` as one of `>`, `>=`, `<`, or `<=`; it must point in the
same direction as `score_direction`. Equality is detected only for an inclusive
operator. For compatibility, command protocol 1.0 treats the newer operator, implementation,
target, and secret-binding names as ignored extension metadata. Ordinary legacy
detection defaults to `>=` for higher scores and `<=` for lower scores. It cannot
take part in verified mitigation because its static decision contract is
incomplete. Unknown v1 response fields are ignored and are not copied into
public evidence. Contradictory decisions are still rejected.

Command protocol 1.2 can opt into native token attribution with
`attribution_kind="token_character_spans"` and a bounded
`maximum_attributions`. The request repeats that bound. The response then returns
ordered, non-overlapping half-open character ranges with finite numeric scores;
optional thresholds and p-values remain numeric metadata. Token strings and
arbitrary fields are rejected, so the normalized evidence contains offsets and
numbers only under `details.localization`. These spans guide localization and
candidate generation; they are not independently verified watermark evidence.
Protocols 1.0 and 1.1 continue to ignore colliding attribution extension names.

The command is trusted executable code, not a sandbox. Use a container or
operating-system boundary for untrusted research code. Conformance helpers
publish case names and mismatched fields only; they do not include vector text
or raw process output.

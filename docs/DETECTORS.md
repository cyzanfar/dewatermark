# Detector registry and capability policy

A detector is meaningful only with the scheme, key or configuration,
tokenizer, normalization policy, model revision, effective text length,
calibration population, and threshold that produced its score.

## Capability manifest

Every detector adapter must expose static metadata without importing a model,
opening a socket, or loading untrusted plugin code:

```json
{
  "identifier": "example/kgw",
  "kind": "detector",
  "version": "1.2.3",
  "schemes": ["kgw"],
  "description": "Pinned independent KGW detector",
  "network_required": false,
  "model_download_possible": false,
  "requires_secret": true,
  "minimum_characters": 400,
  "calibrated": true,
  "independent": true,
  "metadata": {
    "evidence_level": "independent_detector",
    "threat_models": ["T2", "T4"],
    "minimum_effective_tokens": 100,
    "score_direction": "higher",
    "calibration": "empirical_holdout",
    "source": "https://example.invalid/reference",
    "license": "Apache-2.0"
  }
}
```

This is the JSON form returned by `CapabilityManifest.to_dict()` and validated
by `schemas/detector-capability-v1.json`. Generic in-process extensions do not
receive secrets; use a purpose-built, operator-isolated adapter for a keyed
detector.

Runtime execution must fail closed when a required field, key/configuration
fingerprint, tokenizer revision, or calibration record is missing.

## Support matrix

| Surface | Runtime claim | Notes |
| --- | --- | --- |
| Contextual Unicode inspection | Built in | Literal artifact evidence, not model attribution |
| KGW / Unigram references | Evaluation or adapter | Verification requires exact tokenizer, key, implementation, and calibration |
| EXP/ITS and other distortion-free schemes | Adapter | Use a pinned author/reference implementation |
| SynthID-Text reference | Adapter | Supports the supplied reference keys/configuration, not private Gemini production keys |
| Semantic schemes | Adapter | Embedding model and partition configuration are detector inputs |
| Anthropic Claude production text | `unsupported` (`metadata.status=unsupported_pending_spec`) | Anthropic confirms marking for supported models launched on or after 2026-08-02 but has not released the mechanism or detector guidance |
| Other private provider schemes | `unsupported` | Do not infer support from invisible characters or a generic rewrite |

## Built-in reference fixtures versus real detectors

The `reference-kgw`, `reference-unigram`, and `reference-tournament` names are
dependency-free, word-level fixtures for integration tests. Their public keys,
tokenizer, generated vector text, and detector live in the same package, so
their manifests are intentionally neither calibrated nor independent. The
tournament fixture is not SynthID Text. See
[`REFERENCE_DETECTORS.md`](REFERENCE_DETECTORS.md) for the conformance commands,
pinned upstream packs, and promotion requirements.

## Calibration requirements

- Separate calibration, attack-development, and test partitions.
- Match nulls by generator, decoding settings, domain, language, and detector
  token length.
- Record effective scored tokens and repeated-context masking.
- Prefer exact or non-asymptotic tests when available.
- Report empirical FPR only when the null sample can resolve the requested
  operating point; include a confidence interval.
- Test held-out keys and configurations when the threat model permits it.
- Never reuse a threshold across tokenizer, key, length, or population changes
  without validation.

With zero observed false positives, the approximate 95% upper confidence bound
is `3/n`. Very-low-FPR claims therefore require correspondingly large,
independent null sets or a separately justified exact null distribution.

## Adapter isolation

Heavy or conflicting research implementations should run through the JSON
command adapter or an explicitly configured container. Adapter stderr and
provider response bodies are untrusted and are redacted from public results.
Golden vectors from the pinned upstream implementation are required before an
adapter can advertise validated support.

### Runtime command protocol

`dewatermark.CommandDetector` is the supported isolation boundary for a pinned
external detector. Its static `CapabilityManifest` is available to planning
without starting the command. Detection then:

1. checks declared network/model-download consent and input bounds;
2. executes immutable tuple argv with `shell=False`;
3. sends a versioned request on stdin and captures bounded stdout/stderr;
4. checks protocol major, detector/scheme, configuration fingerprint,
   threshold, score direction, finite values, status consistency, and minimum
   effective tokens;
5. returns scoped evidence or a redacted failure.

The command is operator-trusted executable code, not a sandbox. Use a container
or operating-system isolation for untrusted research repositories. Conformance
helpers publish only case names and mismatched field names; vector text and raw
process output are never included in reports.

# Assurance model

`dewatermark` distinguishes observation, transformation, and verification. A
text change is never, by itself, evidence that a statistical watermark was
removed.

## Pipeline

```text
inspect -> classify -> plan -> transform -> verify -> attest
```

1. An inspector identifies literal Unicode channels or selects a named
   statistical detector.
2. Planning resolves privacy, model, network, detector, and resource
   requirements without processing the source text.
3. Transformers produce untrusted candidates. They cannot commit output.
4. Central quality gates validate protected values, meaning, structure, and
   task-specific constraints.
5. A named detector measures the accepted candidate at its registered operating
   point when compatible verification is available.
6. The result records what was observed, what changed, what was verified, and
   what remains unknown.

All active text-receiving extensions must provide a static capability manifest
before construction or text access. Plans bind the active registration identity
and fail if it is replaced before apply. This guards cooperative policy and
consent; in-process Python extensions remain trusted dependencies rather than a
sandbox boundary.

## Detection states

- `detected`: evidence exceeded a named detector's registered threshold.
- `not_detected`: evidence did not exceed that threshold. This does not mean
  human-authored or watermark-free.
- `insufficient_evidence`: the text did not contain enough effective detector
  tokens or calibration was inadequate.
- `unsupported`: no compatible detector is installed or the scheme is private.
- `configuration_mismatch`: key, tokenizer, normalization, model, or detector
  configuration is incompatible.
- `detector_error`: the detector could not produce a valid result.

## Transformation outcomes

- `unchanged`: no accepted edit was made.
- `unicode_sanitized`: contextual Unicode edits were applied and re-inspected.
- `mitigation_verified`: a named detector was positive before transformation,
  below its registered threshold afterward, and all configured quality gates
  passed.
- `mitigation_unverified`: an accepted experimental transformation was applied,
  but compatible independent verification was unavailable.
- `rejected_quality`: candidates were generated but none passed every gate.
- `unsupported_scheme`: the requested claim cannot currently be tested.
- `failed`: processing failed without an accepted result.

The legacy `success`, `partial`, `unchanged`, and `failed` status remains in the
schema-1 compatibility envelope. New integrations should use the assurance
outcome instead.

## Evidence levels

From weakest to strongest:

1. `none`: no detector evidence.
2. `artifact`: literal channel inspection, such as contextual Unicode findings.
3. `surrogate`: a reference-free heuristic used only to rank candidates.
4. `same_implementation`: generation and detection share an implementation or
   configuration and may overestimate generalization.
5. `independent_detector`: a separately versioned detector with held-out
   calibration and a declared operating threshold.
6. `provider_detector`: a provider-authorized detector for the deployed scheme.

Only the final two levels can support a `mitigation_verified` claim. Even then,
the claim is scoped to the recorded detector and operating point.

## Threat models

- `T0`: scheme, key, and detector are unknown.
- `T1`: scheme and public implementation are known; key is hidden.
- `T2`: bounded detector queries are available.
- `T3`: generation-model token probabilities are available.
- `T4`: a secret key or private configuration is available for authorized
  research.

Results from one threat model must not be generalized to another.

## Evidence receipt

Receipts are JSON-compatible and contain no source text by default. They record:

- input and output SHA-256 digests;
- package, Unicode-policy, transform, and detector-capability versions;
- hashed model identifiers and detector/tokenizer revisions when declared;
- detector configuration fingerprints without secret key material;
- score, threshold, calibration metadata, and effective token count when reported;
- every quality-gate outcome and protected-span check;
- privacy consent and whether network or model acquisition occurred;
- remote-call, generated-token, latency, and candidate budgets;
- random seed, policy fingerprint, warnings, rejected-candidate reasons, and
  exact claim scope.

Receipts are evidence about a configured operation, not proof of authorship.

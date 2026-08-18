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
before construction or text access. Plans bind the active registration plus a
deterministic one-way fingerprint of observable class, instance, default, closure, and
capability state. The binding is checked again immediately before first use;
replacement or observable mutation requires re-registration/replanning. This
guards cooperative policy and consent; opaque state, races after validation,
and in-process Python semantics still require a trusted dependency or an OS
sandbox boundary.

## Detection states

- `detected`: evidence was on the positive side of a named detector's registered
  decision boundary.
- `not_detected`: evidence was on the clear side of that boundary. This does not mean
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
  clear at its registered decision boundary afterward, and all required quality
  gates passed.
- `mitigation_unverified`: an accepted experimental transformation was applied,
  but compatible independent verification was unavailable.
- `rejected_quality`: candidates were generated but none passed every required gate.
- `unsupported_scheme`: the requested claim cannot currently be tested.
- `failed`: processing failed without an accepted result.

The legacy `success`, `partial`, `unchanged`, and `failed` status remains in the
schema-1 compatibility envelope. New integrations should use the assurance
outcome instead.

## Evidence levels

The ordered evidence labels, from weakest to strongest, are:

1. `none`: no detector evidence.
2. `artifact`: literal channel inspection, such as contextual Unicode findings.
3. `surrogate`: a reference-free heuristic used only to rank candidates.
4. `same_implementation`: generation and detection share an implementation or
   configuration and may overestimate generalization.
5. `independent_detector`: a separately versioned detector with held-out
   calibration and a declared operating threshold.
6. `provider_detector`: a provider-authorized detector for the deployed scheme.

`same_policy` is a separate deterministic case rather than a rung in that
statistical ladder. The built-in Unicode sanitizer and verifier share the exact,
versioned literal-codepoint policy, so they can substantiate the narrowly scoped
`unicode_sanitized` result and paired `verified_cleared` verification state.
They are not independent statistical implementations and do not substantiate a
statistical `mitigation_verified` claim.

For a statistical detector, the enforcement contract is the capability's
literal `calibrated: true` **and** `independent: true` declarations. The
`independent_detector` and `provider_detector` metadata labels describe the
usual eligible evidence classes, but the label alone is not the enforcement
switch. Those booleans are trust assertions made by the adapter operator; the
runtime does not independently audit the underlying calibration study. Every
claim remains scoped to the recorded detector and operating point.

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
- every required and advisory quality-gate outcome and protected-span check;
- privacy consent and whether network or model acquisition occurred;
- remote-call, generated-token, latency, and candidate budgets;
- random seed, policy fingerprint, warnings, rejected-candidate reasons, and
  exact claim scope.

Receipts are evidence about a configured operation, not proof of authorship.

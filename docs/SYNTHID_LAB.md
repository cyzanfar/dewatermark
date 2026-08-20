# SynthID Text research lab

This lab turns public watermark mechanics into one exact, testable integration.
It does not reverse engineer, detect, or remove a private vendor deployment.

## What the InstaVM article teaches

The [interactive InstaVM article](https://instavm.io/blog/how-claudes-watermark-works)
is useful for understanding a distortion-free exponential-race watermark. Its
demo derives pseudorandom values from a public key and recent token context,
forces the token maximizing `log(r) / p`, and detects by summing
`-log(1-r)` contributions. That gives three useful engineering ideas:

1. the detector must bind the exact tokenizer, context rule, key identity, and
   score definition;
2. per-token contributions can be mapped back to character ranges and used as
   editing hints; and
3. detection thresholds need calibration by effective scored length rather
   than a universal visual cutoff.

The demo is not evidence of Claude's deployed algorithm. It uses a public demo
key, a small context rule, one browser model path, a normal approximation, and
heuristic display cutoffs. It does not publish Anthropic's key, tokenizer,
configuration, threshold calibration, or detector API.

## What public SynthID actually requires

The pinned [Google DeepMind reference repository](https://github.com/google-deepmind/synthid-text)
configuration used by this pack binds an n-gram length, a sequence of layer
keys, context-history size, generation sampling settings, and the tokenizer.
Detection computes per-token G values and combines end-of-sequence and
repeated-context masks. The research code supports mean, weighted-mean, and
trained Bayesian scoring; this initial sealed pack deliberately implements the
mean and explicit weighted-mean paths. Thresholds still need to be selected for
a target false-positive rate and effective-length interval.

The associated [Nature paper](https://www.nature.com/articles/s41586-024-08025-4)
describes SynthID-Text as a sampling-time watermark and evaluates quality and
detectability at scale. Neither the paper nor the research repository publishes
Gemini production keys. The repository also warns that its reference hashing
function does not promise cryptographic security.

## Pack boundary

`adapters/synthid/` provides an operator-sealed command detector for one exact
public research configuration. Sealing binds public source, tokenizer, scoring,
masking, calibration, and target metadata while the key values remain in an
owner-managed local file. The generated capability starts fail-closed:

- it is not a Claude or Gemini detector;
- it cannot be marked calibrated without a complete length-aware calibration
  artifact;
- it cannot be marked independent merely because it runs in another process;
- configuration, tokenizer, scorer, key-ID, or target mismatch returns an
  abstention rather than a guessed score; and
- discovery never starts the adapter or reads its key file.

Command detector protocol 1.2 can carry bounded token-to-character contribution
ranges. The host validates and publishes only numeric ranges; free-form adapter
diagnostics are discarded. These ranges feed `ContextAwareMinimalEditStrategy`,
whose proposals remain untrusted and can be accepted only by central quality
gates and a distinct held-out verifier.

For repeatable operation, bind the detector pair and strategy in an
[operator-scoped mitigation profile](MITIGATION_PROFILES.md). A newly sealed
profile should use `protocol_only_no_results`, not `aggregate_verified`.

## Evaluation protocol

`eval/protocols/synthid-v1.json` preregisters the existing strict benchmark
matrix for SynthID Text adapters: calibration/development/final splits,
split-disjoint private keys, matched decoding, human controls, fixed false-
positive rates, detector-effective length strata, a distinct cross-detector,
required quality/task checks, all-attempt denominators, run-wide budgets,
hash-chained resume, and exact aggregate replay.

A real study should additionally report, without changing the preregistered
primary endpoint:

- light proofreading and small edit-budget curves;
- truncation/excerpting and sentence reordering;
- translation and round-trip translation;
- wrong-key, other-model, and mixed human/generated controls;
- effective scored tokens and repeated-context masking rates; and
- false insertion and task-quality margins for every language/length stratum.

Those conditions require licensed corpora, private split-disjoint keys, a real
generator, two reviewed detector implementations, and blinded task assessment.
No such efficacy result is checked into this repository.

## Claude status

Anthropic has disclosed that its supported Claude marking uses a version of
SynthID-Text and has said detection guidance is forthcoming. That narrows the
scheme family, but it does not provide the exact deployed configuration or an
independent detector contract. `anthropic-claude` therefore remains
`unsupported_pending_spec`. A positive result from this public research pack
must never be presented as a Claude attribution, and a generic rewrite must
never be presented as verified Claude-watermark removal.

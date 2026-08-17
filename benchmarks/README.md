# Benchmarks

Tracked benchmark reports are evidence artifacts, not marketing fixtures.

- `unicode-v0.4.md` is a deterministic regression suite for five synthetic
  covert Unicode channels. It is not evidence of statistical or private-vendor
  watermark mitigation. Its
  [`unicode-v0.4.json`](unicode-v0.4.json) companion preserves the reported
  aggregate counts and explicitly marks unavailable historical provenance.
- Statistical results must follow
  [`docs/BENCHMARK_PROTOCOL.md`](../docs/BENCHMARK_PROTOCOL.md), identify every
  detector/configuration, and include machine-readable aggregate artifacts.

Generated sample text, checkpoints, model caches, and local evaluation outputs
are intentionally not committed by default. A result is eligible for the public
comparison table only when its manifest is reproducible, calibration and test
sets are disjoint, failures remain in the denominator, and quality acceptance
includes task-specific checks plus blinded human review where claimed.

## Evidence levels

| Level | Meaning | Comparative claims allowed? |
| --- | --- | --- |
| Fixture regression | Deterministic behavior on disclosed synthetic cases | No; report only the named fixture scope |
| Harness-capable | Source code implements a protocol component | No; capability is not an experimental result |
| Partial benchmark | A reproducible run satisfies only declared protocol rows | Only within the named strata and limitations |
| Protocol-complete benchmark | Every required row is run, recorded, and independently inspectable | Yes, for the named schemes, detectors, operating points, and threat models |

Every new tracked result must include a machine-readable companion with its
source commit, content-addressed run ID, policy/configuration digests, detector
manifests, sample counts, uncertainty, and explicit `not_run` reasons for
missing protocol rows. Historical artifacts may remain with `null` provenance
fields when the missing information is clearly disclosed; they are not valid
inputs to a leaderboard or superiority claim.

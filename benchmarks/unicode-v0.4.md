# Unicode covert-channel fixture benchmark — v0.4

Run on 2026-08-16 with Python 3.12.11 and seed 13:

```bash
PYTHONPATH=src python eval/run_eval.py --skip-statistical
```

Machine-readable aggregate: [`unicode-v0.4.json`](unicode-v0.4.json).

## Provenance caveat

This historical report predates the current content-addressed run manifest and
canonical Unicode policy. The report was first committed in
`3e9bf6477d5cb4e0ee429865fac4f0be84d138b0`, which is a repository snapshot and
reproduction anchor—not a run-recorded source revision. The original run did
not record a source commit, run ID, or Unicode-policy digest. Those values are
therefore `null` with reasons in the JSON companion. In particular, the digest
of today's `src/dewatermark/unicode_policy.json` must not be retroactively
assigned to this v0.4 result.

The suite embeds a known payload in ten cover texts per family, applies the explicitly lossy `aggressive` profile, and compares it with the same profile applied to the original cover.

| Family | Removed | Rate |
| --- | ---: | ---: |
| zero_width | 10/10 | 100% |
| variation_selector | 10/10 | 100% |
| tags_block | 10/10 | 100% |
| homoglyph | 10/10 | 100% |
| exotic_space | 10/10 | 100% |
| **overall** | **50/50** | **100%** |

This establishes deterministic behavior on disclosed fixtures. It does not establish success against statistical, semantic, cryptographic, retrieval-based, or undisclosed vendor watermarks. Statistical artifacts must name the generator, detector, key/configuration, threshold, length, matched controls, and quality metrics.

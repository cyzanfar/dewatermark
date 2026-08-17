# Unicode covert-channel fixture benchmark — v0.4

Run on 2026-08-16 with Python 3.12.11 and seed 13:

```bash
PYTHONPATH=src python eval/run_eval.py --skip-statistical
```

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

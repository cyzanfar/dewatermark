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

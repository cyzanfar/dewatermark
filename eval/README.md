# Evaluation harness

The packaged `dewatermark-eval` command regression-tests explicit aggressive
Unicode sanitation and measures statistical watermark detection after rewriting
with matched, transformed unwatermarked controls.

## Statistical validity

An empirical estimate is emitted only when the null set contains at least
`ceil(1/FPR)` examples: 100 for 1%, 1,000 for 0.1%, and 100,000 for 1e-5.
Watermarked positives and unwatermarked nulls pass through the same removal
mode. Use multiple seeds, models, tasks, and length sweeps.

The built-in KGW and Unigram implementations are internal references. EXP is a
simplified Gumbel approximation. None is independent vendor validation.

## Independent implementations

Adapters connect isolated MarkLLM, official SynthID-Text, semantic-watermark,
learned-detector, or authorized vendor environments. Each receives one JSON
object on stdin and returns one JSON object on stdout. No shell is invoked.

```json
{"protocol_version":"1.0","action":"generate","prompt":"...","max_new_tokens":250,"seed":1,"watermarked":true}
{"protocol_version":"1.0","action":"detect","text":"..."}
{"protocol_version":"1.0","action":"capabilities"}
```

Generation returns `{"protocol_version":"1.0","text":"..."}` and detection
returns `{"protocol_version":"1.0","score":1.23}`. Register an adapter with:

```bash
dewatermark-eval \
  --adapter 'SynthID|tournament|official-google|python /path/to/synthid_adapter.py' \
  --schemes SynthID --samples 100 --null-samples 1000
```

Detection is valid only for the exact scheme/key represented by the adapter.

## Commands and artifacts

```bash
dewatermark-eval --skip-statistical --output results.md
dewatermark-eval --schemes KGW,Unigram,EXP \
  --modes bias_inversion,sira,full \
  --samples 100 --null-samples 1000 \
  --lengths 100,250,500,1000,2000 \
  --model-revision MODEL_COMMIT --allow-model-download \
  --json-output results.json --checkpoint progress.jsonl
```

Runs stop on sample failure by default. `--failure-policy continue` records
failures explicitly; `--resume` reuses completed length sweeps from the
append-only checkpoint. JSON output records arguments, package versions,
hardware, and the prompt hash. Remote processing requires
`DEWATERMARK_ALLOW_REMOTE_PROCESSING=true`.

Per-sample checkpoint records contain scores, quality metrics, failures, and
source/candidate hashes. Raw text is excluded by default; use
`--include-text-artifacts` only with an appropriate data-handling policy.

Model acquisition is opt-in. For published results, replace `MODEL_COMMIT` with
an immutable revision and retain it in the generated manifest.

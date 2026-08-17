# Evaluation harness

The packaged `dewatermark-eval` command regression-tests explicit aggressive
Unicode sanitation and measures statistical watermark detection after rewriting
with matched, transformed unwatermarked controls.

## Statistical validity

An empirical estimate is emitted only when the null set contains at least
`ceil(1/FPR)` examples: 100 for 1%, 1,000 for 0.1%, and 100,000 for 1e-5.
The report marks an estimate as suitable for a more stable tail estimate only
at `20 * ceil(1/FPR)` nulls and always includes a Wilson interval. A dedicated
null population calibrates thresholds; a disjoint, matched null population
measures test FPR. Watermarked positives and both null populations pass through
the same removal mode. Use multiple seeds, models, tasks, and length sweeps.

Reported `cleared` outcomes are conditional on a named detector flagging the
original positive. `false insertion` is an initially unflagged null crossing
that detector's threshold after transformation. Neither is an authorship claim.
AUROC uses a deterministic stratified-bootstrap interval.

The built-in KGW and Unigram implementations are internal references. EXP is a
simplified Gumbel approximation. None is independent vendor validation.

## Independent implementations

Adapters connect isolated MarkLLM, official SynthID-Text, semantic-watermark,
learned-detector, or authorized vendor environments. Each receives one JSON
object on stdin and returns one JSON object on stdout. No shell is invoked, the
ambient environment is stripped of credentials, stderr is discarded, and JSON
request/response sizes and execution time are bounded.

```json
{"protocol_version":"1.0","policy":{"allow_network":false,"allow_model_download":false},"action":"generate","prompt":"...","max_new_tokens":250,"seed":1,"watermarked":true}
{"protocol_version":"1.0","action":"detect","text":"..."}
{"protocol_version":"1.0","action":"capabilities"}
```

Generation returns `{"protocol_version":"1.0","text":"..."}` and detection
returns `{"protocol_version":"1.0","score":1.23}`. Register an adapter with:

```bash
dewatermark-eval \
  --adapter 'SynthID|tournament|official-google|/path/to/synthid.manifest.json|python /path/to/synthid_adapter.py' \
  --schemes SynthID --samples 100 --null-samples 1000
```

Detection is valid only for the exact scheme/key represented by the adapter.
Independent classification is fail-closed. The preferred five-field adapter
registration points to a static JSON sidecar. Discovery reads that bounded file
and hashes local executable/script arguments; it never executes adapter code.
An adjacent `adapter.py.manifest.json`, `adapter.manifest.json`, or
`adapter-manifest.json` is also discovered for the four-field form. Without a
complete sidecar the command may still run, but results are explicitly
non-independent and are not safely resumable.

The sidecar binds `id`, `family`, `source`, `implementation`, immutable
implementation/model/tokenizer revisions, score direction, positive
`minimum_effective_tokens`, non-secret `configuration_sha256`, explicit network
and download requirements, and a passing `golden_conformance` object with
`vectors_sha256` and `report_sha256`. Runtime capabilities and each independent
score must match that configuration and those revisions. Detection below the
declared effective length is rejected rather than silently scored.

Apply a second, named detector to every generated/transformed population with
`--cross-detector NAME|FAMILY|SOURCE|SIDECAR|COMMAND`. Its thresholds and results are
recorded separately; they are never merged with the generating detector.

## Commands and artifacts

```bash
dewatermark-eval --skip-statistical --output results.md
dewatermark-eval --schemes KGW,Unigram,EXP \
  --modes bias_inversion,sira,full \
  --samples 100 --null-samples 1000 \
  --lengths 100,250,500,1000,2000 \
  --model-revision MODEL_COMMIT --allow-network --allow-model-download \
  --json-output results.json --checkpoint progress.jsonl
```

Runs stop on sample failure by default. `--failure-policy continue` records
failure classes without persisting provider messages. Every checkpoint event
has a content-addressed run identity over arguments, prompts, the complete
library and evaluation source trees, canonical Unicode policy, source
commit/dirty state, package/backend revisions, and adapter sidecar/executable
digests. `--resume` refuses incompatible checkpoints and unresolved identities,
including an unpinned statistical generator revision.

Each primary and cross-detector result includes content-addressed, no-text score
tables for positive, held-out-null, and threshold-calibration cohorts. Rows
record source/candidate scores and flags, requested and adapter-reported
effective lengths, transformation outcomes, failure/abstention, and prompt
cluster. JSON and Markdown expose denominators, cross-detector confusion, and
composite success (detector clear + accepted transform + quality pass).

Legacy per-sample checkpoint records contain quality metrics, failures, and
source/candidate hashes. Raw text is excluded by default; use
`--include-text-artifacts` only with an appropriate data-handling policy.

Network access and model acquisition are separate opt-ins, and a download
requires both. Learned quality metrics obey the same policy: cached MiniLM can
load with `local_files_only`; BERTScore and MAUVE remain unavailable unless both
permissions are explicit. For published results, replace `MODEL_COMMIT` with an
immutable revision and retain it in the generated manifest.

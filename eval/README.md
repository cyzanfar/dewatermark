# Evaluation harness

The packaged `dewatermark-eval` command regression-tests explicit aggressive
Unicode sanitation and measures statistical watermark detection after rewriting
with matched, transformed unwatermarked controls.

## Statistical validity

An empirical estimate is emitted only when the null set contains at least
`ceil(1/FPR)` examples: 100 for 1%, 1,000 for 0.1%, and 100,000 for 1e-5.
The report marks an estimate as suitable for a more stable tail estimate only
at `20 * ceil(1/FPR)` null samples **and independent prompt/document clusters**
and always includes a Wilson interval. A dedicated null population calibrates
thresholds; a disjoint, matched null population measures test FPR. Watermarked
positives and both null populations pass through the same removal mode. Use
multiple seeds, models, tasks, and length sweeps.

Reported `cleared` outcomes are conditional on a named detector flagging the
original positive. `false insertion` is an initially unflagged null crossing
that detector's threshold after transformation. Neither is an authorship claim.
AUROC uses deterministic prompt/document-cluster bootstrap intervals. The JSON
also includes a paired candidate-minus-source AUROC interval and paired cluster
rate deltas at every requested fixed FPR. These intervals condition on the
thresholds calibrated on the disjoint null split; they do not disguise that
conditioning as full threshold-uncertainty propagation.

Registered condition comparisons use a two-sided exact binomial sign test over
independent cluster summaries, followed by the frozen Holm correction. The
exact tail is evaluated numerically without enormous integer intermediates,
and comparison work is bounded before it can enter a public aggregate.

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

The default `eval/RESULTS.md` is a generated, git-ignored local artifact, not a
checked-in benchmark result. Prefer an explicit fresh output directory, as
below; no generated default report is release evidence.

```bash
run_dir="$(mktemp -d)"
dewatermark-eval --skip-statistical \
  --output "$run_dir/results.md" \
  --json-output "$run_dir/results.json" \
  --checkpoint "$run_dir/progress.jsonl"

# Start a different run in a fresh directory.
run_dir="$(mktemp -d)"
dewatermark-eval --schemes KGW,Unigram,EXP \
  --modes bias_inversion,sira,full \
  --samples 100 --null-samples 1000 \
  --lengths 100,250,500,1000,2000 \
  --model-revision MODEL_COMMIT --allow-network --allow-model-download \
  --output "$run_dir/results.md" \
  --json-output "$run_dir/results.json" \
  --checkpoint "$run_dir/progress.jsonl"
```

Runs stop on sample failure by default. `--failure-policy continue` records
closed, host-defined failure codes without persisting provider messages or
adapter-supplied labels. Strict aggregation contracts 1.1 and 1.2 reject any other
`error_class`; unmarked legacy v1 observations retain their open-token
compatibility but are not statistically verified. Every checkpoint event
has a content-addressed run identity over arguments, prompts, the complete
library and evaluation source trees, canonical Unicode policy, source
commit/dirty state, package/backend revisions, and adapter sidecar/executable
digests. `--resume` refuses incompatible checkpoints and unresolved identities,
including an unpinned statistical generator revision.
To continue the same run against the same checkpoint, repeat its command with
`--resume`; otherwise use a fresh run directory.

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

## Protocol-complete evidence path

`dewatermark-eval` is an exploratory generator runner. The stricter evidence
path is `dewatermark-evidence`, backed by the canonical
`protocol-registry-v1.json` and versioned public JSON schemas. It does not import a
detector or touch a model while validating or aggregating.

The `run` subcommand connects execution to that strict evidence path. It uses
the checked-in KGW or SynthID Text preregistration and frozen comparator registry, generates
matched marked/unmarked samples through an adapter, runs every registered
condition and named detector, applies quality and task checks, and creates the
sample registry, observations, aggregate, checkpoint, and evidence bundle in
one command:

```bash
dewatermark-evidence run \
  --protocol-manifest protocols/synthid-v1.json \
  --run-config private-run-config.json \
  --input-corpus private-input-corpus.json \
  --output-directory evidence/synthid-run

# Continue only the exact same scientific run after interruption.
dewatermark-evidence run \
  --protocol-manifest protocols/synthid-v1.json \
  --run-config private-run-config.json \
  --input-corpus private-input-corpus.json \
  --output-directory evidence/synthid-run \
  --resume
```

See [PROTOCOL_RUN.md](PROTOCOL_RUN.md) for the local config, private input, and
adapter contracts. The command never writes raw prompts or generated text to
the checkpoint or public artifacts. Network and model acquisition remain off
unless their separate flags are supplied.

New real-adapter runs set `aggregation_contract_version: "1.2"`. It adds the
preregistered watermark family to the 1.1 bootstrap, comparator, sample,
observation, and result commitments. `verify` deterministically recomputes the
public aggregate for both the v0.7 1.1 contract and the family-bound 1.2
contract; a successful verification reports `aggregate_verified: true`.
Unmarked legacy v1 bundles can remain structurally and content-address valid,
but report `aggregate_verified: false` and cannot establish a verified
aggregate claim.

The run config uses explicit argv arrays, private split-specific key-slot
handles, and independent CSPRNG-generated public key-partition IDs. A public ID
must never be derived from a key or slot; the v1 artifact field
`key_fingerprint` is only a legacy name for that opaque ID. Run-wide limits
cover records, requested tokens, adapter processes, cancellation checks, and
elapsed time. Cancellation is checked before and after each adapter process, at
throttled intervals while it runs, throughout aggregation, and again before
publication; each actual operator callback is reserved in the hash-chained
checkpoint first.
The absolute deadline is rechecked after aggregation, before artifact writes,
and before the completion record is committed. Adapters
must echo the requested private key slot. Marked and null members of a pair must
echo one shared seed and one exact decoding commitment.
Before any adapter process starts, static sidecar,
command, executable/script, implementation, configuration, model, tokenizer,
and source digests are checked so a cross-detector cannot be registered as an
alias of the primary detector.

The resume checkpoint is hash-chained strict JSONL. It retains failed attempts,
resource records, and budget reservations across resumes, and permits recovery
only from a truncated final line. Comparative inference uses prompt/document
clusters, not rows. Every registered non-control comparator remains in its Holm
family; unavailable hypotheses are explicit non-estimable p=1 rows.

Bootstrap settings are bounded deterministic integers: replicates must be from
2 through 10,000, and the seed must be from 0 through 2^63 - 1. Booleans and
other integer-like values are rejected. The aggregator also rejects more than
5,000,000 row-replicate-metric work units. Lower the replicate count or shard a
frozen matrix that would exceed that deterministic CPU bound. Contract 1.1
reserves `::` as the unambiguous detector/condition group delimiter.

```bash
# Offline deterministic plumbing check (synthetic scores; never efficacy evidence)
dewatermark-evidence reference-protocol --output-directory reference-run
dewatermark-evidence verify reference-run/evidence.json

# Assemble already-frozen, content-free observations
dewatermark-evidence assemble \
  --sample-registry evidence/sample-registry.json \
  --observations evidence/observations.json \
  --comparator-registry evidence/comparator-registry.json \
  --output evidence/evidence.json \
  --purpose frozen_evaluation

# Print only the recipe digest and permission requirements; argv/paths stay local
dewatermark-evidence replay evidence/evidence.json

# Execute a custom run only with a bounded local recipe whose digest matches the bundle
replay_workspace="$(mktemp -d)"
dewatermark-evidence replay evidence/evidence.json \
  --recipe replay-recipe.json --workspace "$replay_workspace" --execute
```

`--comparator-registry` is required when strict 1.1 observations declare
`comparator_registry_sha256`; omit it only when the observations declare no
comparator.

`--execute` runs the digest-matched local command without a shell, with a
scrubbed environment and bounded output/time, but it is not an operating-system
sandbox. Pass a fresh disposable directory through `--workspace`, as above.
Result paths are contained and existing results are never overwritten.

The sample registry enforces disjoint calibration/development/final-test
clusters and keys, matched generator controls, provenance-bound human controls,
task checker kinds, exact detector-token bins, and the full final-test task ×
language × length × cohort matrix. Raw human inputs can be converted to digest
records with `protocol.human_control_records`; runtime text is returned only
with explicit opt-in and is never embedded in an evidence bundle.

Observation aggregation recalibrates each named detector/condition on the
calibration nulls, evaluates final matched and human controls, retains failures
and abstentions in the primary success denominator, emits cross-detector
confusion, and reports missing protocol areas instead of omitting them. A
source bundle cannot self-certify replication. Use a separate
`benchmark-replication-record-v1` record and `verify-replication` to cross-bind
the source and reproduced bundle. This verifies metadata and content identity,
not the operator's cryptographic identity; claim eligibility therefore remains
false until an external attestation verifier establishes independence.

Blinded human review is local-only. `review.create_blinded_review_packet`
requires explicit text-artifact consent, randomizes A/B ordering, and keeps the
method assignment key separate. `review.summarize_blinded_reviews` publishes a
content-free, assignment-cluster-bootstrap agreement record; it never promotes
human review into a substitute for task-specific checks.

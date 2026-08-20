# Running a real watermark benchmark

`dewatermark-evidence run` is the end-to-end benchmark command. It generates
matched marked and unmarked text, applies every frozen comparison method, runs
the primary and cross-detectors, checks quality and task success, and writes a
strict evidence bundle.

New real-adapter runs set `aggregation_contract_version: "1.2"` in the public
run manifest. It adds an exact watermark-family binding to the 1.1 bootstrap,
comparator, sample, observation, and result graph. `verify` exactly
reaggregates both the v0.7 1.1 contract and the family-bound 1.2 contract and
reports `aggregate_verified: true`. Unmarked legacy v1 bundles may remain
structurally and content-address valid, but report `aggregate_verified: false`
and do not establish a semantically verified aggregate.

The checked-in [KGW](protocols/kgw-v1.json) and
[SynthID Text](protocols/synthid-v1.json) protocols are real experiment
preregistrations, not results. Select the one matching the detector family in
the private run configuration; neither file is evidence that the named method
succeeds. The
[comparator registry](comparator-registry-v1.json) freezes these conditions
before execution:

- `no_attack`: identity control
- `reference`: this package, supplied through a pinned adapter
- `paraphrase`: pinned paraphrase baseline
- `bira`: pinned BIRA baseline
- `sira`: pinned SIRA baseline

Every executable condition must supply a static sidecar and is bound to the
SHA-256 of its runtime manifest. There are no placeholder implementation
hashes. Comparisons summarize success once per prompt or document cluster and
use an exact paired sign test. Holm correction always covers every registered
non-control condition in each detector and requested-FPR family. If a threshold
or comparator is unavailable, its registered hypothesis stays in the family
with `estimable: false` and `raw_p_value: 1.0`; the family never shrinks after
results are known.

## Files you provide

The local run config follows
[`benchmark-run-config-v1.json`](https://github.com/cyzanfar/text-watermark-remover/blob/v0.8.0/schemas/benchmark-run-config-v1.json). It names one generator/primary-detector
adapter, at least one cross-detector, four transform adapters, one quality
checker, and one task checker. Adapter entries use this shape:

```json
{
  "name": "kgw-primary",
  "family": "kgw",
  "source": "pinned-upstream",
  "sidecar": "/private/path/adapter-manifest.json",
  "argv": ["python", "/private/path/adapter.py"]
}
```

The argv array is passed directly to the process runner on Linux, macOS, and
Windows; no shell or platform-specific string splitting is involved.
Credentials are not allowed in argv and the child receives a stripped
environment. Use an isolated, operator-managed local broker when an adapter
needs credentials.

Each detector sidecar must include lowercase SHA-256 values for its
implementation, configuration, model, tokenizer, and source snapshot. Before
any adapter runs, the benchmark also hashes the sidecar, argv shape, executable,
and script. A primary detector and cross-detector cannot share the same static
identity under different names. This preflight detects aliases; it does not by
itself prove organizational independence.

The private input corpus follows
[`benchmark-input-corpus-v1.json`](https://github.com/cyzanfar/text-watermark-remover/blob/v0.7.0/schemas/benchmark-input-corpus-v1.json). Each record supplies a prompt and its
registered split, task, language, requested length, and cluster. A final-test
record can also supply a licensed human control and provenance metadata. Raw
prompts and human text stay in this private file and process memory.

Create the three public `key_ids` with a cryptographically secure random-number
generator: 32 random bytes rendered as 64 lowercase hex characters for each of
calibration, development, and final test. Set `key_id_policy` to
`csprng_256bit_non_secret`. These values are random public partition labels.
Never compute them from a watermark key or from a key-slot name. Public v1
artifacts retain the field name `key_fingerprint` for compatibility, but its
value has this opaque-ID meaning and is not a fingerprint.

The config also holds three distinct private `key_slots`: opaque handles
understood by the local adapter. A slot is not key material. The runner sends it
to generation and detection, requires the response to echo it exactly, and
never writes the slot—or a hash or commitment derived from it—to a checkpoint
or evidence artifact. Keep the config private.

The run-config schema deliberately rejects a `mitigation_profile_core_sha256`
field. This runner does not load or execute mitigation profiles and cannot
derive a trustworthy mapping from an arbitrary digest to the adapters,
strategies, quality policy, and limits used for a run. Generic benchmark
evidence remains independently verifiable, but profile v1 records only its
preregistered protocol digest and cannot attach a result bundle.

`execution_budget` is required and applies to the whole run, including every
resume:

```json
{
  "max_records": 10000,
  "max_requested_tokens": 10000000,
  "max_adapter_processes": 500000,
  "deadline_seconds": 86400,
  "max_cancellation_checks": 2000000
}
```

Reservations are written before token requests and process launches. Resume
replays those reservations instead of resetting them. Capability probes count
as adapter processes. Cancellation is checked before and after each process,
at throttled intervals while it is running, between bounded aggregation stages,
and before final publication; every actual check is reserved in the checkpoint
first. Size the limit for process checks, periodic checks over expected process
wall time, aggregation-stage checks, and final publication probes. The original
absolute deadline survives resume and is rechecked
after aggregation, before public artifact writes, and immediately before the
completion record.

`--bootstrap-replicates` accepts exact integers from 2 through 10,000.
`--bootstrap-seed` accepts exact integers from 0 through 2^63 - 1. These limits
combine with a 5,000,000 row-replicate-metric aggregation ceiling to keep all
post-adapter statistical work bounded. Lower the replicate count or shard a
larger frozen matrix. Strict aggregation contracts 1.1 and 1.2 reserve `::`
inside detector and condition identifiers so public group keys cannot collide.

## Adapter requests

Adapters receive one JSON object on stdin and return one JSON object on stdout.
All requests include `protocol_version` and a policy object. Marked and null
members of a pair receive the same `pair_seed`, token request, and
`decoding_config_sha256`; only `watermarked` differs. Generation must echo all
of those fields plus `key_slot`. Detection must echo `key_slot`:

```json
{"action":"generate","prompt":"...","max_new_tokens":256,"seed":7,"pair_seed":7,"watermarked":true,"key_slot":"operator-opaque-slot","decoding_config_sha256":"..."}
{"action":"detect","text":"...","key_slot":"operator-opaque-slot"}
```

The runner also sends:

```json
{"action":"transform","condition_id":"reference","source_text":"...","task":"open_ended_prose","language":"en","seed":1}
{"action":"quality_check","source_text":"...","candidate_text":"...","task":"open_ended_prose","language":"en","checker_kinds":["semantic","factual","protected_span"]}
{"action":"task_check","source_text":"...","candidate_text":"...","task":"open_ended_prose","language":"en","checker_kinds":["semantic","factual","protected_span"]}
```

An accepted transform returns `state: "accepted"` and `candidate_text`. A
transform may instead return `failed` or `abstained`. Adapter-supplied error
labels are ignored: strict 1.1 and 1.2 aggregation artifacts contain only the
runner's closed, content-free host failure codes. A checker returns
`state: "completed"` and a Boolean `passed`.
Every network-capable response must include auditable telemetry:

```json
{
  "remote_queries": 1,
  "generated_tokens": 240,
  "estimated_cost_usd": 0.0021
}
```

This object is returned under `telemetry`. Offline adapters may omit it when
their sidecar declares `network_required: false`; zero remote use and cost are
then factual consequences of the enforced policy boundary.

## Run and resume

```bash
dewatermark-evidence run \
  --protocol-manifest protocols/synthid-v1.json \
  --run-config private-run-config.json \
  --input-corpus private-input-corpus.json \
  --output-directory evidence/synthid-run
```

Add `--allow-network` only when a sidecar requires it. A model download also
requires `--allow-model-download`. After interruption, repeat the exact command
with `--resume`. The runner regenerates sources, checks that their registry
digest matches the checkpoint, and skips completed observations. A changed
corpus, adapter executable, sidecar, key partition, seed, or protocol produces
a different run ID and cannot reuse the checkpoint.

The checkpoint is strict, hash-chained JSONL. Duplicate JSON keys, non-finite
numbers, a changed complete record, a broken sequence, or a broken previous-hash
link aborts resume. Only an incomplete final line can be discarded and repaired.
Every adapter-process attempt and budget reservation is retained. A completed
run resumes by verifying and returning its existing bundle without launching an
adapter again.

The output directory contains:

- `sample-registry.json`: IDs, hashes, provenance, splits, and detector lengths
- `observations.json`: scores, states, gate outcomes, and per-call resources
- `comparator-registry.json`: the exact frozen comparison family used by the run
- `evidence.json`: content-addressed aggregate bundle; semantic aggregate
  verification is established only when `verify` reports
  `aggregate_verified: true`
- `progress.jsonl`: append-only, content-free resume checkpoint

Failures, abstentions, and failed attempts from earlier resumes stay in the
all-attempts success denominator. Missing required observations are counted as
failed attempts too. The observation artifact includes attempt history and the
run-wide process/budget ledger without adapter errors or content. Cross-detectors
keep their own effective token counts and declared score direction; raw scores
are preserved and lower-is-positive values are normalized for fixed-FPR,
stratum, and comparison calculations.

All public JSON is validated in memory before a temporary output file is
created. Public readers reject duplicate keys and non-finite values. Atomic
write cleanup removes only a temporary file created by the current process.

## What still requires real compute and data

The repository intentionally contains no claimed KGW or SynthID performance
result. A publishable run still needs licensed human controls, prompts covering
the full task × language × detector-length matrix, split-disjoint private keys,
pinned real generator and detector implementations, and enough independent
null clusters.
At 0.1% FPR, 1,000 calibration and 1,000 held-out null clusters are only the
minimum for an empirical estimate; the harness recommends 20,000 of each for a
less fragile tail estimate. Blinded human review and independent replication
remain separate requirements. The bundle will report these areas as incomplete
instead of turning absent work into a positive claim.

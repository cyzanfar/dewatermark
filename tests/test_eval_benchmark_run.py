import hashlib
import json
import math
import os
import sys
import time
from pathlib import Path

import benchmark_run as benchmark_run_module
import comparisons as comparisons_module
import pytest
from benchmark_run import (
    BenchmarkRunError,
    _adapter,
    _AdapterInvocationFailure,
    _call,
    _CheckpointJournal,
    _ExecutionBudget,
    _read_json,
    _validate_detector_independence,
    _write_json,
    run_benchmark,
)
from comparisons import (
    ComparatorValidationError,
    holm_adjust,
    load_comparator_registry,
    paired_comparator_analysis,
)
from evidence import EvidenceValidationError, _validate_cluster_comparative_analysis, read_bundle
from jsonschema import Draft202012Validator
from manifest import StrictJSONError, strict_json_loads


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _adapter_fixture(tmp_path):
    def entry(identifier):
        configuration_sha256 = _digest(f"fixture-configuration-{identifier}")
        script = tmp_path / f"{identifier}.py"
        script.write_text(
            """
import json
import sys

identifier = IDENTIFIER_PLACEHOLDER
request = json.load(sys.stdin)
telemetry = {
    "remote_queries": 0,
    "generated_tokens": 0,
    "estimated_cost_usd": 0.0,
}
manifest = {
    "id": identifier,
    "implementation_version": "fixture-commit",
    "configuration_sha256": CONFIGURATION_PLACEHOLDER,
    "model_revision": "fixture-model-commit",
    "tokenizer_revision": "fixture-tokenizer-commit",
}
action = request["action"]
if action == "capabilities":
    response = {"protocol_version": "1.0", "manifest": manifest}
elif action == "generate":
    count = request["max_new_tokens"]
    first = "rawmarkedpayload" if request["watermarked"] else "rawnullpayload"
    text = " ".join([first] + ["unit"] * (count - 1))
    response = {
        "protocol_version": "1.0",
        "text": text,
        "requested_tokens": count,
        "effective_tokens": count,
        "key_slot": request["key_slot"],
        "pair_seed": request["pair_seed"],
        "decoding_config_sha256": request["decoding_config_sha256"],
        "watermarked": request["watermarked"],
        **manifest,
        "telemetry": {**telemetry, "generated_tokens": count},
    }
elif action == "detect":
    words = request["text"].split()
    response = {
        "protocol_version": "1.0",
        "score": 10.0 if words and words[0] == "rawmarkedpayload" else 0.0,
        "effective_tokens": len(words),
        "key_slot": request["key_slot"],
        **manifest,
        "telemetry": telemetry,
    }
elif action == "transform":
    condition = request["condition_id"]
    if condition == "bira":
        response = {
            "protocol_version": "1.0",
            "state": "failed",
            "error_class": request["source_text"].split()[0],
            "telemetry": telemetry,
        }
    elif condition == "sira":
        response = {
            "protocol_version": "1.0",
            "state": "abstained",
            "telemetry": telemetry,
        }
    else:
        response = {
            "protocol_version": "1.0",
            "state": "accepted",
            "candidate_text": request["source_text"].replace(
                "rawmarkedpayload", "cleared", 1
            ),
            "telemetry": telemetry,
        }
else:
    response = {
        "protocol_version": "1.0",
        "state": "completed",
        "passed": True,
        "telemetry": telemetry,
    }
print(json.dumps(response))
""".replace("IDENTIFIER_PLACEHOLDER", repr(identifier)).replace(
                "CONFIGURATION_PLACEHOLDER", repr(configuration_sha256)
            ),
            encoding="utf-8",
        )
        sidecar = tmp_path / f"{identifier}.manifest.json"
        _write(
            sidecar,
            {
                "schema_version": "1.0",
                "id": identifier,
                "family": "fixture",
                "source": "offline-fixture",
                "implementation": "deterministic-plumbing-fixture",
                "implementation_version": "fixture-commit",
                "implementation_sha256": _digest(f"fixture-implementation-{identifier}"),
                "independent": True,
                "vendor_validated": False,
                "score_direction": "higher",
                "minimum_effective_tokens": 1,
                "configuration_sha256": configuration_sha256,
                "model_sha256": _digest(f"fixture-model-{identifier}"),
                "tokenizer_sha256": _digest(f"fixture-tokenizer-{identifier}"),
                "source_sha256": _digest(f"fixture-source-{identifier}"),
                "model_revision": "fixture-model-commit",
                "tokenizer_revision": "fixture-tokenizer-commit",
                "golden_conformance": {
                    "passed": True,
                    "vectors_sha256": _digest("fixture-vectors"),
                    "report_sha256": _digest("fixture-report"),
                },
                "network_required": False,
                "model_download_required": False,
            },
        )
        return {
            "name": identifier,
            "family": "fixture",
            "source": "offline-fixture",
            "sidecar": str(sidecar),
            "argv": [sys.executable, str(script)],
        }

    return entry


def test_holm_adjust_is_monotone_in_rank_and_input_stable():
    assert holm_adjust([0.03, 0.01, 0.2]) == [0.06, 0.03, 0.2]


def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers():
    with pytest.raises(StrictJSONError, match="duplicate"):
        strict_json_loads('{"a":1,"a":2}')
    for value in ('{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'):
        with pytest.raises(StrictJSONError, match="finite"):
            strict_json_loads(value)


def test_hash_chained_checkpoint_repairs_only_a_truncated_final_record(tmp_path):
    path = tmp_path / "progress.jsonl"
    journal = _CheckpointJournal(path)
    journal.append({"event": "first"})
    journal.append({"event": "second"})
    complete = path.read_bytes()
    path.write_bytes(complete + b'{"schema_version":"1.0"')
    recovered = _CheckpointJournal(path)
    assert [item["event"] for item in recovered.records] == ["first", "second"]
    recovered.append({"event": "third"})
    assert path.read_bytes().endswith(b"\n")
    assert [item["event"] for item in _CheckpointJournal(path).records] == [
        "first",
        "second",
        "third",
    ]

    path.write_bytes(path.read_bytes() + b'{"a":1,"a":2}\n')
    with pytest.raises(BenchmarkRunError, match="invalid complete"):
        _CheckpointJournal(path)

    tampered = tmp_path / "tampered.jsonl"
    tampered.write_bytes(complete.replace(b'"first"', b'"wirst"', 1))
    with pytest.raises(BenchmarkRunError, match="hash chain"):
        _CheckpointJournal(tampered)


def test_checkpoint_accepts_complete_final_record_without_newline_but_not_ambiguous_json(
    tmp_path,
):
    path = tmp_path / "progress.jsonl"
    journal = _CheckpointJournal(path)
    journal.append({"event": "first"})
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    recovered = _CheckpointJournal(path)
    assert recovered.records == [{"event": "first"}]
    recovered.append({"event": "second"})
    assert [item["event"] for item in _CheckpointJournal(path).records] == ["first", "second"]

    for invalid in (b'{"a":1,"a":2}', b'{"a":NaN}'):
        broken = tmp_path / f"broken-{len(invalid)}.jsonl"
        broken.write_bytes(path.read_bytes() + invalid)
        with pytest.raises(BenchmarkRunError, match="invalid complete"):
            _CheckpointJournal(broken)


def test_run_wide_budget_usage_persists_and_fails_closed_on_resume(tmp_path):
    limits = {
        "max_records": 2,
        "max_requested_tokens": 5,
        "max_adapter_processes": 1,
        "deadline_seconds": 600,
        "max_cancellation_checks": 1,
    }
    journal = _CheckpointJournal(tmp_path / "budget.jsonl")
    journal.append(
        {
            "event": "run.started",
            "run_id": "a" * 64,
            "execution_budget": limits,
            "records_registered": 2,
            "deadline_at_unix": time.time() + 600,
        }
    )
    budget = _ExecutionBudget.create(
        limits=limits,
        journal=journal,
        records_used=2,
        cancellation_check=None,
        resume=True,
        run_id="a" * 64,
    )
    budget.reserve_tokens(5)
    budget.before_process()

    resumed_journal = _CheckpointJournal(journal.path)
    resumed = _ExecutionBudget.create(
        limits=limits,
        journal=resumed_journal,
        records_used=2,
        cancellation_check=None,
        resume=True,
        run_id="a" * 64,
    )
    assert resumed.requested_tokens_used == 5
    assert resumed.adapter_processes_used == 1
    assert resumed.cancellation_checks_used == 1
    with pytest.raises(BenchmarkRunError, match="requested_tokens budget"):
        resumed.reserve_tokens(1)
    with pytest.raises(BenchmarkRunError, match="cancellation_checks budget"):
        resumed.before_process()


@pytest.mark.parametrize(
    ("bootstrap_replicates", "bootstrap_seed"),
    (
        (True, 0),
        (1, 0),
        (benchmark_run_module.MAX_BOOTSTRAP_REPLICATES + 1, 0),
        (2, True),
        (2, -1),
        (2, benchmark_run_module.MAX_BOOTSTRAP_SEED + 1),
    ),
)
def test_benchmark_rejects_unbounded_or_non_exact_bootstrap_settings_before_io(
    tmp_path,
    bootstrap_replicates,
    bootstrap_seed,
):
    output = tmp_path / "output"
    with pytest.raises(BenchmarkRunError, match="bootstrap settings"):
        run_benchmark(
            protocol_manifest_path=tmp_path / "missing-protocol.json",
            comparator_registry_path=tmp_path / "missing-comparators.json",
            run_config_path=tmp_path / "missing-config.json",
            input_corpus_path=tmp_path / "missing-inputs.json",
            output_directory=output,
            bootstrap_replicates=bootstrap_replicates,
            bootstrap_seed=bootstrap_seed,
        )
    assert not output.exists()


def test_cancellation_is_persisted_before_any_adapter_process_reservation(tmp_path):
    limits = {
        "max_records": 1,
        "max_requested_tokens": 1,
        "max_adapter_processes": 1,
        "deadline_seconds": 600,
        "max_cancellation_checks": 1,
    }
    journal = _CheckpointJournal(tmp_path / "cancel.jsonl")
    journal.append(
        {
            "event": "run.started",
            "run_id": "b" * 64,
            "execution_budget": limits,
            "records_registered": 1,
            "deadline_at_unix": time.time() + 600,
        }
    )
    budget = _ExecutionBudget.create(
        limits=limits,
        journal=journal,
        records_used=1,
        cancellation_check=lambda: True,
        resume=True,
        run_id="b" * 64,
    )
    with pytest.raises(BenchmarkRunError, match="cancelled"):
        budget.before_process()
    assert budget.adapter_processes_used == 0
    assert journal.records[-1] == {
        "event": "run.cancelled",
        "reason_code": "operator_cancelled",
    }


def test_run_deadline_tightens_each_adapter_process_timeout(tmp_path):
    limits = {
        "max_records": 1,
        "max_requested_tokens": 1,
        "max_adapter_processes": 1,
        "deadline_seconds": 60,
        "max_cancellation_checks": 2,
    }
    journal = _CheckpointJournal(tmp_path / "deadline.jsonl")
    journal.append(
        {
            "event": "run.started",
            "run_id": "c" * 64,
            "execution_budget": limits,
            "records_registered": 1,
            "deadline_at_unix": time.time() + 2,
        }
    )
    budget = _ExecutionBudget.create(
        limits=limits,
        journal=journal,
        records_used=1,
        cancellation_check=None,
        resume=True,
        run_id="c" * 64,
    )

    class Adapter:
        name = "deadline-fixture"
        timeout = 600
        _capabilities = {}

        def static_manifest(self):
            return {"network_required": False}

        def _call(self, _payload, *, checkpoint=None):
            assert 0 < self.timeout <= 2
            return {}

    adapter = Adapter()
    _call(adapter, {"action": "detect"}, budget)
    assert adapter.timeout == 600


def test_running_adapter_is_cancelled_through_counted_process_checkpoints(tmp_path):
    limits = {
        "max_records": 1,
        "max_requested_tokens": 1,
        "max_adapter_processes": 1,
        "deadline_seconds": 600,
        "max_cancellation_checks": 10,
    }
    journal = _CheckpointJournal(tmp_path / "process-cancel.jsonl")
    journal.append(
        {
            "event": "run.started",
            "run_id": "d" * 64,
            "execution_budget": limits,
            "records_registered": 1,
            "deadline_at_unix": time.time() + 600,
        }
    )
    started = time.monotonic()
    budget = _ExecutionBudget.create(
        limits=limits,
        journal=journal,
        records_used=1,
        cancellation_check=lambda: time.monotonic() - started > 0.05,
        resume=True,
        run_id="d" * 64,
    )
    script = tmp_path / "sleeping-adapter.py"
    script.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
    adapter = benchmark_run_module.CommandScheme(
        name="sleeping",
        command=(sys.executable, str(script)),
        family="fixture",
        source="fixture",
    )
    adapter._capabilities = {}

    with pytest.raises(_AdapterInvocationFailure):
        _call(adapter, {"action": "detect"}, budget)

    assert time.monotonic() - started < 2
    events = [item["event"] for item in journal.records]
    assert "run.cancelled" in events
    assert "adapter.process.started" in events
    assert "adapter.process.failed" in events
    assert "adapter.process.completed" not in events


def test_public_write_validates_before_touching_a_stale_temporary(tmp_path):
    target = tmp_path / "artifact.json"
    stale = tmp_path / f".{target.name}.tmp-{os.getpid()}"
    stale.write_text("operator-owned", encoding="utf-8")
    with pytest.raises(BenchmarkRunError, match="finite plain JSON"):
        _write_json(target, {"value": float("nan")})
    assert stale.read_text(encoding="utf-8") == "operator-owned"


def test_bounded_json_reader_rejects_duplicate_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(BenchmarkRunError, match="readable bounded JSON"):
        _read_json(path, limit=1024, label="fixture")


def test_cross_detector_alias_is_rejected_before_capability_execution(tmp_path):
    entry = _adapter_fixture(tmp_path)
    primary_spec = entry("fixture-primary")
    alias_spec = dict(primary_spec)
    alias_spec["name"] = "fixture-cross"
    primary = _adapter(primary_spec, allow_network=False, allow_model_download=False)
    alias = _adapter(alias_spec, allow_network=False, allow_model_download=False)
    with pytest.raises(BenchmarkRunError, match="sidecar id"):
        _validate_detector_independence([primary, alias])
    assert primary._capabilities is None
    assert alias._capabilities is None


def test_cluster_paired_analysis_never_treats_rows_as_independent_clusters():
    registry = load_comparator_registry()
    samples = []
    observations = []
    for index in range(101):
        cluster = "large-cluster" if index < 100 else "small-cluster"
        sample_id = f"sample-{index}"
        samples.append(
            {
                "sample_id": sample_id,
                "split": "final_test",
                "cohort": "watermarked_positive",
                "cluster_id": cluster,
            }
        )
        control_success = index == 100
        condition_success = index < 100
        for condition_id, success in (
            ("no_attack", control_success),
            ("reference", condition_success),
        ):
            observations.append(
                {
                    "sample_id": sample_id,
                    "detector_id": "detector",
                    "condition_id": condition_id,
                    "source_score": 10.0,
                    "candidate_score": 0.0 if success else 10.0,
                    "transformation_state": "accepted",
                    "quality_gate_passed": True,
                    "task_check_passed": True,
                }
            )
    threshold = {
        "threshold_operator": ">",
        "paired_outcomes": {"source_threshold": 5.0, "candidate_threshold": 5.0},
    }
    aggregate = {
        "groups": {
            f"detector::{condition}": {"fixed_fpr": {"0.01": threshold}}
            for condition in ("no_attack", "reference")
        }
    }
    result = paired_comparator_analysis(
        {
            "requested_fprs": [0.01],
            "detectors": [{"id": "detector", "manifest": {"score_direction": "higher"}}],
            "observations": observations,
        },
        aggregate,
        {"samples": samples},
        registry,
    )
    reference = next(item for item in result["tests"] if item["condition_id"] == "reference")
    assert reference["paired_clusters"] == 2
    assert reference["condition_cluster_wins"] == 1
    assert reference["control_cluster_wins"] == 1
    assert reference["raw_p_value"] == 1.0
    assert reference["family_hypotheses"] == 4
    assert len(result["tests"]) == 4
    assert result["unavailable_hypotheses"] == 3


def test_exact_sign_test_is_stable_for_large_balanced_and_imbalanced_counts():
    assert comparisons_module._exact_sign_test(2_500, 2_500) == 1.0
    imbalanced = comparisons_module._exact_sign_test(3_000, 2_000)
    assert math.isfinite(imbalanced)
    assert 0.0 < imbalanced < 1e-40
    assert imbalanced == comparisons_module._exact_sign_test(2_000, 3_000)
    assert comparisons_module._exact_sign_test(9, 1) == pytest.approx(0.021484375)


def test_exact_sign_test_rejects_work_above_the_bounded_limit(monkeypatch):
    monkeypatch.setattr(comparisons_module, "MAX_COMPARATOR_WORK_UNITS", 3)

    with pytest.raises(ComparatorValidationError, match="bounded limit"):
        comparisons_module._exact_sign_test(8, 3)

    monkeypatch.setattr(comparisons_module, "MAX_COMPARATOR_WORK_UNITS", 5_000_000)
    monkeypatch.setattr(comparisons_module, "MAX_SIGN_TEST_DISCORDANT_PAIRS", 5_000)
    with pytest.raises(ComparatorValidationError, match="bounded limit"):
        comparisons_module._exact_sign_test(5_001, 0)


def test_execution_registries_validate_against_checked_in_schemas():
    repository = Path(__file__).resolve().parents[1]
    pairs = (
        (
            repository / "schemas" / "benchmark-comparator-registry-v1.json",
            repository / "eval" / "comparator-registry-v1.json",
        ),
        (
            repository / "schemas" / "benchmark-protocol-manifest-v1.json",
            repository / "eval" / "protocols" / "kgw-v1.json",
        ),
        (
            repository / "schemas" / "benchmark-protocol-manifest-v1.json",
            repository / "eval" / "protocols" / "synthid-v1.json",
        ),
    )
    for schema_path, value_path in pairs:
        schema = json.loads(schema_path.read_text())
        value = json.loads(value_path.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)


def test_synthid_protocol_uses_the_same_frozen_execution_contract():
    repository = Path(__file__).resolve().parents[1]
    manifest = benchmark_run_module._load_protocol_manifest(
        repository / "eval" / "protocols" / "synthid-v1.json",
        load_comparator_registry(),
    )

    assert manifest["watermark_family"] == "synthid_text"
    assert manifest["classification"] == "real_protocol_preregistration_no_results"
    assert manifest["execution_requirements"]["cross_detector_required"] is True


@pytest.mark.parametrize("section", ["analysis", "execution_requirements"])
def test_protocol_manifest_rejects_unknown_nested_values_before_identity(tmp_path, section):
    repository = Path(__file__).resolve().parents[1]
    manifest = json.loads((repository / "eval" / "protocols" / "kgw-v1.json").read_text())
    private_value = "sk-live-PRIVATEPROTOCOL123456789"
    manifest[section]["note"] = private_value
    path = tmp_path / "protocol.json"
    _write(path, manifest)

    with pytest.raises(BenchmarkRunError, match="protocol") as error:
        benchmark_run_module._load_protocol_manifest(path, load_comparator_registry())

    assert private_value not in str(error.value)


def test_one_command_runs_adapter_matrix_and_emits_strict_content_free_bundle(
    tmp_path, monkeypatch
):
    adapter = _adapter_fixture(tmp_path)
    registry = load_comparator_registry()
    config = {
        "schema_version": "1.0",
        "classification": "synthetic_harness_fixture_not_performance_evidence",
        "purpose": "harness_conformance",
        "seed": 7,
        "generator_adapter": adapter("fixture-primary"),
        "cross_detector_adapters": [adapter("fixture-cross")],
        "condition_adapters": {
            item["id"]: adapter(f"fixture-{item['id']}")
            for item in registry["conditions"]
            if item["adapter_required"]
        },
        "quality_adapter": adapter("fixture-quality"),
        "task_adapter": adapter("fixture-task"),
        "key_ids": {
            "calibration": "30986bdbabb41298763f59b9df94eb9114464102bc6cebcc606aaaf579add949",
            "development": "fce5583ac3301accd0310c3a946d11e1c6ae3907dc1337861d33ebdf14e104fb",
            "final_test": "66ddb41b5664dd00d655b78102f70b8eb8d49f58971a35387eeb76b4063727d4",
        },
        "key_id_policy": "csprng_256bit_non_secret",
        "key_slots": {
            "calibration": "fixture-private-slot-calibration",
            "development": "fixture-private-slot-development",
            "final_test": "fixture-private-slot-final-test",
        },
        "execution_budget": {
            "max_records": 10,
            "max_requested_tokens": 1000,
            "max_adapter_processes": 1000,
            "deadline_seconds": 600,
            "max_cancellation_checks": 1000,
        },
        "model_size_bytes": 1024,
        "human_review": {
            "state": "not_run",
            "reason": "synthetic_fixture_not_human_evaluation",
        },
    }
    config_path = tmp_path / "run-config.json"
    _write(config_path, config)
    repository = Path(__file__).resolve().parents[1]
    run_config_schema = json.loads(
        (repository / "schemas" / "benchmark-run-config-v1.json").read_text()
    )
    Draft202012Validator(run_config_schema).validate(config)

    unvalidated_profile_link = {**config, "mitigation_profile_core_sha256": "a" * 64}
    unvalidated_profile_link_path = tmp_path / "unvalidated-profile-link-run-config.json"
    _write(unvalidated_profile_link_path, unvalidated_profile_link)
    assert not Draft202012Validator(run_config_schema).is_valid(unvalidated_profile_link)
    with pytest.raises(BenchmarkRunError, match="fields do not match"):
        benchmark_run_module._load_run_config(
            unvalidated_profile_link_path,
            registry,
            allow_network=False,
            allow_model_download=False,
        )
    records = []
    for split in ("calibration", "development", "final_test"):
        human = None
        if split == "final_test":
            human = {
                "text": "human " + "unit " * 31,
                "license_id": "CC0-1.0",
                "source_date": "2026-08-18",
                "domain": "offline-fixture",
                "selection_rule_sha256": _digest("selection"),
                "matching_rule_sha256": _digest("matching"),
                "contamination_risk": "not_assessed_synthetic_fixture",
                "memorization_risk": "not_assessed_synthetic_fixture",
            }
        records.append(
            {
                "record_id": f"{split}-fixture",
                "cluster_id": f"{split}-cluster",
                "split": split,
                "task": "open_ended_prose",
                "language": "en",
                "requested_tokens": 32,
                "prompt": f"private {split} prompt",
                "human_control": human,
            }
        )
    corpus_path = tmp_path / "private-inputs.json"
    corpus = {"schema_version": "1.0", "records": records}
    _write(corpus_path, corpus)
    Draft202012Validator(
        json.loads((repository / "schemas" / "benchmark-input-corpus-v1.json").read_text())
    ).validate(corpus)
    family_mismatch_config = {
        **config,
        "classification": "detector_scoped_real_adapter_benchmark",
        "purpose": "frozen_evaluation",
    }
    family_mismatch_config_path = tmp_path / "family-mismatch-run-config.json"
    _write(family_mismatch_config_path, family_mismatch_config)
    Draft202012Validator(run_config_schema).validate(family_mismatch_config)
    family_mismatch_output = tmp_path / "family-mismatch"
    with pytest.raises(BenchmarkRunError, match="preregistered watermark family"):
        run_benchmark(
            protocol_manifest_path=repository / "eval" / "protocols" / "synthid-v1.json",
            comparator_registry_path=repository / "eval" / "comparator-registry-v1.json",
            run_config_path=family_mismatch_config_path,
            input_corpus_path=corpus_path,
            output_directory=family_mismatch_output,
            bootstrap_replicates=10,
        )
    assert not family_mismatch_output.exists()
    private_value = "sk-live-PRIVATEREVIEW123456789"
    private_config = json.loads(json.dumps(config))
    private_config["human_review"] = {"state": "not_run", "reason": private_value}
    private_config_path = tmp_path / "private-review-config.json"
    _write(private_config_path, private_config)
    private_output = tmp_path / "private-review-output"

    def adapter_must_not_run(*_args, **_kwargs):
        raise AssertionError("invalid public metadata reached an adapter process")

    with monkeypatch.context() as context:
        context.setattr(benchmark_run_module.CommandScheme, "_call", adapter_must_not_run)
        with pytest.raises(BenchmarkRunError, match="human_review") as error:
            run_benchmark(
                protocol_manifest_path=repository / "eval" / "protocols" / "kgw-v1.json",
                comparator_registry_path=repository / "eval" / "comparator-registry-v1.json",
                run_config_path=private_config_path,
                input_corpus_path=corpus_path,
                output_directory=private_output,
                bootstrap_replicates=10,
            )
    assert private_value not in str(error.value)
    assert not private_output.exists()
    private_corpus = json.loads(json.dumps(corpus))
    private_identifier = "sk-live-PRIVATEIDENTIFIER123456789"
    private_corpus["records"][0]["record_id"] = private_identifier
    private_corpus_path = tmp_path / "private-identifier-inputs.json"
    _write(private_corpus_path, private_corpus)
    private_identifier_output = tmp_path / "private-identifier-output"
    with monkeypatch.context() as context:
        context.setattr(benchmark_run_module.CommandScheme, "_call", adapter_must_not_run)
        with pytest.raises(BenchmarkRunError, match="safe public identifier") as error:
            run_benchmark(
                protocol_manifest_path=repository / "eval" / "protocols" / "kgw-v1.json",
                comparator_registry_path=repository / "eval" / "comparator-registry-v1.json",
                run_config_path=config_path,
                input_corpus_path=private_corpus_path,
                output_directory=private_identifier_output,
                bootstrap_replicates=10,
            )
    assert private_identifier not in str(error.value)
    assert not private_identifier_output.exists()
    output = tmp_path / "evidence"
    kwargs = {
        "protocol_manifest_path": repository / "eval" / "protocols" / "kgw-v1.json",
        "comparator_registry_path": repository / "eval" / "comparator-registry-v1.json",
        "run_config_path": config_path,
        "input_corpus_path": corpus_path,
        "output_directory": output,
        "bootstrap_replicates": 10,
    }
    result = run_benchmark(**kwargs)
    assert result["classification"] == "synthetic_harness_fixture_not_performance_evidence"
    assert result["observation_count"] == 40
    assert result["registry_complete"] is False
    bundle = read_bundle(output / "evidence.json")
    Draft202012Validator(
        json.loads((repository / "schemas" / "benchmark-evidence-bundle-v1.json").read_text())
    ).validate(bundle)
    assert bundle["purpose"] == "harness_conformance"
    assert bundle["claim_eligibility"]["comparative_performance_eligible"] is False
    tampered_analysis = json.loads(json.dumps(bundle["results"]["comparative_analysis"]))
    tampered_analysis["tests"][0]["family_hypotheses"] -= 1
    with pytest.raises(EvidenceValidationError, match="Holm family size"):
        _validate_cluster_comparative_analysis(tampered_analysis)
    observations = json.loads((output / "observations.json").read_text())
    sample_registry = json.loads((output / "sample-registry.json").read_text())
    assert observations["run_manifest"]["aggregation_contract_version"] == "1.2"
    assert observations["run_manifest"]["watermark_family"] == "kgw"
    final_pair = {
        item["cohort"]: item
        for item in sample_registry["samples"]
        if item["sample_id"].startswith("final_test-fixture-")
        and item["cohort"] in {"watermarked_positive", "matched_generator_null"}
    }
    assert (
        final_pair["watermarked_positive"]["metadata"]["decoding_config_sha256"]
        == final_pair["matched_generator_null"]["metadata"]["decoding_config_sha256"]
    )
    budget = observations["resource_summary"]["execution_budget"]
    assert budget["usage"]["records"] == 3
    assert budget["usage"]["requested_tokens"] == 192
    assert budget["usage"]["cancellation_checks"] >= (budget["usage"]["adapter_processes"] * 2 + 1)
    assert (
        observations["resource_summary"]["adapter_processes"]["started"]
        == budget["usage"]["adapter_processes"]
    )
    states = {
        item["condition_id"]: item["transformation_state"] for item in observations["observations"]
    }
    assert states["bira"] == "failed"
    assert states["sira"] == "abstained"
    public_bytes = b"".join(
        (output / name).read_bytes()
        for name in ("sample-registry.json", "observations.json", "evidence.json", "progress.jsonl")
    )
    assert b"private final_test prompt" not in public_bytes
    assert b"rawmarkedpayload" not in public_bytes
    assert b"rawnullpayload" not in public_bytes
    assert b"transform_failed" in public_bytes
    assert b"fixture-private-slot" not in public_bytes
    for slot in config["key_slots"].values():
        assert hashlib.sha256(slot.encode()).hexdigest().encode() not in public_bytes
    checkpoint_before_resume = (output / "progress.jsonl").read_bytes()
    resumed = run_benchmark(**kwargs, resume=True)
    assert resumed["bundle_id"] == result["bundle_id"]
    assert (output / "progress.jsonl").read_bytes() == checkpoint_before_resume

    replacement_output = tmp_path / "replacement-evidence"
    replacement = run_benchmark(
        **{**kwargs, "output_directory": replacement_output, "bootstrap_seed": 99}
    )
    assert replacement["run_id"] != result["run_id"]
    assert replacement["bundle_id"] != result["bundle_id"]
    for name in ("sample-registry.json", "observations.json", "evidence.json"):
        (output / name).write_bytes((replacement_output / name).read_bytes())

    with pytest.raises(BenchmarkRunError, match="completed artifacts do not match"):
        run_benchmark(**kwargs, resume=True)

    real_aggregate = benchmark_run_module.aggregate_observation_set
    real_time = benchmark_run_module.time.time
    aggregation_completed = False

    def aggregate_then_expire(*args, **call_kwargs):
        nonlocal aggregation_completed
        aggregate = real_aggregate(*args, **call_kwargs)
        aggregation_completed = True
        return aggregate

    def deadline_clock():
        return real_time() + 601 if aggregation_completed else real_time()

    monkeypatch.setattr(
        benchmark_run_module,
        "aggregate_observation_set",
        aggregate_then_expire,
    )
    monkeypatch.setattr(benchmark_run_module.time, "time", deadline_clock)
    expired_output = tmp_path / "expired-after-aggregate"
    with pytest.raises(BenchmarkRunError, match="run deadline is exhausted"):
        run_benchmark(**{**kwargs, "output_directory": expired_output})
    assert not any(
        (expired_output / name).exists()
        for name in ("sample-registry.json", "observations.json", "evidence.json")
    )
    assert not any(
        item.get("event") == "run.completed"
        for item in _CheckpointJournal(expired_output / "progress.jsonl").records
    )

    monkeypatch.setattr(benchmark_run_module.time, "time", real_time)
    aggregation_completed = False
    cancelled_output = tmp_path / "cancelled-after-aggregate"
    with pytest.raises(BenchmarkRunError, match="cancelled"):
        run_benchmark(
            **{**kwargs, "output_directory": cancelled_output},
            cancellation_check=lambda: aggregation_completed,
        )
    assert not any(
        (cancelled_output / name).exists()
        for name in ("sample-registry.json", "observations.json", "evidence.json")
    )
    assert not any(
        item.get("event") == "run.completed"
        for item in _CheckpointJournal(cancelled_output / "progress.jsonl").records
    )

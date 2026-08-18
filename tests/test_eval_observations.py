import hashlib
import json
from collections.abc import Mapping
from types import SimpleNamespace

import observations as observations_module
import pytest
from evidence import reproduction_descriptor
from jsonschema import Draft202012Validator
from observations import (
    ObservationValidationError,
    aggregate_observation_set,
    finalize_observation_set,
    read_observation_set,
    validate_observation_set,
)
from protocol import length_bin_for, load_protocol_registry, registry_sha256


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _sample(identifier, *, split, cohort, key, paired=None):
    metadata = {}
    if cohort in {"watermarked_positive", "matched_generator_null"}:
        metadata = {
            "generator_id": "fixture-generator@commit",
            "decoding_config_sha256": _digest("decoding"),
        }
        if paired:
            metadata["paired_sample_id"] = paired
    else:
        metadata = {
            "content_sha256": _digest(identifier),
            "license_id": "CC0-1.0",
            "source_date": "2025-01-02",
            "domain": "fixture",
            "selection_rule_sha256": _digest("selection"),
            "matching_rule_sha256": _digest("matching"),
            "contamination_risk": "not_assessed_synthetic_fixture",
            "memorization_risk": "not_assessed_synthetic_fixture",
            "generator_exposed": False,
            "rewriter_exposed": False,
        }
    return {
        "sample_id": identifier,
        "cluster_id": identifier.rsplit("-", 1)[0],
        "split": split,
        "task": "open_ended_prose",
        "language": "en",
        "cohort": cohort,
        "input_sha256": _digest(identifier),
        "effective_detector_tokens": 32,
        "length_bin": length_bin_for(32),
        "key_fingerprint": key,
        "task_checkers": ["semantic", "factual", "protected_span"],
        "metadata": metadata,
    }


def _sample_registry():
    samples = []
    for index in range(100):
        positive_id = f"cal-{index:03d}-positive"
        positive = _sample(
            positive_id,
            split="calibration",
            cohort="watermarked_positive",
            key=_digest("key-cal"),
        )
        null = _sample(
            f"cal-{index:03d}-null",
            split="calibration",
            cohort="matched_generator_null",
            key=_digest("key-cal"),
            paired=positive_id,
        )
        null["cluster_id"] = positive["cluster_id"]
        samples.extend((positive, null))
    development_positive = _sample(
        "dev-000-positive",
        split="development",
        cohort="watermarked_positive",
        key=_digest("key-dev"),
    )
    development_null = _sample(
        "dev-000-null",
        split="development",
        cohort="matched_generator_null",
        key=_digest("key-dev"),
        paired="dev-000-positive",
    )
    development_null["cluster_id"] = development_positive["cluster_id"]
    samples.extend((development_positive, development_null))
    for index in range(100):
        positive_id = f"final-{index:03d}-positive"
        final_positive = _sample(
            positive_id,
            split="final_test",
            cohort="watermarked_positive",
            key=_digest("key-final"),
        )
        final_null = _sample(
            f"final-{index:03d}-null",
            split="final_test",
            cohort="matched_generator_null",
            key=_digest("key-final"),
            paired=positive_id,
        )
        final_null["cluster_id"] = final_positive["cluster_id"]
        final_human = _sample(
            f"final-{index:03d}-human",
            split="final_test",
            cohort="human_control",
            key=None,
        )
        samples.extend((final_positive, final_null, final_human))
    protocol = load_protocol_registry()
    return {
        "schema_version": "1.0",
        "protocol_registry_sha256": registry_sha256(protocol),
        "frozen_before_final_test": True,
        "freeze_record_sha256": _digest("freeze"),
        "key_partitions": [
            {"key_fingerprint": _digest("key-cal"), "split": "calibration"},
            {"key_fingerprint": _digest("key-dev"), "split": "development"},
            {"key_fingerprint": _digest("key-final"), "split": "final_test"},
        ],
        "samples": samples,
    }


def _observation(sample, detector):
    cohort = sample["cohort"]
    split = sample["split"]
    if split == "calibration":
        index = int(sample["sample_id"].split("-")[1])
        source_score = candidate_score = float(index)
    elif cohort == "watermarked_positive":
        source_score, candidate_score = 100.0, 0.0
    elif cohort == "human_control":
        source_score, candidate_score = 0.0, 100.0
    else:
        source_score = candidate_score = 0.0
    return {
        "sample_id": sample["sample_id"],
        "detector_id": detector,
        "condition_id": "sanitize-v1",
        "source_score": source_score,
        "candidate_score": candidate_score,
        "source_effective_tokens": sample["effective_detector_tokens"],
        "candidate_effective_tokens": sample["effective_detector_tokens"],
        "transformation_state": "accepted",
        "quality_gate_passed": True,
        "task_check_passed": True,
        "error_class": None,
        "telemetry": {
            "wall_time_seconds": 0.01,
            "peak_rss_bytes": 1024,
            "remote_queries": 0,
            "generated_tokens": 0,
            "estimated_cost_usd": 0.0,
        },
    }


def _observation_set(sample_registry):
    detectors = []
    for identifier, role in (("primary", "primary"), ("cross", "cross")):
        detectors.append(
            {
                "id": identifier,
                "role": role,
                "manifest": {
                    "independent": True,
                    "implementation_version": "fixture-commit",
                    "configuration_sha256": _digest(identifier),
                    "golden_conformance": {"passed": True},
                },
            }
        )
    measured = [
        sample
        for sample in sample_registry["samples"]
        if sample["split"] == "final_test"
        or (sample["split"] == "calibration" and sample["cohort"] == "matched_generator_null")
    ]
    value = {
        "schema_version": "1.0",
        "sample_registry_sha256": _digest("placeholder"),
        "run_manifest": {
            "source_revision": "a" * 40,
            "environment_sha256": _digest("environment"),
        },
        "detectors": detectors,
        "conditions": [
            {
                "id": "sanitize-v1",
                "transform_manifest_sha256": _digest("transform"),
                "quality_gate_manifest_sha256": _digest("quality"),
            }
        ],
        "requested_fprs": [0.01],
        "observations": [
            _observation(sample, detector)
            for detector in ("primary", "cross")
            for sample in measured
        ],
        "resource_summary": {"model_size_bytes": 2048},
        "human_review": {
            "state": "complete",
            "packet_sha256": _digest("packet"),
            "assignment_sha256": _digest("assignments"),
            "protocol_sha256": _digest("review-protocol"),
            "reviewer_count": 2,
            "blinded": True,
            "pre_registered": True,
            "agreement": {
                "metric": "krippendorff_alpha",
                "value": 0.8,
                "ci95": [0.6, 0.9],
            },
        },
        "reproduction": reproduction_descriptor(
            {
                "schema_version": "1.0",
                "argv": ["python", "run_frozen_eval.py"],
                "working_directory": ".",
                "result_bundle_path": "reproduced-evidence.json",
            },
            timeout_seconds=3600,
            network_required=False,
            model_download_required=False,
        ),
    }
    # Bind after the validator derives the canonical sample digest.
    from protocol import validate_sample_registry

    value["sample_registry_sha256"] = validate_sample_registry(sample_registry)[
        "sample_registry_sha256"
    ]
    return finalize_observation_set(value)


def test_observation_aggregation_is_fixed_fpr_cross_detector_and_denominator_safe():
    registry = _sample_registry()
    observations = _observation_set(registry)
    import dewatermark

    schema = dewatermark.benchmark_observation_set_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(observations)
    validation = validate_observation_set(observations, registry)
    assert validation["missing_required_observations"] == 0
    aggregate = aggregate_observation_set(
        observations, registry, bootstrap_replicates=30, bootstrap_seed=7
    )
    primary = aggregate["groups"]["primary::sanitize-v1"]
    assert primary["fixed_fpr"]["0.01"]["estimable"] is True
    assert primary["attempt_outcomes"]["attempted_denominator"] == 100
    assert primary["attempt_outcomes"]["detector_scoped_gate_success_rate_over_all_attempts"] == 1.0
    assert primary["human_control_outcomes"]["false_inserted"] == 100
    assert aggregate["coverage"]["detector_statistics"]["state"] == "partial"
    assert (
        aggregate["coverage"]["detector_statistics"]["reason"]
        == "fixed_fpr_unstable_independence_or_rows_incomplete"
    )
    assert aggregate["coverage"]["negative_effects"]["state"] == "complete"
    assert aggregate["coverage"]["task_coverage"]["state"] == "partial"
    assert aggregate["cross_detector_confusion"]
    assert aggregate["resource_telemetry"]["remote_queries"]["value"] == 0


def test_observation_identity_and_effective_length_fail_closed():
    registry = _sample_registry()
    observations = _observation_set(registry)
    observations["observations"][0]["source_effective_tokens"] = 999
    observations = finalize_observation_set(observations)
    with pytest.raises(ObservationValidationError, match="effective token"):
        validate_observation_set(observations, registry)

    observations = _observation_set(registry)
    observations["observations"][0]["source_score"] = 999.0
    with pytest.raises(ObservationValidationError, match="digest mismatch"):
        validate_observation_set(observations, registry)


def test_failed_observation_requires_redacted_error_class_and_null_gates():
    registry = _sample_registry()
    observations = _observation_set(registry)
    row = observations["observations"][-1]
    row.update(
        transformation_state="failed",
        quality_gate_passed=None,
        task_check_passed=None,
        error_class="TimeoutError",
    )
    observations = finalize_observation_set(observations)
    validate_observation_set(observations, registry)
    aggregate = aggregate_observation_set(observations, registry, bootstrap_replicates=10)
    assert aggregate["failure_classes"]["TimeoutError"] == 1
    assert json.dumps(aggregate).find("private") == -1


def test_observation_serializer_rejects_hook_bearing_mapping_without_reflecting_it():
    secret = "PRIVATE-OBSERVATION-HOOK"

    class HostileMapping(Mapping):
        def __getitem__(self, _key):
            raise AssertionError(secret)

        def __iter__(self):
            raise AssertionError(secret)

        def __len__(self):
            raise AssertionError(secret)

        def __str__(self):
            raise AssertionError(secret)

        def __repr__(self):
            raise AssertionError(secret)

    with pytest.raises(ObservationValidationError, match="plain JSON") as captured:
        finalize_observation_set(HostileMapping())
    assert secret not in str(captured.value)


def test_observation_read_remains_bounded_if_file_grows_after_metadata_check(tmp_path, monkeypatch):
    path = tmp_path / "observations.json"
    monkeypatch.setattr(observations_module, "MAX_OBSERVATION_BYTES", 64)
    path.write_bytes(b"{" + b"x" * 64)
    real_fstat = observations_module.os.fstat

    def stale_small_size(descriptor):
        info = real_fstat(descriptor)
        return SimpleNamespace(st_mode=info.st_mode, st_size=1)

    monkeypatch.setattr(observations_module.os, "fstat", stale_small_size)
    with pytest.raises(ObservationValidationError, match="size limit"):
        read_observation_set(path)

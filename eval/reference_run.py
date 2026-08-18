"""Deterministic offline protocol conformance run (never efficacy evidence)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

try:
    from .evidence import (
        artifact_descriptor,
        create_bundle,
        reference_replay_recipe,
        reproduction_descriptor,
        write_bundle,
    )
    from .manifest import canonical_json, json_safe
    from .observations import aggregate_observation_set, finalize_observation_set
    from .protocol import (
        length_bin_for,
        load_protocol_registry,
        registry_sha256,
        validate_sample_registry,
    )
except ImportError:  # direct-script compatibility
    from evidence import (  # type: ignore
        artifact_descriptor,
        create_bundle,
        reference_replay_recipe,
        reproduction_descriptor,
        write_bundle,
    )
    from manifest import canonical_json, json_safe  # type: ignore
    from observations import aggregate_observation_set, finalize_observation_set  # type: ignore
    from protocol import (  # type: ignore
        length_bin_for,
        load_protocol_registry,
        registry_sha256,
        validate_sample_registry,
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _task_checkers() -> list[str]:
    protocol = load_protocol_registry()
    task = next(value for value in protocol["tasks"] if value["id"] == "open_ended_prose")
    return list(task["required_checker_kinds"])


def _sample(
    identifier: str,
    *,
    split: str,
    cohort: str,
    key: str | None,
    paired: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any]
    if cohort in {"watermarked_positive", "matched_generator_null"}:
        metadata = {
            "generator_id": "synthetic-protocol-fixture-v1",
            "decoding_config_sha256": _digest("no-generator-synthetic-scores"),
        }
        if paired:
            metadata["paired_sample_id"] = paired
    else:
        metadata = {
            "content_sha256": _digest(
                "This manually authored sentence is used only to test evidence plumbing."
            ),
            "license_id": "MIT",
            "source_date": "2026-08-17",
            "domain": "harness-conformance-fixture",
            "selection_rule_sha256": _digest("single-explicit-manual-fixture"),
            "matching_rule_sha256": _digest("not-a-matched-performance-control"),
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
        "task_checkers": _task_checkers(),
        "metadata": metadata,
    }


def reference_sample_registry() -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for index in range(100):
        positive_id = f"cal-{index:03d}-positive"
        positive = _sample(
            positive_id,
            split="calibration",
            cohort="watermarked_positive",
            key=_digest("fixture-key-cal"),
        )
        null = _sample(
            f"cal-{index:03d}-null",
            split="calibration",
            cohort="matched_generator_null",
            key=_digest("fixture-key-cal"),
            paired=positive_id,
        )
        null["cluster_id"] = positive["cluster_id"]
        samples.extend((positive, null))
    development_positive = _sample(
        "dev-000-positive",
        split="development",
        cohort="watermarked_positive",
        key=_digest("fixture-key-dev"),
    )
    development_null = _sample(
        "dev-000-null",
        split="development",
        cohort="matched_generator_null",
        key=_digest("fixture-key-dev"),
        paired="dev-000-positive",
    )
    development_null["cluster_id"] = development_positive["cluster_id"]
    final_positive = _sample(
        "final-000-positive",
        split="final_test",
        cohort="watermarked_positive",
        key=_digest("fixture-key-final"),
    )
    final_null = _sample(
        "final-000-null",
        split="final_test",
        cohort="matched_generator_null",
        key=_digest("fixture-key-final"),
        paired="final-000-positive",
    )
    final_null["cluster_id"] = final_positive["cluster_id"]
    final_human = _sample(
        "final-000-human",
        split="final_test",
        cohort="human_control",
        key=None,
    )
    samples.extend(
        (development_positive, development_null, final_positive, final_null, final_human)
    )
    protocol = load_protocol_registry()
    return {
        "schema_version": "1.0",
        "registry_classification": "synthetic_harness_fixture_not_performance_evidence",
        "protocol_registry_sha256": registry_sha256(protocol),
        "frozen_before_final_test": True,
        "freeze_record_sha256": _digest("reference-protocol-freeze-v1"),
        "key_partitions": [
            {"key_fingerprint": _digest("fixture-key-cal"), "split": "calibration"},
            {"key_fingerprint": _digest("fixture-key-dev"), "split": "development"},
            {"key_fingerprint": _digest("fixture-key-final"), "split": "final_test"},
        ],
        "samples": samples,
    }


def _observation(sample: dict[str, Any], detector_id: str) -> dict[str, Any]:
    if sample["split"] == "calibration":
        score = float(int(sample["sample_id"].split("-")[1]))
        source_score = candidate_score = score
    elif sample["cohort"] == "watermarked_positive":
        source_score, candidate_score = 100.0, 0.0
    elif sample["cohort"] == "human_control":
        source_score, candidate_score = 0.0, 100.0
    else:
        source_score = candidate_score = 0.0
    return {
        "sample_id": sample["sample_id"],
        "detector_id": detector_id,
        "condition_id": "synthetic-transform-v1",
        "source_score": source_score,
        "candidate_score": candidate_score,
        "source_effective_tokens": sample["effective_detector_tokens"],
        "candidate_effective_tokens": sample["effective_detector_tokens"],
        "transformation_state": "accepted",
        "quality_gate_passed": True,
        "task_check_passed": True,
        "error_class": None,
        "telemetry": {
            "wall_time_seconds": 0.0,
            "peak_rss_bytes": None,
            "remote_queries": 0,
            "generated_tokens": 0,
            "estimated_cost_usd": 0.0,
        },
    }


def reference_observation_set(sample_registry: dict[str, Any]) -> dict[str, Any]:
    sample_report = validate_sample_registry(sample_registry)
    measured = [
        sample
        for sample in sample_registry["samples"]
        if sample["split"] == "final_test"
        or (sample["split"] == "calibration" and sample["cohort"] == "matched_generator_null")
    ]
    detector_manifest = {
        "implementation": "deterministic-synthetic-score-fixture",
        "implementation_version": "1",
        "independent": False,
        "configuration_sha256": _digest("synthetic-score-fixture"),
        "golden_conformance": {"passed": True},
        "limitations": ["not_a_watermark_detector", "not_performance_evidence"],
    }
    return finalize_observation_set(
        {
            "schema_version": "1.0",
            "sample_registry_sha256": sample_report["sample_registry_sha256"],
            "run_manifest": {
                "classification": "synthetic_harness_fixture_not_performance_evidence",
                "fixture_sha256": _digest("reference-protocol-run-v1"),
                "network_allowed": False,
                "model_download_allowed": False,
            },
            "detectors": [
                {"id": "fixture-primary", "role": "primary", "manifest": detector_manifest},
                {"id": "fixture-cross", "role": "cross", "manifest": detector_manifest},
            ],
            "conditions": [
                {
                    "id": "synthetic-transform-v1",
                    "transform_manifest_sha256": _digest("synthetic-transform"),
                    "quality_gate_manifest_sha256": _digest("synthetic-quality-gates"),
                }
            ],
            "requested_fprs": [0.01],
            "observations": [
                _observation(sample, detector_id)
                for detector_id in ("fixture-primary", "fixture-cross")
                for sample in measured
            ],
            "resource_summary": {"model_size_bytes": None},
            "human_review": {
                "state": "not_run",
                "reason": "synthetic_fixture_not_human_evaluation",
            },
            "reproduction": reproduction_descriptor(
                reference_replay_recipe(protocol_run=True),
                timeout_seconds=60,
                network_required=False,
                model_download_required=False,
            ),
        }
    )


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(json_safe(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise ValueError("reference artifact exists; refusing to overwrite") from None
        except OSError:
            raise ValueError("reference artifact could not be written atomically") from None
    except OSError:
        raise ValueError("reference artifact could not be written atomically") from None
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def write_reference_protocol_run(output_directory: Path) -> dict[str, Any]:
    """Write a replayable three-file fixture without network or model access."""
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ValueError("reference output directory could not be created") from None
    sample_path = output_directory / "sample-registry.json"
    observation_path = output_directory / "observations.json"
    bundle_path = output_directory / "evidence.json"
    if any(path.exists() for path in (sample_path, observation_path, bundle_path)):
        raise ValueError("reference protocol output exists; refusing to overwrite")
    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    aggregate = aggregate_observation_set(
        observations, samples, bootstrap_replicates=50, bootstrap_seed=0
    )
    _write_json(sample_path, samples)
    _write_json(observation_path, observations)
    coverage = dict(aggregate["coverage"])
    coverage["artifact_handling"] = {
        "state": "complete",
        "reason": "source_artifacts_bound_by_digest",
    }
    public_results = dict(aggregate)
    public_results["score_tables"] = {
        name: {"sha256": table["sha256"], "records": len(table["records"])}
        for name, table in aggregate["score_tables"].items()
    }
    bundle = create_bundle(
        purpose="harness_conformance",
        manifest=observations["run_manifest"],
        protocol_coverage=coverage,
        results=public_results,
        resource_telemetry=aggregate["resource_telemetry"],
        reproduction=observations["reproduction"],
        artifacts=[
            artifact_descriptor(sample_path, root=output_directory),
            artifact_descriptor(observation_path, root=output_directory),
        ],
        sample_registry_sha256=validate_sample_registry(samples)["sample_registry_sha256"],
        sample_count=len(samples["samples"]),
    )
    write_bundle(bundle_path, bundle)
    return {
        "classification": "synthetic_harness_fixture_not_performance_evidence",
        "bundle_id": bundle["bundle_id"],
        "sample_registry_sha256": validate_sample_registry(samples)["sample_registry_sha256"],
        "observation_set_id": observations["observation_set_id"],
        "aggregate_sha256": aggregate["aggregate_sha256"],
        "files": {
            "sample_registry": sample_path.name,
            "observations": observation_path.name,
            "evidence": bundle_path.name,
        },
        "canonical_summary_sha256": hashlib.sha256(
            canonical_json(
                {
                    "bundle_id": bundle["bundle_id"],
                    "observation_set_id": observations["observation_set_id"],
                    "aggregate_sha256": aggregate["aggregate_sha256"],
                }
            ).encode("utf-8")
        ).hexdigest(),
    }

"""Aggregate pre-registered, content-free benchmark observations."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from . import metrics
    from .evidence import (
        EvidenceValidationError,
        _validate_public_detector_manifest,
        _validate_public_manifest,
        _validate_reproduction,
    )
    from .manifest import canonical_json, content_addressed_score_table, json_safe
    from .protocol import merge_coverage, validate_sample_registry
    from .public_codes import HUMAN_REVIEW_REASON_CODES, is_code_or_commitment
    from .resources import telemetry_value
except ImportError:  # direct-script compatibility
    import metrics  # type: ignore
    from evidence import (  # type: ignore
        EvidenceValidationError,
        _validate_public_detector_manifest,
        _validate_public_manifest,
        _validate_reproduction,
    )
    from manifest import canonical_json, content_addressed_score_table, json_safe  # type: ignore
    from protocol import merge_coverage, validate_sample_registry  # type: ignore
    from public_codes import HUMAN_REVIEW_REASON_CODES, is_code_or_commitment  # type: ignore
    from resources import telemetry_value  # type: ignore

OBSERVATION_SCHEMA_VERSION = "1.0"
MAX_OBSERVATION_BYTES = 512 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_FORBIDDEN_KEYS = {
    "api_key",
    "authorization",
    "body",
    "candidate_text",
    "completion",
    "content",
    "document",
    "input",
    "output",
    "password",
    "private_key",
    "prompt",
    "raw",
    "response",
    "secret",
    "source_text",
    "text",
    "token",
}


class ObservationValidationError(ValueError):
    """An observation set cannot support a reproducible aggregate."""


def _require_plain_tree(value: Any, *, _active: set[int] | None = None, _depth: int = 0) -> None:
    if _depth > 128:
        raise ObservationValidationError("public observation nesting exceeds the limit")
    value_type = type(value)
    if value_type is dict or value_type in (list, tuple):
        active = set() if _active is None else _active
        identity = id(value)
        if identity in active:
            raise ObservationValidationError("public observations cannot contain cycles")
        active.add(identity)
        try:
            if value_type is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise ObservationValidationError(
                            "public observation keys must be plain strings"
                        )
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
            else:
                for item in value:
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
        finally:
            active.remove(identity)
        return
    if value is None or value_type in (str, int, float, bool):
        if value_type is float and not math.isfinite(value):
            raise ObservationValidationError("public observation numbers must be finite")
        return
    raise ObservationValidationError("observations must contain only plain JSON values")


def _contains_private_fields(value: Any) -> bool:
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            normalized = key.lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS or normalized.endswith(
                ("_api_key", "_password", "_private_key", "_secret", "_token")
            ):
                return True
            if _contains_private_fields(item):
                return True
    elif type(value) in (list, tuple):
        return any(_contains_private_fields(item) for item in value)
    return False


def observation_set_identity(value: Mapping[str, Any]) -> str:
    _require_plain_tree(value)
    if type(value) is not dict:
        raise ObservationValidationError("observation set must be a plain object")
    payload = {key: item for key, item in value.items() if key != "observation_set_id"}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def finalize_observation_set(value: Mapping[str, Any]) -> dict[str, Any]:
    """Attach a deterministic identity without executing detectors or plugins."""
    _require_plain_tree(value)
    if type(value) is not dict:
        raise ObservationValidationError("observation set must be a plain object")
    result = json_safe(value)
    result.pop("observation_set_id", None)
    result["observation_set_id"] = observation_set_identity(result)
    return result


def _validate_ids(entries: Any, label: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(entries, list) or not entries:
        raise ObservationValidationError(f"{label} must be a non-empty array")
    result: dict[str, Mapping[str, Any]] = {}
    for item in entries:
        if not isinstance(item, Mapping):
            raise ObservationValidationError(f"{label} entries must be objects")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise ObservationValidationError(f"{label} id is invalid")
        if identifier in result:
            raise ObservationValidationError(f"duplicate {label} id; value was redacted")
        result[identifier] = item
    return result


def _validate_human_review(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ObservationValidationError("human_review must be an object")
    state = value.get("state")
    if state in {"not_run", "not_available"}:
        if set(value) != {"state", "reason"} or not is_code_or_commitment(
            value.get("reason"), HUMAN_REVIEW_REASON_CODES
        ):
            raise ObservationValidationError(
                "missing human review requires a registered reason code or commitment"
            )
        return dict(value)
    required = {
        "state",
        "packet_sha256",
        "assignment_sha256",
        "protocol_sha256",
        "reviewer_count",
        "blinded",
        "pre_registered",
        "agreement",
    }
    if state != "complete" or set(value) != required:
        raise ObservationValidationError("complete human review metadata is incomplete")
    for field in ("packet_sha256", "assignment_sha256", "protocol_sha256"):
        if not isinstance(value.get(field), str) or not _SHA256.fullmatch(value[field]):
            raise ObservationValidationError(f"human review {field} is invalid")
    if (
        not isinstance(value.get("reviewer_count"), int)
        or isinstance(value["reviewer_count"], bool)
        or value["reviewer_count"] < 2
    ):
        raise ObservationValidationError("human review requires at least two reviewers")
    if value.get("blinded") is not True or value.get("pre_registered") is not True:
        raise ObservationValidationError("human review must be blinded and pre-registered")
    agreement = value.get("agreement")
    if not isinstance(agreement, Mapping) or set(agreement) != {"metric", "value", "ci95"}:
        raise ObservationValidationError("human review agreement is incomplete")
    if agreement.get("metric") not in {"krippendorff_alpha", "fleiss_kappa"}:
        raise ObservationValidationError("unsupported human-review agreement metric")
    interval = agreement.get("ci95")
    if (
        not isinstance(agreement.get("value"), (int, float))
        or isinstance(agreement["value"], bool)
        or not -1 <= agreement["value"] <= 1
        or not isinstance(interval, list)
        or len(interval) != 2
        or any(
            not isinstance(item, (int, float)) or isinstance(item, bool) or not -1 <= item <= 1
            for item in interval
        )
        or interval[0] > interval[1]
    ):
        raise ObservationValidationError("human review agreement values are invalid")
    return dict(value)


def _validate_telemetry(value: Any) -> dict[str, Any]:
    required = {
        "wall_time_seconds",
        "peak_rss_bytes",
        "remote_queries",
        "generated_tokens",
        "estimated_cost_usd",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ObservationValidationError("observation telemetry fields are incomplete")
    for field in ("wall_time_seconds", "estimated_cost_usd"):
        number = value.get(field)
        if (
            not isinstance(number, (int, float))
            or isinstance(number, bool)
            or not math.isfinite(number)
            or number < 0
        ):
            raise ObservationValidationError(f"telemetry {field} must be finite and non-negative")
    for field in ("remote_queries", "generated_tokens"):
        number = value.get(field)
        if not isinstance(number, int) or isinstance(number, bool) or number < 0:
            raise ObservationValidationError(f"telemetry {field} must be a non-negative integer")
    peak = value.get("peak_rss_bytes")
    if peak is not None and (not isinstance(peak, int) or isinstance(peak, bool) or peak < 0):
        raise ObservationValidationError("peak_rss_bytes must be null or a non-negative integer")
    return dict(value)


def validate_observation_set(
    value: Mapping[str, Any], sample_registry: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate content identity and bind every observation to a frozen sample."""
    _require_plain_tree(value)
    if type(value) is not dict:
        raise ObservationValidationError("observation set must be a plain object")
    sample_report = validate_sample_registry(sample_registry)
    required = {
        "schema_version",
        "observation_set_id",
        "sample_registry_sha256",
        "run_manifest",
        "detectors",
        "conditions",
        "requested_fprs",
        "observations",
        "resource_summary",
        "human_review",
        "reproduction",
    }
    if set(value) != required or value.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
        raise ObservationValidationError("observation-set fields do not match the v1 contract")
    if _contains_private_fields(value):
        raise ObservationValidationError("observation sets cannot contain text or credentials")
    identity = value.get("observation_set_id")
    if not isinstance(identity, str) or not _SHA256.fullmatch(identity):
        raise ObservationValidationError("observation_set_id is invalid")
    if observation_set_identity(value) != identity:
        raise ObservationValidationError("observation-set content digest mismatch")
    if value.get("sample_registry_sha256") != sample_report["sample_registry_sha256"]:
        raise ObservationValidationError("observations are bound to another sample registry")
    try:
        _validate_public_manifest(value.get("run_manifest"))
    except EvidenceValidationError:
        raise ObservationValidationError("run manifest violates the public contract") from None
    detectors = _validate_ids(value.get("detectors"), "detectors")
    conditions = _validate_ids(value.get("conditions"), "conditions")
    primary = [
        identifier for identifier, item in detectors.items() if item.get("role") == "primary"
    ]
    if len(primary) != 1 or any(
        item.get("role") not in {"primary", "cross"} for item in detectors.values()
    ):
        raise ObservationValidationError("exactly one primary detector is required")
    for item in detectors.values():
        if set(item) != {"id", "role", "manifest"} or not isinstance(item.get("manifest"), Mapping):
            raise ObservationValidationError("detector metadata is incomplete")
        try:
            _validate_public_detector_manifest(item["manifest"])
        except EvidenceValidationError:
            raise ObservationValidationError(
                "detector manifest violates the public contract"
            ) from None
    for item in conditions.values():
        if set(item) != {"id", "transform_manifest_sha256", "quality_gate_manifest_sha256"}:
            raise ObservationValidationError("condition metadata is incomplete")
        for field in ("transform_manifest_sha256", "quality_gate_manifest_sha256"):
            if not isinstance(item.get(field), str) or not _SHA256.fullmatch(item[field]):
                raise ObservationValidationError(f"condition {field} is invalid")
    fprs = value.get("requested_fprs")
    if (
        not isinstance(fprs, list)
        or not fprs
        or len(fprs) != len(set(fprs))
        or any(
            not isinstance(item, (int, float)) or isinstance(item, bool) or not 0 < item < 1
            for item in fprs
        )
    ):
        raise ObservationValidationError("requested_fprs must be unique numbers in (0, 1)")
    samples = {str(item["sample_id"]): item for item in sample_registry["samples"]}
    observations = value.get("observations")
    if not isinstance(observations, list):
        raise ObservationValidationError("observations must be an array")
    seen: set[tuple[str, str, str]] = set()
    observed_samples: set[str] = set()
    for index, item in enumerate(observations):
        if not isinstance(item, Mapping):
            raise ObservationValidationError(f"observation {index} must be an object")
        expected_fields = {
            "sample_id",
            "detector_id",
            "condition_id",
            "source_score",
            "candidate_score",
            "source_effective_tokens",
            "candidate_effective_tokens",
            "transformation_state",
            "quality_gate_passed",
            "task_check_passed",
            "error_class",
            "telemetry",
        }
        if set(item) != expected_fields:
            raise ObservationValidationError(f"observation {index} fields are incomplete")
        sample_id = item.get("sample_id")
        detector_id = item.get("detector_id")
        condition_id = item.get("condition_id")
        if (
            sample_id not in samples
            or detector_id not in detectors
            or condition_id not in conditions
        ):
            raise ObservationValidationError(f"observation {index} references an unknown id")
        key = (str(sample_id), str(detector_id), str(condition_id))
        if key in seen:
            raise ObservationValidationError("duplicate sample/detector/condition observation")
        seen.add(key)
        observed_samples.add(str(sample_id))
        for field in ("source_score", "candidate_score"):
            score = item.get(field)
            if (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(score)
            ):
                raise ObservationValidationError(f"observation {index} {field} must be finite")
        for field in ("source_effective_tokens", "candidate_effective_tokens"):
            count = item.get(field)
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ObservationValidationError(f"observation {index} {field} is invalid")
        if item["source_effective_tokens"] != samples[str(sample_id)]["effective_detector_tokens"]:
            raise ObservationValidationError(
                f"observation {index} effective token count differs from registration"
            )
        state = item.get("transformation_state")
        if state not in {"accepted", "failed", "abstained"}:
            raise ObservationValidationError(f"observation {index} state is invalid")
        quality = item.get("quality_gate_passed")
        task = item.get("task_check_passed")
        if state == "accepted" and (not isinstance(quality, bool) or not isinstance(task, bool)):
            raise ObservationValidationError(
                f"accepted observation {index} requires quality and task-check outcomes"
            )
        if state != "accepted" and (quality is not None or task is not None):
            raise ObservationValidationError(
                f"failed/abstained observation {index} must use null gate outcomes"
            )
        error = item.get("error_class")
        if error is not None and (not isinstance(error, str) or not _ID.fullmatch(error)):
            raise ObservationValidationError(f"observation {index} error_class is invalid")
        if state == "failed" and error is None:
            raise ObservationValidationError(f"failed observation {index} requires error_class")
        _validate_telemetry(item.get("telemetry"))
    resource = value.get("resource_summary")
    if not isinstance(resource, Mapping) or set(resource) != {"model_size_bytes"}:
        raise ObservationValidationError("resource_summary is incomplete")
    model_size = resource.get("model_size_bytes")
    if model_size is not None and (
        not isinstance(model_size, int) or isinstance(model_size, bool) or model_size < 0
    ):
        raise ObservationValidationError("model_size_bytes is invalid")
    _validate_human_review(value.get("human_review"))
    try:
        _validate_reproduction(value.get("reproduction"))
    except EvidenceValidationError:
        raise ObservationValidationError("observation reproduction metadata is invalid") from None
    expected_final = {
        (str(sample["sample_id"]), detector_id, condition_id)
        for sample in sample_registry["samples"]
        if sample["split"] == "final_test"
        or (sample["split"] == "calibration" and sample["cohort"] == "matched_generator_null")
        for detector_id in detectors
        for condition_id in conditions
    }
    missing = expected_final - seen
    return {
        "valid": True,
        "observation_set_id": identity,
        "sample_report": sample_report,
        "detectors": detectors,
        "conditions": conditions,
        "primary_detector": primary[0],
        "missing_required_observations": len(missing),
        "unexpected_development_observations": sum(
            samples[sample_id]["split"] == "development" for sample_id in observed_samples
        ),
    }


def _ordered(
    observations: Mapping[str, Mapping[str, Any]],
    samples: Mapping[str, Mapping[str, Any]],
    *,
    split: str,
    cohort: str,
) -> tuple[list[str], list[Mapping[str, Any]]]:
    identifiers = sorted(
        sample_id
        for sample_id, sample in samples.items()
        if sample["split"] == split and sample["cohort"] == cohort and sample_id in observations
    )
    return identifiers, [observations[identifier] for identifier in identifiers]


def _stratum_rows(
    positive_ids: Sequence[str],
    positive_rows: Sequence[Mapping[str, Any]],
    samples: Mapping[str, Mapping[str, Any]],
    source_threshold: float | None,
    candidate_threshold: float | None,
) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
    for sample_id, row in zip(positive_ids, positive_rows):
        sample = samples[sample_id]
        key = (
            str(sample["task"]),
            str(sample["language"]),
            str(sample["length_bin"]),
            str(sample.get("key_fingerprint") or "none"),
        )
        state = str(row["transformation_state"])
        counts[key]["attempted"] += 1
        counts[key][state] += 1
        if (
            source_threshold is not None
            and candidate_threshold is not None
            and row["source_score"] > source_threshold
            and row["candidate_score"] <= candidate_threshold
            and state == "accepted"
            and row["quality_gate_passed"] is True
            and row["task_check_passed"] is True
        ):
            counts[key]["detector_scoped_gate_success"] += 1
    return [
        {
            "task": key[0],
            "language": key[1],
            "length_bin": key[2],
            "key_fingerprint": key[3],
            **{
                field: count[field]
                for field in (
                    "attempted",
                    "accepted",
                    "failed",
                    "abstained",
                    "detector_scoped_gate_success",
                )
            },
        }
        for key, count in sorted(counts.items())
    ]


def aggregate_observation_set(
    value: Mapping[str, Any],
    sample_registry: Mapping[str, Any],
    *,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
) -> dict[str, Any]:
    """Calculate fixed-FPR aggregates while retaining every attempted row."""
    validation = validate_observation_set(value, sample_registry)
    samples = {str(item["sample_id"]): item for item in sample_registry["samples"]}
    all_rows = value["observations"]
    grouped: dict[tuple[str, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for item in all_rows:
        grouped[(str(item["detector_id"]), str(item["condition_id"]))][str(item["sample_id"])] = (
            item
        )
    group_results: dict[str, Any] = {}
    all_statistics_estimable = True
    all_statistics_stable = True
    all_required_rows_present = validation["missing_required_observations"] == 0
    all_quality_recorded = True
    score_tables: dict[str, Any] = {}
    primary_flags: dict[tuple[str, str], dict[str, tuple[bool | None, bool | None]]] = {}
    for group_index, ((detector_id, condition_id), rows) in enumerate(sorted(grouped.items())):
        calibration_ids, calibration = _ordered(
            rows, samples, split="calibration", cohort="matched_generator_null"
        )
        positive_ids, positives = _ordered(
            rows, samples, split="final_test", cohort="watermarked_positive"
        )
        null_ids, nulls = _ordered(
            rows, samples, split="final_test", cohort="matched_generator_null"
        )
        human_ids, humans = _ordered(rows, samples, split="final_test", cohort="human_control")

        def cluster(identifiers: Sequence[str]) -> list[str]:
            return [str(samples[identifier]["cluster_id"]) for identifier in identifiers]

        fixed_reports: dict[str, Any] = {}
        for fpr_index, fpr in enumerate(value["requested_fprs"]):
            report = metrics.fixed_fpr_paired_report(
                [float(item["source_score"]) for item in positives],
                [float(item["candidate_score"]) for item in positives],
                [float(item["source_score"]) for item in nulls],
                [float(item["candidate_score"]) for item in nulls],
                [float(item["source_score"]) for item in calibration],
                [float(item["candidate_score"]) for item in calibration],
                fpr=float(fpr),
                positive_cluster_ids=cluster(positive_ids),
                null_cluster_ids=cluster(null_ids),
                calibration_cluster_ids=cluster(calibration_ids),
                bootstrap_replicates=bootstrap_replicates,
                bootstrap_seed=bootstrap_seed + group_index * 100 + fpr_index,
            )
            fixed_reports[str(fpr)] = report
            all_statistics_estimable &= bool(report["estimable"])
            all_statistics_stable &= bool(report.get("adequate_for_stable_estimate"))
        primary_fpr = str(value["requested_fprs"][0])
        primary_report = fixed_reports[primary_fpr]
        paired = primary_report.get("paired_outcomes", {})
        source_threshold = paired.get("source_threshold")
        candidate_threshold = paired.get("candidate_threshold")
        success_bools = [
            source_threshold is not None
            and candidate_threshold is not None
            and item["source_score"] > source_threshold
            and item["candidate_score"] <= candidate_threshold
            and item["transformation_state"] == "accepted"
            and item["quality_gate_passed"] is True
            and item["task_check_passed"] is True
            for item in positives
        ]
        attempts = metrics.attempt_outcome_report(
            [str(item["transformation_state"]) for item in positives],
            success_bools,
            cluster_ids=cluster(positive_ids),
            bootstrap_replicates=bootstrap_replicates,
            bootstrap_seed=bootstrap_seed + group_index * 100 + 98,
        )
        human_outcomes = metrics.paired_detection_outcomes(
            [],
            [],
            [float(item["source_score"]) for item in humans],
            [float(item["candidate_score"]) for item in humans],
            source_threshold=float("nan") if source_threshold is None else source_threshold,
            candidate_threshold=float("nan")
            if candidate_threshold is None
            else candidate_threshold,
            null_cluster_ids=cluster(human_ids),
            bootstrap_replicates=bootstrap_replicates,
            bootstrap_seed=bootstrap_seed + group_index * 100 + 99,
        )
        all_quality_recorded &= all(
            item["transformation_state"] != "accepted"
            or (
                isinstance(item["quality_gate_passed"], bool)
                and isinstance(item["task_check_passed"], bool)
            )
            for item in positives
        )
        flags: dict[str, tuple[bool | None, bool | None]] = {}
        for sample_id, item in zip(positive_ids, positives):
            flags[sample_id] = (
                item["source_score"] > source_threshold if source_threshold is not None else None,
                item["candidate_score"] > candidate_threshold
                if candidate_threshold is not None
                else None,
            )
        primary_flags[(detector_id, condition_id)] = flags
        table_rows = []
        for cohort, identifiers, population in (
            ("positive", positive_ids, positives),
            ("matched_generator_null", null_ids, nulls),
            ("human_control", human_ids, humans),
            ("calibration_null", calibration_ids, calibration),
        ):
            for sample_id, item in zip(identifiers, population):
                table_rows.append(
                    {
                        "sample_id": sample_id,
                        "cohort": cohort,
                        "source_score": item["source_score"],
                        "candidate_score": item["candidate_score"],
                        "transformation_state": item["transformation_state"],
                        "quality_gate_passed": item["quality_gate_passed"],
                        "task_check_passed": item["task_check_passed"],
                        "source_effective_tokens": item["source_effective_tokens"],
                        "candidate_effective_tokens": item["candidate_effective_tokens"],
                    }
                )
        group_id = f"{detector_id}::{condition_id}"
        score_tables[group_id] = content_addressed_score_table(table_rows)
        group_results[group_id] = {
            "detector_id": detector_id,
            "condition_id": condition_id,
            "fixed_fpr": fixed_reports,
            "attempt_outcomes": attempts,
            "human_control_outcomes": human_outcomes,
            "strata": _stratum_rows(
                positive_ids, positives, samples, source_threshold, candidate_threshold
            ),
            "score_table_sha256": score_tables[group_id]["sha256"],
            "sample_counts": {
                "calibration_null": len(calibration),
                "final_positive": len(positives),
                "final_matched_null": len(nulls),
                "final_human_control": len(humans),
            },
        }
    cross_confusion: dict[str, Any] = {}
    detector_ids = sorted(validation["detectors"])
    primary_detector = str(validation["primary_detector"])
    for condition_id in sorted(validation["conditions"]):
        primary = primary_flags.get((primary_detector, condition_id), {})
        for detector_id in detector_ids:
            if detector_id == primary_detector:
                continue
            cross = primary_flags.get((detector_id, condition_id), {})
            shared = sorted(set(primary) & set(cross))
            for stage_index, stage in enumerate(("source", "candidate")):
                index = stage_index
                pairs = [
                    (primary[sample_id][index], cross[sample_id][index]) for sample_id in shared
                ]
                eligible = [
                    (left, right) for left, right in pairs if left is not None and right is not None
                ]
                cross_confusion[f"{condition_id}::{detector_id}::{stage}"] = {
                    "samples": len(eligible),
                    "both_flagged": sum(left and right for left, right in eligible),
                    "primary_only": sum(left and not right for left, right in eligible),
                    "cross_only": sum(not left and right for left, right in eligible),
                    "neither_flagged": sum(not left and not right for left, right in eligible),
                }
    independent_detectors = all(
        item["manifest"].get("independent") is True
        and isinstance(item["manifest"].get("golden_conformance"), Mapping)
        and item["manifest"]["golden_conformance"].get("passed") is True
        for item in validation["detectors"].values()
    )
    telemetry_rows = [item["telemetry"] for item in all_rows]
    peaks = [
        item["peak_rss_bytes"] for item in telemetry_rows if item["peak_rss_bytes"] is not None
    ]
    model_size = value["resource_summary"]["model_size_bytes"]
    telemetry = {
        "wall_time": telemetry_value(
            sum(item["wall_time_seconds"] for item in telemetry_rows), "seconds"
        ),
        "process_cpu_time": telemetry_value(None, "seconds", state="not_available"),
        "peak_rss": telemetry_value(max(peaks) if peaks else None, "bytes"),
        "model_size": telemetry_value(model_size, "bytes"),
        "remote_queries": telemetry_value(
            sum(item["remote_queries"] for item in telemetry_rows), "queries"
        ),
        "generated_tokens": telemetry_value(
            sum(item["generated_tokens"] for item in telemetry_rows), "tokens"
        ),
        "estimated_cost": telemetry_value(
            sum(item["estimated_cost_usd"] for item in telemetry_rows), "USD"
        ),
    }
    human_review = _validate_human_review(value["human_review"])
    execution_coverage = {
        "detector_statistics": {
            "state": "complete"
            if all_statistics_estimable
            and all_statistics_stable
            and independent_detectors
            and all_required_rows_present
            else "partial",
            "reason": (
                "fixed_fpr_stable_independent_complete"
                if all_statistics_estimable
                and all_statistics_stable
                and independent_detectors
                and all_required_rows_present
                else "fixed_fpr_unstable_independence_or_rows_incomplete"
            ),
        },
        "negative_effects": {
            "state": "complete"
            if len(detector_ids) >= 2 and all_required_rows_present
            else "partial",
            "reason": (
                "cross_detector_negative_effects_complete"
                if len(detector_ids) >= 2 and all_required_rows_present
                else "cross_detector_negative_effects_incomplete"
            ),
        },
        "quality_preservation": {
            "state": "complete"
            if all_quality_recorded
            and validation["sample_report"]["registry_complete"]
            and all_required_rows_present
            else "partial",
            "reason": (
                "quality_and_task_outcomes_complete"
                if all_quality_recorded and all_required_rows_present
                else "quality_or_task_outcomes_missing"
            ),
        },
        "human_evaluation": {
            "state": "complete" if human_review["state"] == "complete" else human_review["state"],
            "reason": (
                "blinded_review_metadata_complete"
                if human_review["state"] == "complete"
                else "blinded_human_review_not_assessed"
            ),
        },
        "resource_accounting": {
            "state": "complete" if model_size is not None and peaks else "partial",
            "reason": (
                "model_resource_telemetry_complete"
                if model_size is not None and peaks
                else "model_size_or_peak_memory_unavailable"
            ),
        },
        "artifact_handling": {
            "state": "partial",
            "reason": "aggregate_content_addressed_bundle_binding_pending",
        },
        "independent_replication": {
            "state": "not_run",
            "reason": "independent_replication_not_attached",
        },
    }
    coverage = merge_coverage(validation["sample_report"]["coverage"], execution_coverage)
    aggregate = {
        "schema_version": "1.0",
        "classification": "detector_scoped_benchmark_aggregate_not_authorship_evidence",
        "observation_set_id": validation["observation_set_id"],
        "sample_registry_sha256": validation["sample_report"]["sample_registry_sha256"],
        "groups": group_results,
        "cross_detector_confusion": cross_confusion,
        "score_tables": score_tables,
        "failure_classes": dict(
            sorted(
                Counter(
                    str(item["error_class"])
                    for item in all_rows
                    if item["transformation_state"] == "failed"
                ).items()
            )
        ),
        "coverage": coverage,
        "resource_telemetry": telemetry,
    }
    aggregate["aggregate_sha256"] = hashlib.sha256(
        canonical_json(aggregate).encode("utf-8")
    ).hexdigest()
    return json_safe(aggregate)


def read_observation_set(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        if path.is_symlink():
            raise ObservationValidationError("observation set is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OBSERVATION_BYTES:
            raise ObservationValidationError("observation set is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(MAX_OBSERVATION_BYTES + 1)
        if len(data) > MAX_OBSERVATION_BYTES:
            raise ObservationValidationError("observation set exceeds the size limit")
        value = json.loads(data.decode("utf-8"))
    except ObservationValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ObservationValidationError("observation set is not readable bounded JSON") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not isinstance(value, dict):
        raise ObservationValidationError("observation set must contain one object")
    return value

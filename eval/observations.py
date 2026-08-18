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
from typing import Any, Callable, Mapping, Sequence

try:
    from . import metrics
    from .comparisons import paired_comparator_analysis
    from .evidence import (
        EvidenceValidationError,
        _validate_public_detector_manifest,
        _validate_public_manifest,
        _validate_reproduction,
    )
    from .manifest import (
        StrictJSONError,
        canonical_json,
        content_addressed_score_table,
        json_safe,
        strict_json_loads,
    )
    from .protocol import (
        _require_safe_public_values,
        merge_coverage,
        validate_sample_registry,
    )
    from .public_codes import (
        HOST_ERROR_CLASS_CODES,
        HUMAN_REVIEW_REASON_CODES,
        is_code_or_commitment,
    )
    from .resources import telemetry_value
except ImportError:  # direct-script compatibility
    import metrics  # type: ignore
    from comparisons import paired_comparator_analysis  # type: ignore
    from evidence import (  # type: ignore
        EvidenceValidationError,
        _validate_public_detector_manifest,
        _validate_public_manifest,
        _validate_reproduction,
    )
    from manifest import (  # type: ignore
        StrictJSONError,
        canonical_json,
        content_addressed_score_table,
        json_safe,
        strict_json_loads,
    )
    from protocol import (  # type: ignore
        _require_safe_public_values,
        merge_coverage,
        validate_sample_registry,
    )
    from public_codes import (  # type: ignore
        HOST_ERROR_CLASS_CODES,
        HUMAN_REVIEW_REASON_CODES,
        is_code_or_commitment,
    )
    from resources import telemetry_value  # type: ignore

OBSERVATION_SCHEMA_VERSION = "1.0"
MAX_OBSERVATION_BYTES = 512 * 1024 * 1024
MAX_BOOTSTRAP_REPLICATES = 10_000
MAX_BOOTSTRAP_SEED = (1 << 63) - 1
MAX_BOOTSTRAP_WORK_UNITS = 5_000_000
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
    try:
        _require_safe_public_values(value, label="observation set")
    except ValueError:
        raise ObservationValidationError(
            "observation set contains private or credential-like text"
        ) from None
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
    return _validate_attempt_telemetry(value)


def _validate_attempt_telemetry(value: Any) -> dict[str, Any]:
    """Validate possibly incomplete telemetry from an interrupted adapter attempt."""
    required = {
        "wall_time_seconds",
        "peak_rss_bytes",
        "remote_queries",
        "generated_tokens",
        "estimated_cost_usd",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise ObservationValidationError("attempt telemetry fields are incomplete")
    wall = value.get("wall_time_seconds")
    if (
        not isinstance(wall, (int, float))
        or isinstance(wall, bool)
        or not math.isfinite(wall)
        or wall < 0
    ):
        raise ObservationValidationError("attempt wall time must be finite and non-negative")
    peak = value.get("peak_rss_bytes")
    if peak is not None and (type(peak) is not int or peak < 0):
        raise ObservationValidationError("attempt peak RSS is invalid")
    for field in ("remote_queries", "generated_tokens"):
        item = value.get(field)
        if item is not None and (type(item) is not int or item < 0):
            raise ObservationValidationError(f"attempt {field} is invalid")
    cost = value.get("estimated_cost_usd")
    if cost is not None and (
        not isinstance(cost, (int, float))
        or isinstance(cost, bool)
        or not math.isfinite(cost)
        or cost < 0
    ):
        raise ObservationValidationError("attempt estimated cost is invalid")
    return dict(value)


def _attempt_rows(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    history = row.get("attempt_history")
    if isinstance(history, list) and history:
        return history
    return [
        {
            "attempt_index": 1,
            "state": row["transformation_state"],
            "error_class": row["error_class"],
            "telemetry": row["telemetry"],
            "telemetry_complete": True,
        }
    ]


def _detector_independence_bound(detectors: Mapping[str, Mapping[str, Any]]) -> bool:
    """Return whether public metadata supports a distinct-detector claim.

    Sparse legacy v1 manifests remain valid inputs, but a self-declared
    ``independent`` flag is not enough to upgrade aggregate coverage.
    """
    if len(detectors) < 2:
        return False
    required_digests = (
        "sidecar_sha256",
        "command_sha256",
        "implementation_sha256",
        "configuration_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "source_sha256",
    )
    identities: list[dict[str, Any]] = []
    for identifier, entry in detectors.items():
        manifest = entry.get("manifest")
        if type(manifest) is not dict or manifest.get("id") != identifier:
            return False
        if (
            manifest.get("independent_requested") is not True
            or manifest.get("independent") is not True
            or manifest.get("reproducible") is not True
            or manifest.get("reproducibility_blockers") != []
            or manifest.get("command_identity") != "public-shape-v1"
            or type(manifest.get("golden_conformance")) is not dict
            or manifest["golden_conformance"].get("passed") is not True
            or any(
                type(manifest["golden_conformance"].get(field)) is not str
                or not _SHA256.fullmatch(manifest["golden_conformance"][field])
                for field in ("vectors_sha256", "report_sha256")
            )
            or any(
                type(manifest.get(field)) is not str or not _SHA256.fullmatch(manifest[field])
                for field in required_digests
            )
        ):
            return False
        executable = manifest.get("executable_digests")
        if type(executable) is not list or not executable:
            return False
        script_digests = tuple(
            sorted(
                item["sha256"]
                for item in executable
                if type(item) is dict
                and type(item.get("argument_index")) is int
                and item["argument_index"] > 0
                and type(item.get("sha256")) is str
                and _SHA256.fullmatch(item["sha256"])
            )
        )
        if not script_digests:
            script_digests = tuple(
                sorted(
                    item["sha256"]
                    for item in executable
                    if type(item) is dict
                    and type(item.get("sha256")) is str
                    and _SHA256.fullmatch(item["sha256"])
                )
            )
        if not script_digests:
            return False
        identities.append(
            {
                "id": identifier,
                "sidecar": manifest["sidecar_sha256"],
                "command": manifest["command_sha256"],
                "scripts": script_digests,
                "implementation_source": (
                    manifest["implementation_sha256"],
                    manifest["source_sha256"],
                ),
                "full": tuple(manifest[field] for field in required_digests[2:]),
            }
        )
    for field in ("id", "sidecar", "command", "scripts", "implementation_source", "full"):
        values = [identity[field] for identity in identities]
        if len(values) != len(set(values)):
            return False
    return True


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
    run_manifest = value["run_manifest"]
    strict_aggregate = run_manifest.get("aggregation_contract_version") == "1.1"
    if strict_aggregate and any("::" in identifier for identifier in (*detectors, *conditions)):
        raise ObservationValidationError(
            "aggregation contract 1.1 reserves the double-colon identifier delimiter"
        )
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
        if set(item) not in (expected_fields, expected_fields | {"attempt_history"}):
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
        if (
            detector_id == primary[0]
            and item["source_effective_tokens"]
            != samples[str(sample_id)]["effective_detector_tokens"]
        ):
            raise ObservationValidationError(
                f"observation {index} primary-detector effective token count differs from registration"
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
        if strict_aggregate and error is not None and error not in HOST_ERROR_CLASS_CODES:
            raise ObservationValidationError(
                f"observation {index} error_class is not a registered host code"
            )
        if state == "failed" and error is None:
            raise ObservationValidationError(f"failed observation {index} requires error_class")
        _validate_telemetry(item.get("telemetry"))
        history = item.get("attempt_history")
        if history is not None:
            if type(history) is not list or not history:
                raise ObservationValidationError(
                    f"observation {index} attempt_history must be non-empty"
                )
            for attempt_index, attempt in enumerate(history, 1):
                if type(attempt) is not dict or set(attempt) != {
                    "attempt_index",
                    "state",
                    "error_class",
                    "telemetry",
                    "telemetry_complete",
                }:
                    raise ObservationValidationError(
                        f"observation {index} attempt history fields are incomplete"
                    )
                if attempt.get("attempt_index") != attempt_index:
                    raise ObservationValidationError(
                        f"observation {index} attempt indices must be contiguous"
                    )
                attempt_state = attempt.get("state")
                if attempt_state not in {"accepted", "failed", "abstained"}:
                    raise ObservationValidationError(
                        f"observation {index} attempt state is invalid"
                    )
                attempt_error = attempt.get("error_class")
                if attempt_error is not None and (
                    type(attempt_error) is not str or not _ID.fullmatch(attempt_error)
                ):
                    raise ObservationValidationError(
                        f"observation {index} attempt error_class is invalid"
                    )
                if (
                    strict_aggregate
                    and attempt_error is not None
                    and attempt_error not in HOST_ERROR_CLASS_CODES
                ):
                    raise ObservationValidationError(
                        f"observation {index} attempt error_class is not a registered host code"
                    )
                if attempt_state == "failed" and attempt_error is None:
                    raise ObservationValidationError(
                        f"observation {index} failed attempt requires error_class"
                    )
                if type(attempt.get("telemetry_complete")) is not bool:
                    raise ObservationValidationError(
                        f"observation {index} attempt telemetry status is invalid"
                    )
                telemetry = _validate_attempt_telemetry(attempt.get("telemetry"))
                if attempt["telemetry_complete"] is True and any(
                    telemetry[field] is None
                    for field in (
                        "remote_queries",
                        "generated_tokens",
                        "estimated_cost_usd",
                    )
                ):
                    raise ObservationValidationError(
                        f"observation {index} complete attempt telemetry contains nulls"
                    )
            terminal = history[-1]
            if (
                terminal["state"] != state
                or terminal["error_class"] != error
                or terminal["telemetry"] != item["telemetry"]
                or terminal["telemetry_complete"]
                is not all(
                    terminal["telemetry"][field] is not None
                    for field in (
                        "remote_queries",
                        "generated_tokens",
                        "estimated_cost_usd",
                    )
                )
            ):
                raise ObservationValidationError(
                    f"observation {index} terminal attempt must match the observation"
                )
    resource = value.get("resource_summary")
    if not isinstance(resource, Mapping) or set(resource) not in (
        {"model_size_bytes"},
        {
            "model_size_bytes",
            "execution_budget",
            "adapter_processes",
            "adapter_process_resources",
            "run_attempts",
        },
    ):
        raise ObservationValidationError("resource_summary is incomplete")
    model_size = resource.get("model_size_bytes")
    if model_size is not None and (
        not isinstance(model_size, int) or isinstance(model_size, bool) or model_size < 0
    ):
        raise ObservationValidationError("model_size_bytes is invalid")
    if "execution_budget" in resource:
        execution = resource["execution_budget"]
        if type(execution) is not dict or set(execution) != {
            "limits",
            "usage",
            "deadline_at_unix",
        }:
            raise ObservationValidationError("execution budget summary is invalid")
        limits = execution.get("limits")
        usage = execution.get("usage")
        expected_limits = {
            "max_records",
            "max_requested_tokens",
            "max_adapter_processes",
            "deadline_seconds",
            "max_cancellation_checks",
        }
        expected_usage = {
            "records",
            "requested_tokens",
            "adapter_processes",
            "cancellation_checks",
        }
        if (
            type(limits) is not dict
            or set(limits) != expected_limits
            or type(usage) is not dict
            or set(usage) != expected_usage
            or any(type(item) is not int or item < 0 for item in limits.values())
            or any(type(item) is not int or item < 0 for item in usage.values())
            or usage["records"] > limits["max_records"]
            or usage["requested_tokens"] > limits["max_requested_tokens"]
            or usage["adapter_processes"] > limits["max_adapter_processes"]
            or usage["cancellation_checks"] > limits["max_cancellation_checks"]
            or type(execution.get("deadline_at_unix")) not in (int, float)
            or not math.isfinite(float(execution["deadline_at_unix"]))
        ):
            raise ObservationValidationError("execution budget values are invalid")
        for key, fields in (
            (
                "adapter_processes",
                {"started", "completed", "failed", "telemetry_incomplete"},
            ),
            (
                "run_attempts",
                {"sample_failures", "observation_failures", "observation_attempts"},
            ),
        ):
            summary = resource[key]
            if (
                type(summary) is not dict
                or set(summary) != fields
                or any(type(item) is not int or item < 0 for item in summary.values())
            ):
                raise ObservationValidationError(f"{key} summary is invalid")
        process_resources = resource["adapter_process_resources"]
        if type(process_resources) is not dict or set(process_resources) != {
            "telemetry_complete",
            "wall_time_seconds",
            "peak_rss_bytes",
            "remote_queries",
            "generated_tokens",
            "estimated_cost_usd",
        }:
            raise ObservationValidationError("adapter process resource summary is invalid")
        _validate_attempt_telemetry(
            {
                key: process_resources[key]
                for key in (
                    "wall_time_seconds",
                    "peak_rss_bytes",
                    "remote_queries",
                    "generated_tokens",
                    "estimated_cost_usd",
                )
            }
        )
        if type(process_resources["telemetry_complete"]) is not bool or (
            process_resources["telemetry_complete"]
            and any(
                process_resources[field] is None
                for field in ("remote_queries", "generated_tokens", "estimated_cost_usd")
            )
        ):
            raise ObservationValidationError("adapter process resource status is invalid")
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
    *,
    direction_sign: float,
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
        attempts = _attempt_rows(row)
        for attempt in attempts:
            state = str(attempt["state"])
            counts[key]["attempted"] += 1
            counts[key][state] += 1
        if (
            source_threshold is not None
            and candidate_threshold is not None
            and direction_sign * float(row["source_score"]) > source_threshold
            and direction_sign * float(row["candidate_score"]) <= candidate_threshold
            and row["transformation_state"] == "accepted"
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
    comparator_registry: Mapping[str, Any] | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Calculate fixed-FPR aggregates while retaining every attempted row."""
    if (
        type(bootstrap_replicates) is not int
        or not 2 <= bootstrap_replicates <= MAX_BOOTSTRAP_REPLICATES
        or type(bootstrap_seed) is not int
        or not 0 <= bootstrap_seed <= MAX_BOOTSTRAP_SEED
    ):
        raise ObservationValidationError("bootstrap settings are invalid")
    validation = validate_observation_set(value, sample_registry)
    samples = {str(item["sample_id"]): item for item in sample_registry["samples"]}
    all_rows = value["observations"]
    detector_directions = {
        str(item["id"]): str(item["manifest"].get("score_direction", "higher"))
        for item in value["detectors"]
    }
    grouped: dict[tuple[str, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for item in all_rows:
        grouped[(str(item["detector_id"]), str(item["condition_id"]))][str(item["sample_id"])] = (
            item
        )
    total_attempts = sum(len(_attempt_rows(item)) for item in all_rows)
    bootstrap_work = bootstrap_replicates * (
        len(all_rows) * (8 * len(value["requested_fprs"]) + 4) + 2 * total_attempts
    )
    if bootstrap_work > MAX_BOOTSTRAP_WORK_UNITS:
        raise ObservationValidationError("bootstrap workload exceeds the bounded aggregation limit")

    def poll() -> None:
        if checkpoint is not None:
            checkpoint()

    poll()
    group_results: dict[str, Any] = {}
    all_statistics_estimable = True
    all_statistics_stable = True
    all_required_rows_present = validation["missing_required_observations"] == 0
    all_quality_recorded = True
    score_tables: dict[str, Any] = {}
    primary_flags: dict[tuple[str, str], dict[str, tuple[bool | None, bool | None]]] = {}
    for group_index, ((detector_id, condition_id), rows) in enumerate(sorted(grouped.items())):
        poll()
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

        direction_sign = -1.0 if detector_directions[detector_id] == "lower" else 1.0

        def score(item: Mapping[str, Any], field: str, *, sign: float = direction_sign) -> float:
            return sign * float(item[field])

        fixed_reports: dict[str, Any] = {}
        for fpr_index, fpr in enumerate(value["requested_fprs"]):
            poll()
            report = metrics.fixed_fpr_paired_report(
                [score(item, "source_score") for item in positives],
                [score(item, "candidate_score") for item in positives],
                [score(item, "source_score") for item in nulls],
                [score(item, "candidate_score") for item in nulls],
                [score(item, "source_score") for item in calibration],
                [score(item, "candidate_score") for item in calibration],
                fpr=float(fpr),
                positive_cluster_ids=cluster(positive_ids),
                null_cluster_ids=cluster(null_ids),
                calibration_cluster_ids=cluster(calibration_ids),
                bootstrap_replicates=bootstrap_replicates,
                bootstrap_seed=bootstrap_seed + group_index * 100 + fpr_index,
            )
            fixed_reports[str(fpr)] = report
            poll()
            all_statistics_estimable &= bool(report["estimable"])
            all_statistics_stable &= bool(report.get("adequate_for_stable_estimate"))
        primary_fpr = str(value["requested_fprs"][0])
        primary_report = fixed_reports[primary_fpr]
        paired = primary_report.get("paired_outcomes", {})
        source_threshold = paired.get("source_threshold")
        candidate_threshold = paired.get("candidate_threshold")
        terminal_successes = [
            source_threshold is not None
            and candidate_threshold is not None
            and score(item, "source_score") > source_threshold
            and score(item, "candidate_score") <= candidate_threshold
            and item["transformation_state"] == "accepted"
            and item["quality_gate_passed"] is True
            and item["task_check_passed"] is True
            for item in positives
        ]
        expected_positive_ids = sorted(
            sample_id
            for sample_id, sample in samples.items()
            if sample["split"] == "final_test" and sample["cohort"] == "watermarked_positive"
        )
        missing_positive_ids = sorted(set(expected_positive_ids) - set(positive_ids))
        attempt_states: list[str] = []
        observed_successes: list[bool] = []
        attempt_clusters: list[str] = []
        for sample_id, item, terminal_success in zip(positive_ids, positives, terminal_successes):
            item_attempts = _attempt_rows(item)
            attempt_states.extend(str(attempt["state"]) for attempt in item_attempts)
            observed_successes.extend([False] * (len(item_attempts) - 1) + [bool(terminal_success)])
            attempt_clusters.extend([str(samples[sample_id]["cluster_id"])] * len(item_attempts))
        attempt_states.extend(["failed"] * len(missing_positive_ids))
        observed_successes.extend([False] * len(missing_positive_ids))
        attempt_clusters.extend(cluster(missing_positive_ids))
        attempts = metrics.attempt_outcome_report(
            attempt_states,
            observed_successes,
            cluster_ids=attempt_clusters,
            bootstrap_replicates=bootstrap_replicates,
            bootstrap_seed=bootstrap_seed + group_index * 100 + 98,
        )
        poll()
        human_outcomes = metrics.paired_detection_outcomes(
            [],
            [],
            [score(item, "source_score") for item in humans],
            [score(item, "candidate_score") for item in humans],
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
                score(item, "source_score") > source_threshold
                if source_threshold is not None
                else None,
                score(item, "candidate_score") > candidate_threshold
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
                        "attempt_count": len(_attempt_rows(item)),
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
                positive_ids,
                positives,
                samples,
                source_threshold,
                candidate_threshold,
                direction_sign=direction_sign,
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
    independent_detectors = _detector_independence_bound(validation["detectors"])
    attempt_entries = [attempt for item in all_rows for attempt in _attempt_rows(item)]
    telemetry_rows = [item["telemetry"] for item in attempt_entries]
    peaks = [
        item["peak_rss_bytes"] for item in telemetry_rows if item["peak_rss_bytes"] is not None
    ]
    resource_summary = value["resource_summary"]
    model_size = resource_summary["model_size_bytes"]
    process_resources = resource_summary.get("adapter_process_resources")
    complete_process_resources = (
        isinstance(process_resources, Mapping)
        and process_resources.get("telemetry_complete") is True
    )

    def run_resource(field: str, fallback: Any) -> Any:
        if process_resources is None:
            return fallback
        return process_resources[field] if complete_process_resources else None

    telemetry = {
        "wall_time": telemetry_value(
            run_resource(
                "wall_time_seconds",
                sum(item["wall_time_seconds"] for item in telemetry_rows),
            ),
            "seconds",
        ),
        "process_cpu_time": telemetry_value(None, "seconds", state="not_available"),
        "peak_rss": telemetry_value(
            run_resource("peak_rss_bytes", max(peaks) if peaks else None), "bytes"
        ),
        "model_size": telemetry_value(model_size, "bytes"),
        "remote_queries": telemetry_value(
            run_resource(
                "remote_queries",
                sum(item["remote_queries"] for item in telemetry_rows)
                if all(item["remote_queries"] is not None for item in telemetry_rows)
                else None,
            ),
            "queries",
        ),
        "generated_tokens": telemetry_value(
            run_resource(
                "generated_tokens",
                sum(item["generated_tokens"] for item in telemetry_rows)
                if all(item["generated_tokens"] is not None for item in telemetry_rows)
                else None,
            ),
            "tokens",
        ),
        "estimated_cost": telemetry_value(
            run_resource(
                "estimated_cost_usd",
                sum(item["estimated_cost_usd"] for item in telemetry_rows)
                if all(item["estimated_cost_usd"] is not None for item in telemetry_rows)
                else None,
            ),
            "USD",
        ),
    }
    resource_accounting_complete = model_size is not None and (
        (complete_process_resources and process_resources.get("peak_rss_bytes") is not None)
        if process_resources is not None
        else bool(peaks)
    )
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
            if len(detector_ids) >= 2 and independent_detectors and all_required_rows_present
            else "partial",
            "reason": (
                "cross_detector_negative_effects_complete"
                if len(detector_ids) >= 2 and independent_detectors and all_required_rows_present
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
            "state": "complete" if resource_accounting_complete else "partial",
            "reason": (
                "model_resource_telemetry_complete"
                if resource_accounting_complete
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
                (
                    Counter(
                        str(attempt["error_class"])
                        for item in all_rows
                        for attempt in _attempt_rows(item)
                        if attempt["state"] == "failed"
                    )
                    + Counter(
                        {
                            "missing_required_observation": validation[
                                "missing_required_observations"
                            ]
                        }
                    )
                ).items()
            )
        ),
        "coverage": coverage,
        "resource_telemetry": telemetry,
    }
    if comparator_registry is not None:
        poll()
        aggregate["comparative_analysis"] = paired_comparator_analysis(
            value,
            aggregate,
            sample_registry,
            comparator_registry,
        )
    poll()
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
        value = strict_json_loads(data)
    except ObservationValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
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

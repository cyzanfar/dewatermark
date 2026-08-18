"""Frozen comparator registries and multiplicity-aware paired analysis."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from dewatermark.command_safety import validate_public_json

try:
    from .manifest import StrictJSONError, canonical_json, json_safe, strict_json_loads
except ImportError:  # direct-script compatibility
    from manifest import (  # type: ignore
        StrictJSONError,
        canonical_json,
        json_safe,
        strict_json_loads,
    )

COMPARATOR_REGISTRY_PATH = Path(__file__).with_name("comparator-registry-v1.json")
COMPARATOR_REGISTRY_SCHEMA_VERSION = "1.0"
MAX_COMPARATOR_REGISTRY_BYTES = 256 * 1024
MAX_COMPARATOR_WORK_UNITS = 5_000_000
MAX_SIGN_TEST_DISCORDANT_PAIRS = 5_000_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_IMPLEMENTATION_BINDINGS = {
    "intrinsic_identity_transform",
    "runtime_manifest_sha256_required",
}


class ComparatorValidationError(ValueError):
    """A comparator registry or its paired analysis is invalid."""


def _require_plain(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ComparatorValidationError("comparator registry nesting exceeds the limit")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ComparatorValidationError("comparator registry keys must be strings")
            _require_plain(item, depth=depth + 1)
        return
    if type(value) is list:
        for item in value:
            _require_plain(item, depth=depth + 1)
        return
    if value is None or type(value) in (str, int, float, bool):
        if type(value) is float and not math.isfinite(value):
            raise ComparatorValidationError("comparator registry numbers must be finite")
        return
    raise ComparatorValidationError("comparator registry must contain plain JSON values")


def validate_comparator_registry(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed, pre-execution comparator and analysis family."""
    _require_plain(value)
    if type(value) is not dict:
        raise ComparatorValidationError("comparator registry must be an object")
    try:
        validate_public_json(value, source="comparator registry")
    except (TypeError, ValueError):
        raise ComparatorValidationError(
            "comparator registry contains private or credential-like metadata"
        ) from None
    required = {
        "schema_version",
        "registry_id",
        "classification",
        "frozen",
        "control_condition_id",
        "analysis",
        "conditions",
    }
    if set(value) != required or value.get("schema_version") != COMPARATOR_REGISTRY_SCHEMA_VERSION:
        raise ComparatorValidationError("comparator registry fields do not match v1")
    if value.get("classification") != "frozen_comparator_preregistration_no_results":
        raise ComparatorValidationError("comparator registry classification is invalid")
    if value.get("frozen") is not True:
        raise ComparatorValidationError("comparator registry must be frozen")
    if not isinstance(value.get("registry_id"), str) or not _ID.fullmatch(value["registry_id"]):
        raise ComparatorValidationError("comparator registry id is invalid")
    analysis = value.get("analysis")
    if type(analysis) is not dict or set(analysis) != {"method", "family", "alpha"}:
        raise ComparatorValidationError("comparator analysis declaration is incomplete")
    if analysis.get("method") != "holm_bonferroni_cluster_paired_sign_test":
        raise ComparatorValidationError("unsupported comparator correction method")
    if analysis.get("family") != "detector_and_fixed_fpr":
        raise ComparatorValidationError("unsupported comparator hypothesis family")
    alpha = analysis.get("alpha")
    if type(alpha) not in (int, float) or isinstance(alpha, bool) or not 0 < alpha < 1:
        raise ComparatorValidationError("comparator alpha must be in (0, 1)")
    conditions = value.get("conditions")
    if type(conditions) is not list or len(conditions) < 2:
        raise ComparatorValidationError("at least two comparator conditions are required")
    identifiers: set[str] = set()
    roles: list[str] = []
    for condition in conditions:
        if type(condition) is not dict or set(condition) != {
            "id",
            "role",
            "adapter_required",
            "implementation_binding",
        }:
            raise ComparatorValidationError("comparator condition fields are incomplete")
        identifier = condition.get("id")
        if (
            not isinstance(identifier, str)
            or not _ID.fullmatch(identifier)
            or identifier in identifiers
        ):
            raise ComparatorValidationError("comparator condition id is invalid or duplicated")
        identifiers.add(identifier)
        role = condition.get("role")
        if role not in {"negative_control", "system_under_test", "baseline"}:
            raise ComparatorValidationError("comparator condition role is invalid")
        roles.append(str(role))
        if type(condition.get("adapter_required")) is not bool:
            raise ComparatorValidationError("adapter_required must be boolean")
        binding = condition.get("implementation_binding")
        if binding not in _IMPLEMENTATION_BINDINGS:
            raise ComparatorValidationError("implementation binding is invalid")
    control = value.get("control_condition_id")
    if control not in identifiers:
        raise ComparatorValidationError("control condition is not registered")
    control_row = next(item for item in conditions if item["id"] == control)
    if control_row["role"] != "negative_control" or control_row["adapter_required"] is not False:
        raise ComparatorValidationError("control condition must be an intrinsic negative control")
    if control_row["implementation_binding"] != "intrinsic_identity_transform":
        raise ComparatorValidationError("control condition must bind the identity transform")
    if any(
        item["adapter_required"] is True
        and item["implementation_binding"] != "runtime_manifest_sha256_required"
        for item in conditions
    ):
        raise ComparatorValidationError("adapter conditions require runtime manifest binding")
    if roles.count("system_under_test") != 1:
        raise ComparatorValidationError("exactly one system-under-test condition is required")
    return json_safe(value)


def load_comparator_registry(path: Path | None = None) -> dict[str, Any]:
    selected = path or COMPARATOR_REGISTRY_PATH
    try:
        if (
            selected.is_symlink()
            or not selected.is_file()
            or selected.stat().st_size > MAX_COMPARATOR_REGISTRY_BYTES
        ):
            raise ComparatorValidationError("comparator registry is not a bounded regular file")
        raw = selected.read_bytes()
        if len(raw) > MAX_COMPARATOR_REGISTRY_BYTES:
            raise ComparatorValidationError("comparator registry exceeds the size limit")
        value = strict_json_loads(raw)
    except ComparatorValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise ComparatorValidationError(
            "comparator registry is not readable bounded JSON"
        ) from None
    return validate_comparator_registry(value)


def comparator_registry_sha256(value: Mapping[str, Any] | None = None) -> str:
    selected = (
        validate_comparator_registry(value) if value is not None else load_comparator_registry()
    )
    return hashlib.sha256(canonical_json(selected).encode("utf-8")).hexdigest()


def _exact_sign_test_work_units(condition_wins: int, control_wins: int) -> int:
    discordant = condition_wins + control_wins
    if discordant == 0:
        return 1
    smaller_tail = min(condition_wins, control_wins)
    if smaller_tail == discordant // 2:
        return 1
    return smaller_tail + 1


def _exact_sign_test(
    condition_wins: int,
    control_wins: int,
    *,
    _work_limit: int | None = None,
) -> float:
    """Two-sided exact paired sign test over independent cluster summaries.

    The probability is evaluated from the smaller binomial tail with a stable
    log-PMF starting point and a downward recurrence. This retains the exact
    binomial test (rather than using an asymptotic approximation) without
    constructing enormous integers.
    """
    if (
        type(condition_wins) is not int
        or condition_wins < 0
        or type(control_wins) is not int
        or control_wins < 0
    ):
        raise ComparatorValidationError("sign-test counts are invalid")
    work_limit = MAX_COMPARATOR_WORK_UNITS if _work_limit is None else _work_limit
    work_units = _exact_sign_test_work_units(condition_wins, control_wins)
    discordant = condition_wins + control_wins
    if (
        type(work_limit) is not int
        or work_limit < 1
        or work_units > work_limit
        or discordant > MAX_SIGN_TEST_DISCORDANT_PAIRS
    ):
        raise ComparatorValidationError("comparator workload exceeds the bounded limit")
    if discordant == 0:
        return 1.0
    smaller_tail = min(condition_wins, control_wins)
    # For odd n, floor(n / 2) splits the distribution exactly in half. For
    # even n, doubling the lower tail through n / 2 is greater than one.
    if smaller_tail == discordant // 2:
        return 1.0
    log_probability = (
        math.lgamma(discordant + 1)
        - math.lgamma(smaller_tail + 1)
        - math.lgamma(discordant - smaller_tail + 1)
        - discordant * math.log(2.0)
    )
    probability = math.exp(min(0.0, log_probability))
    if probability == 0.0:
        return 0.0

    def lower_tail_probabilities():
        nonlocal probability
        yield probability
        for index in range(smaller_tail, 0, -1):
            probability *= index / (discordant - index + 1)
            yield probability

    tail = math.fsum(lower_tail_probabilities())
    return min(1.0, max(0.0, 2.0 * tail))


def _threshold_flag(score: float, threshold: float, operator: str) -> bool:
    if operator == ">":
        return score > threshold
    if operator == ">=":
        return score >= threshold
    if operator == "<":
        return score < threshold
    if operator == "<=":
        return score <= threshold
    raise ComparatorValidationError("threshold operator is unsupported")


def _attempt_successes(
    row: Mapping[str, Any] | None,
    *,
    source_threshold: float,
    candidate_threshold: float,
    source_operator: str,
    candidate_operator: str,
    direction: str,
) -> list[bool]:
    """Retain every attempt; only the terminal accepted row can be successful."""
    if row is None:
        return [False]
    history = row.get("attempt_history")
    attempt_count = len(history) if isinstance(history, list) and history else 1
    outcomes = [False] * attempt_count
    sign = -1.0 if direction == "lower" else 1.0
    outcomes[-1] = bool(
        _threshold_flag(sign * float(row["source_score"]), source_threshold, source_operator)
        and not _threshold_flag(
            sign * float(row["candidate_score"]),
            candidate_threshold,
            candidate_operator,
        )
        and row["transformation_state"] == "accepted"
        and row["quality_gate_passed"] is True
        and row["task_check_passed"] is True
    )
    return outcomes


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    """Return Holm adjusted p-values in input order."""
    if any(
        type(item) not in (int, float) or not math.isfinite(item) or not 0 <= item <= 1
        for item in p_values
    ):
        raise ValueError("p-values must be finite numbers in [0, 1]")
    ordered = sorted(
        enumerate(float(item) for item in p_values), key=lambda item: (item[1], item[0])
    )
    adjusted = [1.0] * len(ordered)
    running = 0.0
    total = len(ordered)
    for rank, (index, p_value) in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * p_value))
        adjusted[index] = running
    return adjusted


def paired_comparator_analysis(
    observations: Mapping[str, Any],
    aggregate: Mapping[str, Any],
    sample_registry: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare conditions at the independent cluster level with a fixed Holm family."""
    checked = validate_comparator_registry(registry)
    control = str(checked["control_condition_id"])
    condition_ids = [str(item["id"]) for item in checked["conditions"] if item["id"] != control]
    samples = {str(item["sample_id"]): item for item in sample_registry["samples"]}
    positives = sorted(
        sample_id
        for sample_id, sample in samples.items()
        if sample["split"] == "final_test" and sample["cohort"] == "watermarked_positive"
    )
    clusters: dict[str, list[str]] = {}
    for sample_id in positives:
        cluster_id = str(samples[sample_id]["cluster_id"])
        clusters.setdefault(cluster_id, []).append(sample_id)
    rows = {
        (str(item["sample_id"]), str(item["detector_id"]), str(item["condition_id"])): item
        for item in observations["observations"]
    }
    detector_ids = sorted(str(item["id"]) for item in observations["detectors"])
    score_directions = {
        str(item["id"]): str(item["manifest"].get("score_direction", "higher"))
        for item in observations["detectors"]
    }
    tests: list[dict[str, Any]] = []
    unavailable = 0
    work_used = 0

    def consume_work(units: int) -> None:
        nonlocal work_used
        work_used += units
        if work_used > MAX_COMPARATOR_WORK_UNITS:
            raise ComparatorValidationError("comparator workload exceeds the bounded limit")

    alpha = float(checked["analysis"]["alpha"])
    for detector_id in detector_ids:
        for fpr in observations["requested_fprs"]:
            reports: dict[str, Mapping[str, Any]] = {}
            for condition_id in [control, *condition_ids]:
                group = aggregate["groups"].get(f"{detector_id}::{condition_id}", {})
                report = group.get("fixed_fpr", {}).get(str(fpr), {})
                if isinstance(report, Mapping):
                    reports[condition_id] = report
            family: list[dict[str, Any]] = []
            for condition_id in condition_ids:
                control_report = reports.get(control, {})
                condition_report = reports.get(condition_id, {})
                control_paired = control_report.get("paired_outcomes", {})
                condition_paired = condition_report.get("paired_outcomes", {})
                thresholds = (
                    control_paired.get("source_threshold"),
                    control_paired.get("candidate_threshold"),
                    condition_paired.get("source_threshold"),
                    condition_paired.get("candidate_threshold"),
                )
                control_operator = control_report.get("threshold_operator")
                condition_operator = condition_report.get("threshold_operator")
                if (
                    control_operator not in {">", ">=", "<", "<="}
                    or condition_operator not in {">", ">=", "<", "<="}
                    or not all(
                        type(item) in (int, float) and math.isfinite(float(item))
                        for item in thresholds
                    )
                ):
                    unavailable += 1
                    family.append(
                        {
                            "detector_id": detector_id,
                            "requested_fpr": float(fpr),
                            "condition_id": condition_id,
                            "control_condition_id": control,
                            "estimable": False,
                            "reason_code": "fixed_fpr_threshold_not_estimable",
                            "paired_clusters": len(clusters),
                            "paired_samples": len(positives),
                            "condition_attempts": 0,
                            "control_attempts": 0,
                            "condition_cluster_wins": 0,
                            "control_cluster_wins": 0,
                            "cluster_ties": len(clusters),
                            "success_rate_difference": None,
                            "raw_p_value": 1.0,
                        }
                    )
                    continue
                cluster_differences: list[float] = []
                condition_attempts = 0
                control_attempts = 0
                for cluster_ids in clusters.values():
                    control_values: list[bool] = []
                    condition_values: list[bool] = []
                    for sample_id in cluster_ids:
                        control_row = rows.get((sample_id, detector_id, control))
                        condition_row = rows.get((sample_id, detector_id, condition_id))
                        control_history = (
                            control_row.get("attempt_history") if control_row else None
                        )
                        condition_history = (
                            condition_row.get("attempt_history") if condition_row else None
                        )
                        consume_work(
                            (len(control_history) if isinstance(control_history, list) else 1)
                            + (len(condition_history) if isinstance(condition_history, list) else 1)
                        )
                        control_values.extend(
                            _attempt_successes(
                                control_row,
                                source_threshold=float(thresholds[0]),
                                candidate_threshold=float(thresholds[1]),
                                source_operator=str(control_operator),
                                candidate_operator=str(control_operator),
                                direction=score_directions[detector_id],
                            )
                        )
                        condition_values.extend(
                            _attempt_successes(
                                condition_row,
                                source_threshold=float(thresholds[2]),
                                candidate_threshold=float(thresholds[3]),
                                source_operator=str(condition_operator),
                                candidate_operator=str(condition_operator),
                                direction=score_directions[detector_id],
                            )
                        )
                    control_attempts += len(control_values)
                    condition_attempts += len(condition_values)
                    cluster_differences.append(
                        sum(condition_values) / len(condition_values)
                        - sum(control_values) / len(control_values)
                    )
                condition_wins = sum(item > 0 for item in cluster_differences)
                control_wins = sum(item < 0 for item in cluster_differences)
                sign_test_work = _exact_sign_test_work_units(condition_wins, control_wins)
                consume_work(sign_test_work)
                if not cluster_differences:
                    unavailable += 1
                family.append(
                    {
                        "detector_id": detector_id,
                        "requested_fpr": float(fpr),
                        "condition_id": condition_id,
                        "control_condition_id": control,
                        "estimable": bool(cluster_differences),
                        "reason_code": None
                        if cluster_differences
                        else "no_final_test_positive_clusters",
                        "paired_clusters": len(cluster_differences),
                        "paired_samples": len(positives),
                        "condition_attempts": condition_attempts,
                        "control_attempts": control_attempts,
                        "condition_cluster_wins": condition_wins,
                        "control_cluster_wins": control_wins,
                        "cluster_ties": len(cluster_differences) - condition_wins - control_wins,
                        "success_rate_difference": (
                            sum(cluster_differences) / len(cluster_differences)
                            if cluster_differences
                            else None
                        ),
                        "raw_p_value": _exact_sign_test(
                            condition_wins,
                            control_wins,
                            _work_limit=sign_test_work,
                        ),
                    }
                )
            adjusted = holm_adjust([item["raw_p_value"] for item in family])
            for item, adjusted_p in zip(family, adjusted):
                item["adjusted_p_value"] = adjusted_p
                item["reject_null"] = bool(item["estimable"] and adjusted_p <= alpha)
                item["family_hypotheses"] = len(condition_ids)
                tests.append(item)
    return {
        "method": "holm_bonferroni_cluster_paired_sign_test",
        "alpha": alpha,
        "control_condition_id": control,
        "tested_hypotheses": len(tests),
        "estimable_hypotheses": sum(bool(item["estimable"]) for item in tests),
        "unavailable_hypotheses": unavailable,
        "tests": tests,
    }

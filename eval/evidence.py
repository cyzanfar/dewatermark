"""Immutable benchmark bundles, offline replay, and replication attestations."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from dewatermark.bounded_process import BoundedProcessFailure, run_bounded_process
from dewatermark.models import _unsafe_public_text

try:
    from .manifest import StrictJSONError, canonical_json, json_safe, strict_json_loads
    from .protocol import (
        ProtocolValidationError,
        load_protocol_registry,
        registry_sha256,
        validate_coverage_declaration,
    )
    from .public_codes import (
        DETECTOR_LIMITATION_CODES,
        HOST_ERROR_CLASS_CODES,
        HUMAN_REVIEW_REASON_CODES,
        METRIC_NARRATIVE_CODES,
        REPRODUCIBILITY_BLOCKER_CODES,
        RESULT_REASON_CODES,
        is_code_or_commitment,
        is_public_token,
    )
    from .resources import scrubbed_subprocess_environment, zero_network_telemetry
except ImportError:  # direct-script compatibility
    from manifest import (  # type: ignore
        StrictJSONError,
        canonical_json,
        json_safe,
        strict_json_loads,
    )
    from protocol import (  # type: ignore
        ProtocolValidationError,
        load_protocol_registry,
        registry_sha256,
        validate_coverage_declaration,
    )
    from public_codes import (  # type: ignore
        DETECTOR_LIMITATION_CODES,
        HOST_ERROR_CLASS_CODES,
        HUMAN_REVIEW_REASON_CODES,
        METRIC_NARRATIVE_CODES,
        REPRODUCIBILITY_BLOCKER_CODES,
        RESULT_REASON_CODES,
        is_code_or_commitment,
        is_public_token,
    )
    from resources import scrubbed_subprocess_environment, zero_network_telemetry  # type: ignore

BUNDLE_SCHEMA_VERSION = "1.0"
REPLICATION_SCHEMA_VERSION = "1.0"
REPLAY_RECIPE_SCHEMA_VERSION = "1.0"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_REPLAY_RECIPE_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_RFC3339_UTC = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?Z$"
)
_PUBLIC_ARG = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,255}$|^--?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
_PUBLIC_PATH_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$")
_FORBIDDEN_FIELDS = {
    "api_key",
    "authorization",
    "body",
    "candidate_text",
    "completion",
    "content",
    "cookie",
    "credential",
    "document",
    "human_text",
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
_SENSITIVE_ARG_FIELDS = {
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}
_PUBLIC_MANIFEST_FIELDS = {
    "schema_version",
    "classification",
    "fixture",
    "version",
    "network_allowed",
    "model_download_allowed",
}
_PUBLIC_MANIFEST_SUFFIXES = (
    "_sha256",
    "_id",
    "_version",
    "_revision",
    "_allowed",
    "_required",
    "_count",
)
_PUBLIC_RESULT_FIELDS = {
    "schema_version",
    "classification",
    "positive_scores",
    "calibration_null_scores",
    "test_null_scores",
    "failures",
    "abstentions",
    "attempted",
    "aggregate_sha256",
    "observation_set_id",
    "sample_registry_sha256",
    "groups",
    "cross_detector_confusion",
    "comparative_analysis",
    "score_tables",
    "failure_classes",
    "coverage",
    "resource_telemetry",
}
_AGGREGATION_CONTRACT_VERSION = "1.1"
_STRICT_AGGREGATE_RESULT_FIELDS = {
    "schema_version",
    "classification",
    "aggregate_sha256",
    "observation_set_id",
    "sample_registry_sha256",
    "groups",
    "cross_detector_confusion",
    "score_tables",
    "failure_classes",
    "coverage",
    "resource_telemetry",
}
_PUBLIC_RESULT_KEYS = _PUBLIC_RESULT_FIELDS | {
    "abstained",
    "accepted",
    "adequate_for_stable_estimate",
    "artifact_handling",
    "attempt_outcomes",
    "attempted_denominator",
    "adjusted_p_value",
    "alpha",
    "both_flagged",
    "calibration_null",
    "candidate_calibration",
    "candidate_effective_tokens",
    "candidate_score",
    "candidate_threshold",
    "attempt_count",
    "condition_attempts",
    "control_attempts",
    "condition_cluster_wins",
    "control_cluster_wins",
    "cluster_ties",
    "condition_only_successes",
    "clear_rate",
    "clear_rate_ci95_condition",
    "clear_rate_cluster_bootstrap_ci95",
    "clear_rate_conditional_on_source_detection",
    "clear_rate_conditional_row_level_wilson_ci95",
    "clear_rate_row_level_wilson_ci95",
    "cleared",
    "cluster_resampling_unit",
    "code",
    "cohort",
    "condition_id",
    "control_condition_id",
    "control_only_successes",
    "counts_by_stratum",
    "cross_only",
    "denominator_policy",
    "detector_id",
    "detector_scoped_gate_success",
    "detector_scoped_gate_success_rate_over_accepted",
    "detector_scoped_gate_success_rate_over_accepted_cluster_bootstrap_ci95",
    "detector_scoped_gate_success_rate_over_accepted_row_level_wilson_ci95",
    "detector_scoped_gate_success_rate_over_all_attempts",
    "detector_scoped_gate_success_rate_over_all_attempts_cluster_bootstrap_ci95",
    "detector_scoped_gate_success_rate_over_all_attempts_row_level_wilson_ci95",
    "detector_scoped_gate_successes",
    "detector_statistics",
    "empirical_fpr",
    "empirical_fpr_row_level_wilson_ci95",
    "estimable",
    "estimable_hypotheses",
    "estimated_cost",
    "factual_qa",
    "failed",
    "false_inserted",
    "false_insertion_denominator",
    "false_insertion_rate",
    "false_insertion_rate_ci95_condition",
    "false_insertion_rate_cluster_bootstrap_ci95",
    "false_insertion_rate_conditional_on_source_unflagged",
    "false_insertion_rate_conditional_row_level_wilson_ci95",
    "false_insertion_rate_row_level_wilson_ci95",
    "false_positives",
    "family_hypotheses",
    "final_human_control",
    "final_matched_null",
    "final_positive",
    "final_test_key_count",
    "fixed_fpr",
    "generated_tokens",
    "held_out_keys",
    "human_control_count",
    "human_control_outcomes",
    "human_evaluation",
    "independent_replication",
    "independent_splits",
    "initially_detected",
    "interpretation_scope",
    "interval_scope",
    "key_fingerprint",
    "language",
    "language_coverage",
    "length_bin",
    "length_coverage",
    "matched_controls",
    "mathematics",
    "method",
    "minimum_null_clusters",
    "minimum_null_samples",
    "minimum_test_null_clusters",
    "minimum_test_null_samples",
    "missing",
    "missing_checker_kinds",
    "missing_final_test_matrix_cells",
    "missing_groups",
    "model_size",
    "negative_effects",
    "neither_flagged",
    "null_clusters",
    "null_flag_rate_after",
    "null_flag_rate_before",
    "null_flag_rate_delta",
    "null_flag_rate_delta_ci95",
    "null_flag_rate_delta_ci95_method",
    "null_samples",
    "observed",
    "observed_languages",
    "paired_outcomes",
    "paired_samples",
    "paired_clusters",
    "peak_rss",
    "positive_flag_rate_after",
    "positive_flag_rate_before",
    "positive_flag_rate_delta",
    "positive_flag_rate_delta_ci95",
    "positive_flag_rate_delta_ci95_method",
    "positive_samples",
    "primary_only",
    "process_cpu_time",
    "quality_gate_passed",
    "quality_preservation",
    "reason",
    "reason_code",
    "reason_codes",
    "raw_p_value",
    "recommended_null_clusters",
    "recommended_null_samples",
    "recommended_test_null_clusters",
    "recommended_test_null_samples",
    "records",
    "remote_queries",
    "reproducible_identity",
    "requested_fpr",
    "resampling_unit",
    "residual",
    "reject_null",
    "resource_accounting",
    "row_level_interval_scope",
    "sample_count",
    "sample_counts",
    "sample_id",
    "samples",
    "score_population_denominator",
    "score_table_sha256",
    "sha256",
    "source_calibration",
    "source_effective_tokens",
    "source_score",
    "source_threshold",
    "state",
    "strata",
    "structured_data",
    "success_rate_difference",
    "summarization",
    "task",
    "task_check_passed",
    "task_coverage",
    "test_fpr_after",
    "test_fpr_after_cluster_bootstrap_ci95",
    "test_fpr_after_row_level_wilson_ci95",
    "test_fpr_before",
    "test_fpr_before_cluster_bootstrap_ci95",
    "test_fpr_before_row_level_wilson_ci95",
    "test_null_clusters",
    "test_null_samples",
    "tests",
    "threshold",
    "threshold_operator",
    "tpr_after",
    "tpr_after_cluster_bootstrap_ci95",
    "tpr_after_row_level_wilson_ci95",
    "tpr_before",
    "tpr_before_cluster_bootstrap_ci95",
    "tpr_before_row_level_wilson_ci95",
    "transformation_state",
    "translation",
    "tested_hypotheses",
    "tuning_key_count",
    "unit",
    "unavailable_hypotheses",
    "value",
    "wall_time",
}
_DYNAMIC_RESULT_PARENTS = {
    "counts_by_stratum",
    "cross_detector_confusion",
    "failure_classes",
    "fixed_fpr",
    "groups",
    "missing_checker_kinds",
    "score_tables",
}
_PUBLIC_RESULT_IDENTIFIER_FIELDS = {
    "classification",
    "code",
    "cohort",
    "condition_id",
    "control_condition_id",
    "detector_id",
    "language",
    "length_bin",
    "reason_code",
    "sample_id",
    "task",
}
_PUBLIC_RESULT_DIGEST_FIELDS = {
    "aggregate_sha256",
    "observation_set_id",
    "sample_registry_sha256",
    "score_table_sha256",
    "sha256",
}
_PUBLIC_RESULT_OPAQUE_KEY_ID_FIELDS = {"key_fingerprint"}
_PUBLIC_DETECTOR_MANIFEST_FIELDS = {
    "schema_version",
    "id",
    "family",
    "source",
    "implementation",
    "implementation_version",
    "independent_requested",
    "independent",
    "vendor_validated",
    "score_direction",
    "minimum_effective_tokens",
    "minimum_tokens",
    "configuration_sha256",
    "implementation_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "source_sha256",
    "model_revision",
    "tokenizer_revision",
    "golden_conformance",
    "network_required",
    "model_download_required",
    "reproducibility_blockers",
    "sidecar_sha256",
    "command_sha256",
    "command_identity",
    "executable_digests",
    "reproducible",
    "limitations",
}


class EvidenceValidationError(ValueError):
    """A bundle is unsafe, incomplete, or no longer content-addressed."""


def _normal_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _require_plain_tree(value: Any, *, _active: set[int] | None = None, _depth: int = 0) -> None:
    """Reject hook-bearing objects before public traversal or serialization."""
    if _depth > 128:
        raise EvidenceValidationError("public evidence nesting exceeds the limit")
    value_type = type(value)
    if value_type is dict or value_type in (list, tuple):
        active = set() if _active is None else _active
        identity = id(value)
        if identity in active:
            raise EvidenceValidationError("public evidence cannot contain cycles")
        active.add(identity)
        try:
            if value_type is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise EvidenceValidationError("public evidence keys must be plain strings")
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
            else:
                for item in value:
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
        finally:
            active.remove(identity)
        return
    if value is None or value_type in (str, int, float, bool):
        if value_type is float and not math.isfinite(value):
            raise EvidenceValidationError("public evidence numbers must be finite")
        return
    raise EvidenceValidationError("public evidence must contain only plain JSON values")


def _contains_forbidden_fields(value: Any) -> bool:
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            normalized = _normal_key(key)
            if normalized in _FORBIDDEN_FIELDS or normalized.endswith(
                ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
            ):
                return True
            if _contains_forbidden_fields(item):
                return True
    elif type(value) in (list, tuple):
        return any(_contains_forbidden_fields(item) for item in value)
    return False


def _unsafe_public_string(value: str) -> bool:
    """Reject credential material and host-local paths even under benign keys."""
    return _unsafe_public_text(value)


def _require_public_values(value: Any) -> None:
    """Reject private-looking strings in both values and dynamic public keys."""
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            if _unsafe_public_string(key):
                raise EvidenceValidationError("public evidence contains a private-looking value")
            _require_public_values(item)
    elif type(value) in (list, tuple):
        for item in value:
            _require_public_values(item)
    elif type(value) is str and _unsafe_public_string(value):
        raise EvidenceValidationError("public evidence contains a private-looking value")


def _manifest_key_allowed(key: str) -> bool:
    normalized = _normal_key(key)
    return normalized in _PUBLIC_MANIFEST_FIELDS or normalized.endswith(_PUBLIC_MANIFEST_SUFFIXES)


def _validate_public_manifest(value: Any) -> dict[str, Any]:
    """Validate a bundle manifest made only of public scalar commitments."""
    if type(value) is not dict or len(value) > 64:
        raise EvidenceValidationError("evidence manifest violates the public v1 contract")
    _require_plain_tree(value)
    _require_public_values(value)
    for key, item in value.items():
        if not _manifest_key_allowed(key):
            raise EvidenceValidationError("evidence manifest contains an unregistered field")
        normalized = _normal_key(key)
        if normalized.endswith("_sha256"):
            if type(item) is not str or not _SHA256.fullmatch(item):
                raise EvidenceValidationError("evidence manifest digest is invalid")
        elif normalized.endswith(("_allowed", "_required")):
            if type(item) is not bool:
                raise EvidenceValidationError("evidence manifest permission flag is invalid")
        elif normalized.endswith("_count"):
            if type(item) is not int or item < 0:
                raise EvidenceValidationError("evidence manifest count is invalid")
        elif type(item) is not str or not _PUBLIC_ID.fullmatch(item):
            raise EvidenceValidationError("evidence manifest identifier is invalid")
    return dict(value)


def _validate_result_keys(value: Any, *, parent: str | None = None) -> None:
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            if parent in _DYNAMIC_RESULT_PARENTS:
                if not _PUBLIC_ID.fullmatch(key) and not re.fullmatch(r"0(?:\.\d+)?", key):
                    raise EvidenceValidationError("evidence results contain an invalid public key")
            elif key not in _PUBLIC_RESULT_KEYS:
                raise EvidenceValidationError("evidence results contain an unregistered field")
            _validate_result_keys(item, parent=key)
    elif type(value) in (list, tuple):
        for item in value:
            _validate_result_keys(item, parent=parent)


def _validate_result_strings(value: Any, *, parent: str | None = None) -> None:
    """Require every result string to be metadata, a registered code, or a commitment."""
    if type(value) is dict:
        for key, item in value.items():
            if key == "coverage":
                continue
            _validate_result_strings(item, parent=key)
        return
    if type(value) in (list, tuple):
        if parent == "reason_codes" and any(item not in RESULT_REASON_CODES for item in value):
            raise EvidenceValidationError("evidence result reason_codes must be registered codes")
        for item in value:
            _validate_result_strings(item, parent=parent)
        return
    if type(value) is not str:
        return
    if parent in METRIC_NARRATIVE_CODES:
        if value not in METRIC_NARRATIVE_CODES[parent]:
            raise EvidenceValidationError("evidence result narratives must be registered codes")
        return
    if parent == "schema_version":
        if value != "1.0":
            raise EvidenceValidationError("evidence result schema version is unsupported")
        return
    if parent == "reason_codes":
        return
    if parent in _PUBLIC_RESULT_DIGEST_FIELDS:
        if not _SHA256.fullmatch(value):
            raise EvidenceValidationError("evidence result digest is invalid")
        return
    if parent in _PUBLIC_RESULT_OPAQUE_KEY_ID_FIELDS:
        if not _SHA256.fullmatch(value):
            raise EvidenceValidationError("evidence opaque key partition ID is invalid")
        return
    if parent in _PUBLIC_RESULT_IDENTIFIER_FIELDS:
        if not is_public_token(value):
            raise EvidenceValidationError("evidence result identifier is invalid")
        return
    if parent == "threshold_operator":
        if value not in {">", ">=", "<", "<="}:
            raise EvidenceValidationError("evidence threshold operator is unsupported")
        return
    if parent in {"cluster_resampling_unit", "resampling_unit"}:
        if value not in {"prompt_or_document_cluster", "row_no_cluster_ids_supplied"}:
            raise EvidenceValidationError("evidence result resampling unit is invalid")
        return
    if parent == "state":
        if value not in {
            "accepted",
            "abstained",
            "complete",
            "declared",
            "failed",
            "measured",
            "not_applicable",
            "not_available",
            "not_run",
            "partial",
        }:
            raise EvidenceValidationError("evidence result state is invalid")
        return
    if parent == "transformation_state":
        if value not in {"accepted", "failed", "abstained"}:
            raise EvidenceValidationError("evidence transformation state is invalid")
        return
    if parent == "unit":
        if value not in {"USD", "bytes", "calls", "queries", "seconds", "tokens"}:
            raise EvidenceValidationError("evidence result telemetry unit is invalid")
        return
    raise EvidenceValidationError("evidence result field cannot contain a string")


def _numeric_array(value: Any) -> bool:
    return type(value) is list and all(
        type(item) in (int, float) and math.isfinite(float(item)) for item in value
    )


def results_identity(value: Mapping[str, Any]) -> str:
    """Return the canonical identity of a public result without its identity field."""
    payload = {key: item for key, item in value.items() if key != "aggregate_sha256"}
    return _sha256_bytes(canonical_json(payload).encode("utf-8"))


def _validate_cluster_comparative_analysis(value: Any) -> None:
    if type(value) is not dict or set(value) != {
        "method",
        "alpha",
        "control_condition_id",
        "tested_hypotheses",
        "estimable_hypotheses",
        "unavailable_hypotheses",
        "tests",
    }:
        raise EvidenceValidationError("cluster comparative analysis fields are incomplete")
    alpha = value.get("alpha")
    tests = value.get("tests")
    if (
        value.get("method") != "holm_bonferroni_cluster_paired_sign_test"
        or type(alpha) not in (int, float)
        or not math.isfinite(float(alpha))
        or not 0 < alpha < 1
        or not is_public_token(value.get("control_condition_id"))
        or type(tests) is not list
    ):
        raise EvidenceValidationError("cluster comparative analysis is invalid")
    required = {
        "detector_id",
        "requested_fpr",
        "condition_id",
        "control_condition_id",
        "estimable",
        "reason_code",
        "paired_clusters",
        "paired_samples",
        "condition_attempts",
        "control_attempts",
        "condition_cluster_wins",
        "control_cluster_wins",
        "cluster_ties",
        "success_rate_difference",
        "raw_p_value",
        "adjusted_p_value",
        "reject_null",
        "family_hypotheses",
    }
    families: dict[tuple[str, float], list[dict[str, Any]]] = {}
    for test in tests:
        if type(test) is not dict or set(test) != required:
            raise EvidenceValidationError("cluster comparison row fields are incomplete")
        if (
            not is_public_token(test.get("detector_id"))
            or not is_public_token(test.get("condition_id"))
            or test.get("control_condition_id") != value["control_condition_id"]
            or type(test.get("requested_fpr")) not in (int, float)
            or not 0 < test["requested_fpr"] < 1
            or type(test.get("estimable")) is not bool
            or type(test.get("reject_null")) is not bool
        ):
            raise EvidenceValidationError("cluster comparison row identity is invalid")
        for key in (
            "paired_clusters",
            "paired_samples",
            "condition_attempts",
            "control_attempts",
            "condition_cluster_wins",
            "control_cluster_wins",
            "cluster_ties",
            "family_hypotheses",
        ):
            if type(test.get(key)) is not int or test[key] < 0:
                raise EvidenceValidationError("cluster comparison count is invalid")
        for key in ("raw_p_value", "adjusted_p_value"):
            item = test.get(key)
            if (
                type(item) not in (int, float)
                or not math.isfinite(float(item))
                or not 0 <= item <= 1
            ):
                raise EvidenceValidationError("cluster comparison p-value is invalid")
        difference = test.get("success_rate_difference")
        if difference is not None and (
            type(difference) not in (int, float)
            or not math.isfinite(float(difference))
            or not -1 <= difference <= 1
        ):
            raise EvidenceValidationError("cluster comparison effect is invalid")
        if test["estimable"]:
            if test.get("reason_code") is not None or difference is None:
                raise EvidenceValidationError("estimable comparison metadata is inconsistent")
        elif (
            not is_public_token(test.get("reason_code"))
            or difference is not None
            or test["raw_p_value"] != 1.0
            or test["reject_null"] is not False
        ):
            raise EvidenceValidationError("unavailable comparison must be an explicit p=1 row")
        family_key = (str(test["detector_id"]), float(test["requested_fpr"]))
        families.setdefault(family_key, []).append(test)
    if (
        value.get("tested_hypotheses") != len(tests)
        or value.get("estimable_hypotheses") != sum(test["estimable"] for test in tests)
        or value.get("unavailable_hypotheses") != sum(not test["estimable"] for test in tests)
    ):
        raise EvidenceValidationError("comparative hypothesis counts are inconsistent")
    for family in families.values():
        if len({test["condition_id"] for test in family}) != len(family) or any(
            test["family_hypotheses"] != len(family) for test in family
        ):
            raise EvidenceValidationError("Holm family size is not the registered row count")
        raw = [float(test["raw_p_value"]) for test in family]
        order = sorted(range(len(raw)), key=lambda index: (raw[index], index))
        expected = [1.0] * len(raw)
        running = 0.0
        for rank, index in enumerate(order):
            running = max(running, min(1.0, (len(raw) - rank) * raw[index]))
            expected[index] = running
        for test, adjusted in zip(family, expected):
            if not math.isclose(
                float(test["adjusted_p_value"]), adjusted, rel_tol=0.0, abs_tol=1e-15
            ):
                raise EvidenceValidationError("Holm adjusted p-value is inconsistent")
            if test["reject_null"] != bool(test["estimable"] and adjusted <= alpha):
                raise EvidenceValidationError("Holm rejection decision is inconsistent")


def _validate_public_results(value: Any) -> dict[str, Any]:
    """Validate the closed v1 aggregate/result vocabulary."""
    if type(value) is not dict or not set(value) <= _PUBLIC_RESULT_FIELDS:
        raise EvidenceValidationError("evidence results violate the public v1 contract")
    _require_plain_tree(value)
    _require_public_values(value)
    _validate_result_keys(value)
    comparative = value.get("comparative_analysis")
    if comparative is not None:
        _validate_cluster_comparative_analysis(comparative)
    _validate_result_strings(value)
    for key in ("positive_scores", "calibration_null_scores", "test_null_scores"):
        if key in value and not _numeric_array(value[key]):
            raise EvidenceValidationError("evidence score arrays must contain finite numbers")
    for key in ("failures", "abstentions", "attempted"):
        if key in value and (type(value[key]) is not int or value[key] < 0):
            raise EvidenceValidationError("evidence result counts must be non-negative integers")
    for key in ("aggregate_sha256", "observation_set_id", "sample_registry_sha256"):
        if key in value and (type(value[key]) is not str or not _SHA256.fullmatch(value[key])):
            raise EvidenceValidationError("evidence result digest is invalid")
    if "aggregate_sha256" in value and value["aggregate_sha256"] != results_identity(value):
        raise EvidenceValidationError("evidence aggregate content digest mismatch")
    if "schema_version" in value and value["schema_version"] != "1.0":
        raise EvidenceValidationError("evidence result schema version is unsupported")
    if "classification" in value and (
        type(value["classification"]) is not str
        or not _PUBLIC_ID.fullmatch(value["classification"])
    ):
        raise EvidenceValidationError("evidence result classification is invalid")
    score_tables = value.get("score_tables")
    if score_tables is not None:
        if type(score_tables) is not dict:
            raise EvidenceValidationError("evidence score table index must be an object")
        for table in score_tables.values():
            if type(table) is not dict or set(table) != {"sha256", "records"}:
                raise EvidenceValidationError(
                    "evidence score tables must contain only digest and record count"
                )
            if type(table["sha256"]) is not str or not _SHA256.fullmatch(table["sha256"]):
                raise EvidenceValidationError("evidence score table digest is invalid")
            if type(table["records"]) is not int or table["records"] < 0:
                raise EvidenceValidationError("evidence score table record count is invalid")
    if "coverage" in value:
        coverage = value["coverage"]
        if type(coverage) is not dict:
            raise EvidenceValidationError("evidence result coverage must be an object")
        try:
            validate_coverage_declaration(coverage)
        except ProtocolValidationError:
            raise EvidenceValidationError("evidence result coverage is invalid") from None
    telemetry = value.get("resource_telemetry")
    if telemetry is not None:
        _validate_telemetry(telemetry)
    return dict(value)


def _validate_public_detector_manifest(value: Any) -> None:
    if type(value) is not dict or not set(value) <= _PUBLIC_DETECTOR_MANIFEST_FIELDS:
        raise EvidenceValidationError("observation detector manifest violates the public contract")
    for key in (
        "schema_version",
        "id",
        "family",
        "source",
        "implementation",
        "implementation_version",
        "model_revision",
        "tokenizer_revision",
    ):
        item = value.get(key)
        if item is not None and not is_public_token(item):
            raise EvidenceValidationError("observation detector identifier is invalid")
    direction = value.get("score_direction")
    if direction is not None and direction not in {"higher", "lower"}:
        raise EvidenceValidationError("observation detector score direction is invalid")
    for key in ("minimum_effective_tokens", "minimum_tokens"):
        item = value.get(key)
        if item is not None and (type(item) is not int or item < 0):
            raise EvidenceValidationError("observation detector token minimum is invalid")
    for key in ("independent_requested", "independent", "vendor_validated"):
        item = value.get(key)
        if item is not None and type(item) is not bool:
            raise EvidenceValidationError("observation detector classification flag is invalid")
    for key in ("network_required", "model_download_required"):
        item = value.get(key)
        if item is not None and type(item) is not bool:
            raise EvidenceValidationError("observation detector resource flag is invalid")
    for key in (
        "configuration_sha256",
        "sidecar_sha256",
        "command_sha256",
        "implementation_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "source_sha256",
    ):
        item = value.get(key)
        if item is not None and (type(item) is not str or not _SHA256.fullmatch(item)):
            raise EvidenceValidationError("observation detector manifest digest is invalid")
    if value.get("command_identity") is not None and value["command_identity"] != "public-shape-v1":
        raise EvidenceValidationError("observation detector command identity is invalid")
    if value.get("reproducible") is not None and type(value["reproducible"]) is not bool:
        raise EvidenceValidationError("observation detector reproducibility flag is invalid")
    executable = value.get("executable_digests")
    if executable is not None:
        if type(executable) is not list:
            raise EvidenceValidationError("observation detector executable digests are invalid")
        for item in executable:
            if (
                type(item) is not dict
                or set(item) != {"argument_index", "basename", "sha256"}
                or type(item.get("argument_index")) is not int
                or item["argument_index"] < 0
                or not is_public_token(item.get("basename"))
                or type(item.get("sha256")) is not str
                or not _SHA256.fullmatch(item["sha256"])
            ):
                raise EvidenceValidationError(
                    "observation detector executable digest entry is invalid"
                )
    golden = value.get("golden_conformance")
    if golden is not None:
        allowed = {"passed", "vectors_sha256", "report_sha256"}
        if type(golden) is not dict or not set(golden) <= allowed:
            raise EvidenceValidationError("observation detector conformance is not content-free")
        if type(golden.get("passed")) is not bool:
            raise EvidenceValidationError("observation detector conformance status is invalid")
        for key in ("vectors_sha256", "report_sha256"):
            item = golden.get(key)
            if item is not None and (type(item) is not str or not _SHA256.fullmatch(item)):
                raise EvidenceValidationError("observation detector conformance digest is invalid")
    for key, allowed in (
        ("limitations", DETECTOR_LIMITATION_CODES),
        ("reproducibility_blockers", REPRODUCIBILITY_BLOCKER_CODES),
    ):
        items = value.get(key)
        if items is not None and (
            type(items) is not list
            or any(not is_code_or_commitment(item, allowed) for item in items)
            or len(items) != len(set(items))
        ):
            raise EvidenceValidationError(
                "observation detector narratives must be registered codes or commitments"
            )


def _validate_public_human_review(value: Any) -> None:
    if type(value) is not dict:
        raise EvidenceValidationError("observation human_review must be an object")
    state = value.get("state")
    if state in {"not_run", "not_available"}:
        if set(value) != {"state", "reason"} or not is_code_or_commitment(
            value.get("reason"), HUMAN_REVIEW_REASON_CODES
        ):
            raise EvidenceValidationError(
                "observation human-review reason must be a registered code or commitment"
            )
        return
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
        raise EvidenceValidationError("observation human-review metadata is incomplete")
    for key in ("packet_sha256", "assignment_sha256", "protocol_sha256"):
        item = value.get(key)
        if type(item) is not str or not _SHA256.fullmatch(item):
            raise EvidenceValidationError("observation human-review digest is invalid")
    if type(value.get("reviewer_count")) is not int or value["reviewer_count"] < 2:
        raise EvidenceValidationError("observation human-review count is invalid")
    if value.get("blinded") is not True or value.get("pre_registered") is not True:
        raise EvidenceValidationError("observation human review is not blinded and registered")
    agreement = value.get("agreement")
    if type(agreement) is not dict or set(agreement) != {"metric", "value", "ci95"}:
        raise EvidenceValidationError("observation human-review agreement is invalid")
    if agreement.get("metric") not in {"krippendorff_alpha", "fleiss_kappa"}:
        raise EvidenceValidationError("observation human-review metric is invalid")
    score = agreement.get("value")
    interval = agreement.get("ci95")
    if (
        type(score) not in (int, float)
        or not math.isfinite(float(score))
        or not -1 <= score <= 1
        or type(interval) is not list
        or len(interval) != 2
        or any(
            type(item) not in (int, float) or not math.isfinite(float(item)) or not -1 <= item <= 1
            for item in interval
        )
    ):
        raise EvidenceValidationError("observation human-review agreement is invalid")


def _validate_public_observation_artifact(value: dict[str, Any]) -> None:
    """Validate the content-free shape without requiring the bound sample file."""
    identity = value.get("observation_set_id")
    sample_digest = value.get("sample_registry_sha256")
    if type(identity) is not str or not _SHA256.fullmatch(identity):
        raise EvidenceValidationError("observation_set_id is invalid")
    if type(sample_digest) is not str or not _SHA256.fullmatch(sample_digest):
        raise EvidenceValidationError("observation sample registry digest is invalid")
    payload = {key: item for key, item in value.items() if key != "observation_set_id"}
    if _sha256_bytes(canonical_json(payload).encode("utf-8")) != identity:
        raise EvidenceValidationError("observation-set content digest mismatch")
    run_manifest = value.get("run_manifest")
    _validate_public_manifest(run_manifest)
    strict_aggregate = (
        type(run_manifest) is dict and run_manifest.get("aggregation_contract_version") == "1.1"
    )
    detectors = value.get("detectors")
    if type(detectors) is not list or not detectors:
        raise EvidenceValidationError("observation detector index must be a non-empty array")
    detector_ids: set[str] = set()
    primary = 0
    for detector in detectors:
        if type(detector) is not dict or set(detector) != {"id", "role", "manifest"}:
            raise EvidenceValidationError("observation detector metadata is incomplete")
        identifier = detector.get("id")
        if not is_public_token(identifier) or identifier in detector_ids:
            raise EvidenceValidationError("observation detector id is invalid")
        detector_ids.add(identifier)
        role = detector.get("role")
        if role not in {"primary", "cross"}:
            raise EvidenceValidationError("observation detector role is invalid")
        primary += role == "primary"
        _validate_public_detector_manifest(detector.get("manifest"))
    if primary != 1:
        raise EvidenceValidationError("observation set requires exactly one primary detector")
    conditions = value.get("conditions")
    if type(conditions) is not list or not conditions:
        raise EvidenceValidationError("observation conditions must be a non-empty array")
    condition_ids: set[str] = set()
    for condition in conditions:
        if type(condition) is not dict or set(condition) != {
            "id",
            "transform_manifest_sha256",
            "quality_gate_manifest_sha256",
        }:
            raise EvidenceValidationError("observation condition metadata is incomplete")
        identifier = condition.get("id")
        if not is_public_token(identifier) or identifier in condition_ids:
            raise EvidenceValidationError("observation condition id is invalid")
        condition_ids.add(identifier)
        for key in ("transform_manifest_sha256", "quality_gate_manifest_sha256"):
            item = condition.get(key)
            if type(item) is not str or not _SHA256.fullmatch(item):
                raise EvidenceValidationError("observation condition digest is invalid")
    requested_fprs = value.get("requested_fprs")
    if (
        type(requested_fprs) is not list
        or not requested_fprs
        or any(
            type(item) not in (int, float) or not math.isfinite(float(item)) or not 0 < item < 1
            for item in requested_fprs
        )
        or len(requested_fprs) != len(set(requested_fprs))
    ):
        raise EvidenceValidationError("observation requested_fprs are invalid")
    observations = value.get("observations")
    if type(observations) is not list:
        raise EvidenceValidationError("observations must be an array")
    row_fields = {
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
    telemetry_fields = {
        "wall_time_seconds",
        "peak_rss_bytes",
        "remote_queries",
        "generated_tokens",
        "estimated_cost_usd",
    }

    def validate_attempt_telemetry(telemetry: Any) -> None:
        if type(telemetry) is not dict or set(telemetry) != telemetry_fields:
            raise EvidenceValidationError("observation row telemetry is invalid")
        wall = telemetry.get("wall_time_seconds")
        if type(wall) not in (int, float) or not math.isfinite(float(wall)) or wall < 0:
            raise EvidenceValidationError("observation row telemetry is invalid")
        peak = telemetry.get("peak_rss_bytes")
        if peak is not None and (type(peak) is not int or peak < 0):
            raise EvidenceValidationError("observation row telemetry is invalid")
        for key in ("remote_queries", "generated_tokens"):
            item = telemetry.get(key)
            if item is not None and (type(item) is not int or item < 0):
                raise EvidenceValidationError("observation row telemetry is invalid")
        cost = telemetry.get("estimated_cost_usd")
        if cost is not None and (
            type(cost) not in (int, float) or not math.isfinite(float(cost)) or cost < 0
        ):
            raise EvidenceValidationError("observation row telemetry is invalid")

    for row in observations:
        if type(row) is not dict or set(row) not in (
            row_fields,
            row_fields | {"attempt_history"},
        ):
            raise EvidenceValidationError("observation row fields are incomplete")
        if not is_public_token(row.get("sample_id")):
            raise EvidenceValidationError("observation sample id is invalid")
        if (
            row.get("detector_id") not in detector_ids
            or row.get("condition_id") not in condition_ids
        ):
            raise EvidenceValidationError("observation row references an unknown id")
        for key in ("source_score", "candidate_score"):
            item = row.get(key)
            if type(item) not in (int, float) or not math.isfinite(float(item)):
                raise EvidenceValidationError("observation score is invalid")
        for key in ("source_effective_tokens", "candidate_effective_tokens"):
            item = row.get(key)
            if type(item) is not int or item < 0:
                raise EvidenceValidationError("observation token count is invalid")
        state = row.get("transformation_state")
        if state not in {"accepted", "failed", "abstained"}:
            raise EvidenceValidationError("observation transformation state is invalid")
        for key in ("quality_gate_passed", "task_check_passed"):
            if row.get(key) is not None and type(row[key]) is not bool:
                raise EvidenceValidationError("observation gate result is invalid")
        error = row.get("error_class")
        if error is not None and not is_public_token(error):
            raise EvidenceValidationError("observation error class is invalid")
        if strict_aggregate and error is not None and error not in HOST_ERROR_CLASS_CODES:
            raise EvidenceValidationError("observation error class is not a registered host code")
        telemetry = row.get("telemetry")
        validate_attempt_telemetry(telemetry)
        history = row.get("attempt_history")
        if history is not None:
            if type(history) is not list or not history:
                raise EvidenceValidationError("observation attempt history is invalid")
            for index, attempt in enumerate(history, 1):
                if type(attempt) is not dict or set(attempt) != {
                    "attempt_index",
                    "state",
                    "error_class",
                    "telemetry",
                    "telemetry_complete",
                }:
                    raise EvidenceValidationError("observation attempt history is invalid")
                if attempt.get("attempt_index") != index or attempt.get("state") not in {
                    "accepted",
                    "failed",
                    "abstained",
                }:
                    raise EvidenceValidationError("observation attempt history is invalid")
                if attempt.get("error_class") is not None and not is_public_token(
                    attempt["error_class"]
                ):
                    raise EvidenceValidationError("observation attempt history is invalid")
                if (
                    strict_aggregate
                    and attempt.get("error_class") is not None
                    and attempt["error_class"] not in HOST_ERROR_CLASS_CODES
                ):
                    raise EvidenceValidationError(
                        "observation attempt error class is not a registered host code"
                    )
                if type(attempt.get("telemetry_complete")) is not bool:
                    raise EvidenceValidationError("observation attempt history is invalid")
                validate_attempt_telemetry(attempt.get("telemetry"))
    resource = value.get("resource_summary")
    if type(resource) is not dict or set(resource) not in (
        {"model_size_bytes"},
        {
            "model_size_bytes",
            "execution_budget",
            "adapter_processes",
            "adapter_process_resources",
            "run_attempts",
        },
    ):
        raise EvidenceValidationError("observation resource summary is invalid")
    model_size = resource.get("model_size_bytes")
    if model_size is not None and (type(model_size) is not int or model_size < 0):
        raise EvidenceValidationError("observation model size is invalid")
    if "execution_budget" in resource:
        execution = resource["execution_budget"]
        if type(execution) is not dict or set(execution) != {
            "limits",
            "usage",
            "deadline_at_unix",
        }:
            raise EvidenceValidationError("observation execution budget is invalid")
        for section in ("limits", "usage"):
            if type(execution.get(section)) is not dict or any(
                type(item) is not int or item < 0 for item in execution[section].values()
            ):
                raise EvidenceValidationError("observation execution budget is invalid")
        deadline = execution.get("deadline_at_unix")
        if type(deadline) not in (int, float) or not math.isfinite(float(deadline)):
            raise EvidenceValidationError("observation execution budget is invalid")
        for section in ("adapter_processes", "run_attempts"):
            if type(resource.get(section)) is not dict or any(
                type(item) is not int or item < 0 for item in resource[section].values()
            ):
                raise EvidenceValidationError("observation resource summary is invalid")
        process_resources = resource.get("adapter_process_resources")
        if type(process_resources) is not dict or set(process_resources) != {
            "telemetry_complete",
            "wall_time_seconds",
            "peak_rss_bytes",
            "remote_queries",
            "generated_tokens",
            "estimated_cost_usd",
        }:
            raise EvidenceValidationError("observation process resources are invalid")
        if type(process_resources.get("telemetry_complete")) is not bool:
            raise EvidenceValidationError("observation process resources are invalid")
        validate_attempt_telemetry({key: process_resources[key] for key in telemetry_fields})
    _validate_public_human_review(value.get("human_review"))
    _validate_reproduction(value.get("reproduction"))


def _validate_public_json_artifact(value: Any) -> None:
    """Accept only registered content-free JSON artifact contracts."""
    if type(value) is not dict:
        raise EvidenceValidationError("JSON evidence artifact has no registered public contract")
    _require_plain_tree(value)
    _require_public_values(value)
    keys = set(value)
    if keys == {"aggregate"} and type(value.get("aggregate")) is bool:
        return
    comparator_fields = {
        "schema_version",
        "registry_id",
        "classification",
        "frozen",
        "control_condition_id",
        "analysis",
        "conditions",
    }
    if keys == comparator_fields:
        try:
            from .comparisons import ComparatorValidationError, validate_comparator_registry
        except ImportError:
            from comparisons import (  # type: ignore
                ComparatorValidationError,
                validate_comparator_registry,
            )

        try:
            validate_comparator_registry(value)
        except ComparatorValidationError:
            raise EvidenceValidationError(
                "JSON evidence artifact violates the comparator-registry contract"
            ) from None
        return
    if "samples" in keys:
        try:
            from .protocol import validate_sample_registry
        except ImportError:
            from protocol import validate_sample_registry  # type: ignore

        try:
            validate_sample_registry(value)
        except (ProtocolValidationError, ValueError):
            raise EvidenceValidationError(
                "JSON evidence artifact violates the sample-registry contract"
            ) from None
        return
    observation_fields = {
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
    if "observations" in keys:
        if keys != observation_fields:
            raise EvidenceValidationError(
                "JSON evidence artifact violates the observation-set contract"
            )
        _validate_public_observation_artifact(value)
        return
    if keys <= _PUBLIC_RESULT_FIELDS:
        _validate_public_results(value)
        return
    raise EvidenceValidationError("JSON evidence artifact has no registered public contract")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded_file(path: Path, limit: int, error: str) -> bytes:
    """Read one regular-file snapshot without a stat/read allocation race."""
    descriptor = -1
    try:
        if path.is_symlink():
            raise EvidenceValidationError(error)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise EvidenceValidationError(error)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(limit + 1)
    except EvidenceValidationError:
        raise
    except OSError:
        raise EvidenceValidationError(error) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(data) > limit:
        raise EvidenceValidationError(error)
    return data


def _without_identity(value: Mapping[str, Any], identity_field: str) -> dict[str, Any]:
    _require_plain_tree(value)
    assert type(value) is dict
    return {key: item for key, item in value.items() if key != identity_field}


def bundle_identity(bundle: Mapping[str, Any]) -> str:
    return _sha256_bytes(canonical_json(_without_identity(bundle, "bundle_id")).encode("utf-8"))


def replication_identity(record: Mapping[str, Any]) -> str:
    return _sha256_bytes(canonical_json(_without_identity(record, "record_id")).encode("utf-8"))


def _relative_path(value: Any, label: str, *, allow_root: bool = False) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise EvidenceValidationError(f"{label} must be a non-empty portable relative path")
    path = PurePosixPath(value)
    if value == ".":
        if allow_root:
            return path
        raise EvidenceValidationError(f"{label} must name a file below the replay root")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceValidationError(f"{label} must not escape the bundle root")
    if len(value) > 1024 or any(not _PUBLIC_PATH_PART.fullmatch(part) for part in path.parts):
        raise EvidenceValidationError(f"{label} contains a non-public path component")
    return path


def artifact_descriptor(
    path: Path,
    *,
    root: Path,
    media_type: str = "application/json",
) -> dict[str, Any]:
    """Describe a public aggregate artifact without opening symbolic links."""
    if media_type != "application/json":
        raise EvidenceValidationError(
            "public_aggregate_no_text artifacts must use the registered JSON contract"
        )
    try:
        if path.is_symlink():
            raise EvidenceValidationError("evidence artifacts must be regular non-symlink files")
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(resolved_root)
    except EvidenceValidationError:
        raise
    except (OSError, ValueError):
        raise EvidenceValidationError("evidence artifact is outside the declared root") from None
    portable = _relative_path(relative.as_posix(), "artifact path")
    data = _read_bounded_file(
        resolved,
        MAX_BUNDLE_BYTES,
        "evidence artifact is not a bounded regular file",
    )
    byte_digest = _sha256_bytes(data)
    canonical_digest = byte_digest
    try:
        parsed = strict_json_loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise EvidenceValidationError("JSON evidence artifact is not readable JSON") from None
    _require_plain_tree(parsed)
    if _contains_forbidden_fields(parsed):
        raise EvidenceValidationError("JSON evidence artifact contains private-data fields")
    _validate_public_json_artifact(parsed)
    canonical_digest = _sha256_bytes(canonical_json(parsed).encode("utf-8"))
    return {
        "path": portable.as_posix(),
        "sha256": byte_digest,
        "canonical_sha256": canonical_digest,
        "bytes": len(data),
        "media_type": media_type,
        "privacy_class": "public_aggregate_no_text",
    }


def replay_recipe_identity(recipe: Mapping[str, Any]) -> str:
    """Return the public commitment for a private, local replay recipe."""
    _require_plain_tree(recipe)
    return _sha256_bytes(canonical_json(recipe).encode("utf-8"))


def _validate_replay_recipe(value: Any, *, expected_sha256: str | None = None) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceValidationError("replay recipe must be an object")
    _require_plain_tree(value)
    required = {"schema_version", "argv", "working_directory", "result_bundle_path"}
    if set(value) != required or value.get("schema_version") != REPLAY_RECIPE_SCHEMA_VERSION:
        raise EvidenceValidationError("replay recipe fields do not match the v1 contract")
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not _PUBLIC_ARG.fullmatch(item) for item in argv)
        or argv[0].startswith("-")
    ):
        raise EvidenceValidationError("replay argv must contain only bounded portable tokens")
    forbidden_argument_names = _SENSITIVE_ARG_FIELDS | {
        "body",
        "completion",
        "content",
        "document",
        "env",
        "environment",
        "human_text",
        "input",
        "prompt",
        "raw",
        "response",
        "source_text",
        "text",
    }
    for item in argv:
        normalized = _normal_key(item.split("=", 1)[0].lstrip("-/"))
        if normalized in forbidden_argument_names or normalized.endswith(
            ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
        ):
            raise EvidenceValidationError("replay argv cannot contain private-data arguments")
        if "://" in item or "@" in item and ":" in item:
            raise EvidenceValidationError("replay argv cannot contain URLs or credentials")
    _relative_path(value.get("working_directory"), "working_directory", allow_root=True)
    _relative_path(value.get("result_bundle_path"), "result_bundle_path")
    result = dict(value)
    identity = replay_recipe_identity(result)
    if expected_sha256 is not None and identity != expected_sha256:
        raise EvidenceValidationError("replay recipe digest does not match the evidence bundle")
    return result


def load_replay_recipe(path: Path) -> dict[str, Any]:
    """Load a bounded local recipe without publishing its argv or paths."""
    try:
        data = _read_bounded_file(
            path,
            MAX_REPLAY_RECIPE_BYTES,
            "replay recipe is not a bounded regular file",
        )
        value = strict_json_loads(data)
    except EvidenceValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise EvidenceValidationError("replay recipe is not readable bounded JSON") from None
    return _validate_replay_recipe(value)


def reproduction_descriptor(
    recipe: Mapping[str, Any],
    *,
    timeout_seconds: int,
    network_required: bool,
    model_download_required: bool,
) -> dict[str, Any]:
    """Create the content-free public commitment to a local replay recipe."""
    validated = _validate_replay_recipe(recipe)
    return _validate_reproduction(
        {
            "recipe_sha256": replay_recipe_identity(validated),
            "timeout_seconds": timeout_seconds,
            "network_required": network_required,
            "model_download_required": model_download_required,
        }
    )


def reference_replay_recipe(*, protocol_run: bool = False) -> dict[str, Any]:
    """Return one deterministic built-in recipe safe for automatic replay."""
    if protocol_run:
        return {
            "schema_version": REPLAY_RECIPE_SCHEMA_VERSION,
            "argv": [
                "dewatermark-evidence",
                "reference-protocol",
                "--output-directory",
                "reproduced",
            ],
            "working_directory": ".",
            "result_bundle_path": "reproduced/evidence.json",
        }
    return {
        "schema_version": REPLAY_RECIPE_SCHEMA_VERSION,
        "argv": [
            "dewatermark-evidence",
            "reference",
            "--output",
            "reference-evidence.json",
        ],
        "working_directory": ".",
        "result_bundle_path": "reference-evidence.json",
    }


def _builtin_replay_recipe(recipe_sha256: str) -> dict[str, Any] | None:
    for protocol_run in (False, True):
        recipe = reference_replay_recipe(protocol_run=protocol_run)
        if replay_recipe_identity(recipe) == recipe_sha256:
            return recipe
    return None


def _resolved_replay_process(
    recipe: Mapping[str, Any], recipe_sha256: str
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Resolve a built-in logical entry point without trusting ambient PATH.

    Custom recipes execute their digest-bound argv exactly. Built-in reference
    recipes instead run this installed/source module with the current Python
    interpreter. Absolute local paths remain process-private and never enter a
    bundle, plan, report, or error.
    """
    environment = scrubbed_subprocess_environment()
    argv = tuple(str(item) for item in recipe["argv"])
    builtin = _builtin_replay_recipe(recipe_sha256)
    if builtin is None or replay_recipe_identity(builtin) != replay_recipe_identity(recipe):
        return argv, environment
    if not argv or argv[0] != "dewatermark-evidence":
        raise EvidenceValidationError("built-in replay recipe entry point is invalid")
    module_path = Path(__file__).resolve()
    source_root = module_path.parent.parent / "src"
    if (source_root / "dewatermark" / "__init__.py").is_file():
        environment["PYTHONPATH"] = str(source_root)
    return (sys.executable, str(module_path), *argv[1:]), environment


def _validate_reproduction(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceValidationError("reproduction must be an object")
    _require_plain_tree(value)
    required = {
        "recipe_sha256",
        "timeout_seconds",
        "network_required",
        "model_download_required",
    }
    if set(value) != required:
        raise EvidenceValidationError("reproduction fields do not match the v1 contract")
    recipe_sha256 = value.get("recipe_sha256")
    if not isinstance(recipe_sha256, str) or not _SHA256.fullmatch(recipe_sha256):
        raise EvidenceValidationError("reproduction recipe_sha256 is invalid")
    timeout = value.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 604800:
        raise EvidenceValidationError("reproduction timeout is outside the allowed range")
    if not isinstance(value.get("network_required"), bool) or not isinstance(
        value.get("model_download_required"), bool
    ):
        raise EvidenceValidationError("reproduction permission requirements must be booleans")
    if value["model_download_required"] and not value["network_required"]:
        raise EvidenceValidationError("a model download also requires network access")
    return dict(value)


def _validate_telemetry(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceValidationError("resource_telemetry must be an object")
    _require_plain_tree(value)
    required = {
        "wall_time",
        "process_cpu_time",
        "peak_rss",
        "model_size",
        "remote_queries",
        "generated_tokens",
        "estimated_cost",
    }
    if not required <= set(value):
        raise EvidenceValidationError("resource_telemetry omits required measurements")
    result: dict[str, Any] = {}
    expected_units = {
        "wall_time": "seconds",
        "process_cpu_time": "seconds",
        "peak_rss": "bytes",
        "model_size": "bytes",
        "remote_queries": "queries",
        "generated_tokens": "tokens",
        "estimated_cost": "USD",
    }
    for key, item in value.items():
        if type(key) is not str or type(item) is not dict:
            raise EvidenceValidationError("telemetry values must be named objects")
        if key not in required and not re.fullmatch(
            r"operation\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}", key
        ):
            raise EvidenceValidationError("unknown resource telemetry field")
        if set(item) != {"state", "value", "unit"}:
            raise EvidenceValidationError("telemetry fields do not match the v1 contract")
        if item.get("state") not in {
            "measured",
            "declared",
            "not_available",
            "not_applicable",
        }:
            raise EvidenceValidationError("invalid telemetry state")
        number = item.get("value")
        if number is not None and (
            not isinstance(number, (int, float))
            or isinstance(number, bool)
            or not math.isfinite(number)
            or number < 0
        ):
            raise EvidenceValidationError("telemetry values must be non-negative")
        if item["state"] in {"measured", "declared"} and number is None:
            raise EvidenceValidationError("measured or declared telemetry requires a value")
        if item["state"] in {"not_available", "not_applicable"} and number is not None:
            raise EvidenceValidationError("unavailable telemetry must use null")
        expected_unit = expected_units.get(key, "calls")
        if item.get("unit") != expected_unit:
            raise EvidenceValidationError("telemetry unit does not match its registered field")
        result[key] = dict(item)
    return result


def _claim_eligibility(coverage: Mapping[str, Any], purpose: str) -> dict[str, Any]:
    incomplete = sorted(
        area for area, value in coverage.items() if value.get("state") != "complete"
    )
    reasons = [f"protocol_area_incomplete:{area}" for area in incomplete]
    if purpose != "frozen_evaluation":
        reasons.append(f"non_claim_purpose:{purpose}")
    # A source bundle cannot self-certify independent reproduction. A separate
    # cross-bound replication record is required by ``verify_replication``.
    reasons.append("independent_replication_record_required")
    return {
        "protocol_complete": not incomplete,
        "comparative_performance_eligible": False,
        "best_in_class_eligible": False,
        "reason_codes": sorted(set(reasons)),
    }


def create_bundle(
    *,
    purpose: str,
    manifest: Mapping[str, Any],
    protocol_coverage: Mapping[str, Any],
    results: Mapping[str, Any],
    resource_telemetry: Mapping[str, Any],
    reproduction: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]] = (),
    sample_registry_sha256: str | None = None,
    sample_count: int | None = None,
) -> dict[str, Any]:
    """Create an immutable, content-free evidence bundle."""
    if type(purpose) is not str or purpose not in {
        "harness_conformance",
        "exploratory",
        "frozen_evaluation",
    }:
        raise EvidenceValidationError("unknown bundle purpose")
    for value in (manifest, protocol_coverage, results, resource_telemetry, reproduction):
        _require_plain_tree(value)
    if type(artifacts) not in (list, tuple):
        raise EvidenceValidationError("artifacts must be a plain array")
    _require_plain_tree(artifacts)
    if _contains_forbidden_fields(
        {"manifest": manifest, "results": results, "artifacts": artifacts}
    ):
        raise EvidenceValidationError("evidence bundles cannot contain text or credentials")
    protocol = load_protocol_registry()
    coverage = validate_coverage_declaration(protocol_coverage, protocol)
    try:
        telemetry = _validate_telemetry(resource_telemetry)
    except EvidenceValidationError:
        raise
    reproduction_value = _validate_reproduction(reproduction)
    safe_manifest = json_safe(_validate_public_manifest(manifest))
    safe_results = json_safe(_validate_public_results(results))
    safe_artifacts = json_safe(artifacts)
    _require_public_values(coverage)
    _validate_result_keys({"coverage": coverage})
    if _contains_forbidden_fields(
        {"manifest": safe_manifest, "results": safe_results, "artifacts": safe_artifacts}
    ):
        raise EvidenceValidationError("evidence bundles cannot contain text or credentials")
    sample_registry = None
    if sample_registry_sha256 is not None or sample_count is not None:
        if not isinstance(sample_registry_sha256, str) or not _SHA256.fullmatch(
            sample_registry_sha256
        ):
            raise EvidenceValidationError("sample registry requires a SHA-256 digest")
        if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count < 0:
            raise EvidenceValidationError("sample registry requires a non-negative sample count")
        sample_registry = {"sha256": sample_registry_sha256, "sample_count": sample_count}
    bundle: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_type": "dewatermark_benchmark_evidence",
        "purpose": purpose,
        "manifest": safe_manifest,
        "protocol_registry": {
            "id": protocol["registry_id"],
            "sha256": registry_sha256(protocol),
        },
        "sample_registry": sample_registry,
        "protocol_coverage": coverage,
        "results": safe_results,
        "artifacts": safe_artifacts,
        "resource_telemetry": telemetry,
        "reproduction": reproduction_value,
        "claim_eligibility": _claim_eligibility(coverage, purpose),
    }
    bundle["bundle_id"] = bundle_identity(bundle)
    validate_bundle(bundle, verify_artifacts=False)
    return bundle


def _validate_artifact_descriptors(entries: Any) -> None:
    """Validate public descriptor metadata even when local files are unavailable."""
    if type(entries) is not list:
        raise EvidenceValidationError("artifacts must be an array")
    _require_plain_tree(entries)
    _require_public_values(entries)
    if not entries:
        return
    seen: set[str] = set()
    for item in entries:
        if type(item) is not dict or set(item) != {
            "path",
            "sha256",
            "canonical_sha256",
            "bytes",
            "media_type",
            "privacy_class",
        }:
            raise EvidenceValidationError("artifact descriptor violates the v1 contract")
        portable = _relative_path(item.get("path"), "artifact path")
        if portable.as_posix() in seen:
            raise EvidenceValidationError("artifact paths must be unique")
        seen.add(portable.as_posix())
        if item.get("privacy_class") != "public_aggregate_no_text":
            raise EvidenceValidationError(
                "evidence bundles reference only public no-text artifacts"
            )
        if item.get("media_type") != "application/json":
            raise EvidenceValidationError(
                "public no-text artifacts must use the registered JSON media type"
            )
        digest = item.get("sha256")
        canonical_digest = item.get("canonical_sha256")
        size = item.get("bytes")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise EvidenceValidationError("artifact sha256 is invalid")
        if not isinstance(canonical_digest, str) or not _SHA256.fullmatch(canonical_digest):
            raise EvidenceValidationError("artifact canonical_sha256 is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceValidationError("artifact byte count is invalid")
        if size > MAX_BUNDLE_BYTES:
            raise EvidenceValidationError("evidence artifact exceeds the size limit")


def _validate_artifacts(entries: Any, root: Path) -> list[tuple[Mapping[str, Any], Any]]:
    _validate_artifact_descriptors(entries)
    if not entries:
        return []
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        raise EvidenceValidationError("artifact root is not an accessible directory") from None
    validated: list[tuple[Mapping[str, Any], Any]] = []
    for item in entries:
        portable = _relative_path(item.get("path"), "artifact path")
        digest = item["sha256"]
        canonical_digest = item["canonical_sha256"]
        size = item["bytes"]
        path = resolved_root.joinpath(*portable.parts)
        try:
            if path.is_symlink():
                raise EvidenceValidationError("artifact is missing or not a regular file")
            resolved = path.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except EvidenceValidationError:
            raise
        except (OSError, ValueError):
            raise EvidenceValidationError("artifact resolves outside the bundle root") from None
        data = _read_bounded_file(
            resolved,
            MAX_BUNDLE_BYTES,
            "artifact is not a bounded regular file",
        )
        if len(data) != size or _sha256_bytes(data) != digest:
            raise EvidenceValidationError("artifact digest mismatch")
        try:
            parsed = strict_json_loads(data)
        except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
            raise EvidenceValidationError("JSON artifact is not readable bounded data") from None
        _require_plain_tree(parsed)
        if _contains_forbidden_fields(parsed):
            raise EvidenceValidationError("JSON artifact contains private-data fields")
        _validate_public_json_artifact(parsed)
        observed_canonical = _sha256_bytes(canonical_json(parsed).encode("utf-8"))
        if observed_canonical != canonical_digest:
            raise EvidenceValidationError("artifact canonical digest mismatch")
        validated.append((item, parsed))
    return validated


def _validate_bundle_artifact_graph(
    bundle: Mapping[str, Any],
    artifacts: Sequence[tuple[Mapping[str, Any], Any]] | None = None,
) -> None:
    """Bind every benchmark identity to one coherent sample/observation graph."""
    sample_reference = bundle.get("sample_registry")
    results = bundle.get("results")
    if type(results) is not dict:
        raise EvidenceValidationError("bundle results must be a plain object")
    result_sample_digest = results.get("sample_registry_sha256")
    result_observation_id = results.get("observation_set_id")
    manifest = bundle.get("manifest")
    contract_version = (
        manifest.get("aggregation_contract_version") if type(manifest) is dict else None
    )
    if contract_version not in {None, _AGGREGATION_CONTRACT_VERSION}:
        raise EvidenceValidationError("bundle aggregation contract is unsupported")
    strict_aggregate = contract_version == _AGGREGATION_CONTRACT_VERSION
    if strict_aggregate:
        expected_fields = set(_STRICT_AGGREGATE_RESULT_FIELDS)
        if "comparative_analysis" in results:
            expected_fields.add("comparative_analysis")
        if set(results) != expected_fields:
            raise EvidenceValidationError("bound aggregate results are incomplete")
        replicates = manifest.get("bootstrap_replicates_count")
        seed = manifest.get("bootstrap_seed_count")
        if (
            type(replicates) is not int
            or not 2 <= replicates <= 10_000
            or type(seed) is not int
            or not 0 <= seed <= (1 << 63) - 1
        ):
            raise EvidenceValidationError("bound aggregate bootstrap settings are invalid")

    if sample_reference is None:
        if strict_aggregate:
            raise EvidenceValidationError("bound aggregate requires a sample registry")
        if result_sample_digest is not None or result_observation_id is not None:
            raise EvidenceValidationError("bundle result identities require a sample registry")
        if artifacts is not None and any(
            type(value) is dict and ("samples" in value or "observations" in value)
            for _, value in artifacts
        ):
            raise EvidenceValidationError("bundle contains an undeclared benchmark artifact graph")
        return

    assert isinstance(sample_reference, Mapping)
    expected_sample_digest = sample_reference["sha256"]
    if result_sample_digest != expected_sample_digest:
        raise EvidenceValidationError("bundle results reference another sample registry")
    if type(result_observation_id) is not str or not _SHA256.fullmatch(result_observation_id):
        raise EvidenceValidationError("bundle results require an observation-set identity")

    descriptor_matches = sum(
        item.get("canonical_sha256") == expected_sample_digest
        for item in bundle.get("artifacts", [])
        if isinstance(item, Mapping)
    )
    if descriptor_matches != 1:
        raise EvidenceValidationError("bundle must declare exactly one sample registry artifact")
    comparator_digest = manifest.get("comparator_registry_sha256") if strict_aggregate else None
    comparator_declared = bool(
        type(comparator_digest) is str and _SHA256.fullmatch(comparator_digest)
    )
    comparative_present = "comparative_analysis" in results
    if strict_aggregate and comparator_declared != comparative_present:
        raise EvidenceValidationError(
            "bound aggregate comparator declaration and analysis do not match"
        )
    if strict_aggregate and comparator_declared:
        if (
            sum(
                item.get("canonical_sha256") == comparator_digest
                for item in bundle.get("artifacts", [])
                if isinstance(item, Mapping)
            )
            != 1
        ):
            raise EvidenceValidationError(
                "bound aggregate requires exactly one comparator registry artifact"
            )
    if artifacts is None:
        return

    sample_artifacts = [
        (descriptor, value)
        for descriptor, value in artifacts
        if type(value) is dict and "samples" in value
    ]
    observation_artifacts = [
        (descriptor, value)
        for descriptor, value in artifacts
        if type(value) is dict and "observations" in value
    ]
    comparator_artifacts = [
        (descriptor, value)
        for descriptor, value in artifacts
        if type(value) is dict
        and set(value)
        == {
            "schema_version",
            "registry_id",
            "classification",
            "frozen",
            "control_condition_id",
            "analysis",
            "conditions",
        }
    ]
    if len(sample_artifacts) != 1 or len(observation_artifacts) != 1:
        raise EvidenceValidationError(
            "bundle requires exactly one sample registry and one observation set artifact"
        )
    sample_descriptor, sample_registry = sample_artifacts[0]
    _, observation_set = observation_artifacts[0]

    try:
        from .observations import ObservationValidationError, validate_observation_set
        from .protocol import validate_sample_registry
    except ImportError:
        from observations import (  # type: ignore
            ObservationValidationError,
            validate_observation_set,
        )
        from protocol import validate_sample_registry  # type: ignore

    try:
        sample_report = validate_sample_registry(sample_registry)
        observation_report = validate_observation_set(observation_set, sample_registry)
    except (ObservationValidationError, ProtocolValidationError, ValueError):
        raise EvidenceValidationError("bundle benchmark artifact graph is inconsistent") from None
    if (
        sample_descriptor.get("canonical_sha256") != sample_report["sample_registry_sha256"]
        or sample_report["sample_registry_sha256"] != expected_sample_digest
        or sample_report["sample_count"] != sample_reference["sample_count"]
        or observation_report["observation_set_id"] != result_observation_id
        or observation_set.get("sample_registry_sha256") != expected_sample_digest
        or results.get("sample_registry_sha256") != expected_sample_digest
        or results.get("observation_set_id") != observation_set.get("observation_set_id")
        or bundle.get("manifest") != observation_set.get("run_manifest")
        or bundle.get("reproduction") != observation_set.get("reproduction")
    ):
        raise EvidenceValidationError("bundle benchmark artifact graph is inconsistent")
    if "resource_telemetry" in results and results["resource_telemetry"] != bundle.get(
        "resource_telemetry"
    ):
        raise EvidenceValidationError("bundle benchmark resource identities are inconsistent")
    if not strict_aggregate:
        return

    comparator_registry = None
    if comparator_declared:
        if len(comparator_artifacts) != 1:
            raise EvidenceValidationError(
                "bound aggregate requires exactly one comparator registry artifact"
            )
        comparator_descriptor, comparator_registry = comparator_artifacts[0]
        if comparator_descriptor.get("canonical_sha256") != manifest.get(
            "comparator_registry_sha256"
        ):
            raise EvidenceValidationError("bound comparator registry identity is inconsistent")
    elif comparator_artifacts:
        raise EvidenceValidationError("aggregate declares an unused comparator registry artifact")

    try:
        from .observations import aggregate_observation_set
    except ImportError:
        from observations import aggregate_observation_set  # type: ignore

    try:
        aggregate = aggregate_observation_set(
            observation_set,
            sample_registry,
            bootstrap_replicates=manifest["bootstrap_replicates_count"],
            bootstrap_seed=manifest["bootstrap_seed_count"],
            comparator_registry=comparator_registry,
        )
    except (ObservationValidationError, ProtocolValidationError, ValueError):
        raise EvidenceValidationError("bound aggregate could not be reproduced") from None
    expected_results = dict(aggregate)
    expected_results["score_tables"] = {
        name: {"sha256": table["sha256"], "records": len(table["records"])}
        for name, table in aggregate["score_tables"].items()
    }
    expected_results["aggregate_sha256"] = results_identity(expected_results)
    if expected_results != results:
        raise EvidenceValidationError("bundle results do not reproduce from observations")

    result_coverage = results["coverage"]
    bundle_coverage = bundle.get("protocol_coverage")
    if type(result_coverage) is not dict or type(bundle_coverage) is not dict:
        raise EvidenceValidationError("bound aggregate coverage is incomplete")
    expected_bundle_coverage = dict(result_coverage)
    expected_bundle_coverage["artifact_handling"] = {
        "state": "complete",
        "reason": "source_artifacts_bound_by_digest",
    }
    if bundle_coverage != expected_bundle_coverage:
        raise EvidenceValidationError("bundle coverage does not match reproduced results")


def validate_bundle(
    bundle: Mapping[str, Any],
    *,
    artifact_root: Path | None = None,
    verify_artifacts: bool = True,
) -> dict[str, Any]:
    """Fail closed on mutation, omitted coverage, content, or artifact drift."""
    _require_plain_tree(bundle)
    if type(bundle) is not dict:
        raise EvidenceValidationError("bundle must be a plain object")
    required = {
        "schema_version",
        "bundle_type",
        "bundle_id",
        "purpose",
        "manifest",
        "protocol_registry",
        "sample_registry",
        "protocol_coverage",
        "results",
        "artifacts",
        "resource_telemetry",
        "reproduction",
        "claim_eligibility",
    }
    if set(bundle) != required:
        raise EvidenceValidationError("bundle fields do not match the v1 contract")
    if (
        bundle.get("schema_version") != BUNDLE_SCHEMA_VERSION
        or bundle.get("bundle_type") != "dewatermark_benchmark_evidence"
    ):
        raise EvidenceValidationError("unsupported evidence bundle schema")
    if _contains_forbidden_fields(bundle):
        raise EvidenceValidationError("evidence bundle contains text or credential fields")
    _require_public_values(bundle)
    purpose = bundle.get("purpose")
    if purpose not in {"harness_conformance", "exploratory", "frozen_evaluation"}:
        raise EvidenceValidationError("unknown evidence purpose")
    bundle_id = bundle.get("bundle_id")
    if not isinstance(bundle_id, str) or not _SHA256.fullmatch(bundle_id):
        raise EvidenceValidationError("bundle_id is not a SHA-256 digest")
    if bundle_identity(bundle) != bundle_id:
        raise EvidenceValidationError("bundle content digest mismatch")
    protocol = load_protocol_registry()
    protocol_ref = bundle.get("protocol_registry")
    if not isinstance(protocol_ref, Mapping) or protocol_ref != {
        "id": protocol["registry_id"],
        "sha256": registry_sha256(protocol),
    }:
        raise EvidenceValidationError("bundle is bound to another protocol registry")
    coverage = validate_coverage_declaration(bundle.get("protocol_coverage", {}), protocol)
    _validate_result_keys({"coverage": coverage})
    if bundle.get("claim_eligibility") != _claim_eligibility(coverage, str(purpose)):
        raise EvidenceValidationError("claim eligibility was not derived from bundle coverage")
    artifact_entries = bundle.get("artifacts")
    if not isinstance(artifact_entries, list):
        raise EvidenceValidationError("artifacts must be an array")
    _validate_artifact_descriptors(artifact_entries)
    sample_registry = bundle.get("sample_registry")
    if sample_registry is not None:
        if not isinstance(sample_registry, Mapping) or set(sample_registry) != {
            "sha256",
            "sample_count",
        }:
            raise EvidenceValidationError("sample_registry reference violates the v1 contract")
        if not isinstance(sample_registry.get("sha256"), str) or not _SHA256.fullmatch(
            sample_registry["sha256"]
        ):
            raise EvidenceValidationError("sample registry digest is invalid")
        if (
            not isinstance(sample_registry.get("sample_count"), int)
            or isinstance(sample_registry["sample_count"], bool)
            or sample_registry["sample_count"] < 0
        ):
            raise EvidenceValidationError("sample registry count is invalid")
        artifact_digests = {
            item.get("canonical_sha256") for item in artifact_entries if isinstance(item, Mapping)
        }
        if sample_registry["sha256"] not in artifact_digests:
            raise EvidenceValidationError(
                "sample registry digest is not bound by an artifact descriptor"
            )
    _validate_telemetry(bundle.get("resource_telemetry"))
    _validate_reproduction(bundle.get("reproduction"))
    if not isinstance(bundle.get("manifest"), Mapping) or not isinstance(
        bundle.get("results"), Mapping
    ):
        raise EvidenceValidationError("manifest and results must be objects")
    _validate_public_manifest(bundle["manifest"])
    _validate_public_results(bundle["results"])
    _validate_bundle_artifact_graph(bundle)
    if verify_artifacts:
        validated_artifacts = _validate_artifacts(artifact_entries, artifact_root or Path.cwd())
        _validate_bundle_artifact_graph(bundle, validated_artifacts)
    return {
        "valid": True,
        "bundle_id": bundle_id,
        "purpose": purpose,
        "protocol_complete": bundle["claim_eligibility"]["protocol_complete"],
        "aggregate_verified": bool(
            verify_artifacts
            and isinstance(bundle.get("manifest"), Mapping)
            and bundle["manifest"].get("aggregation_contract_version")
            == _AGGREGATION_CONTRACT_VERSION
        ),
        "artifact_count": len(bundle["artifacts"]),
    }


def read_bundle(path: Path, *, verify_artifacts: bool = True) -> dict[str, Any]:
    try:
        data = _read_bounded_file(
            path,
            MAX_BUNDLE_BYTES,
            "evidence bundle is not a bounded regular file",
        )
        value = strict_json_loads(data)
    except EvidenceValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise EvidenceValidationError("evidence bundle is not readable bounded JSON") from None
    if not isinstance(value, dict):
        raise EvidenceValidationError("evidence bundle must contain one JSON object")
    validate_bundle(value, artifact_root=path.parent, verify_artifacts=verify_artifacts)
    return value


def write_bundle(path: Path, bundle: Mapping[str, Any]) -> None:
    validate_bundle(bundle, artifact_root=path.parent, verify_artifacts=True)
    if path.exists() or path.is_symlink():
        raise EvidenceValidationError("evidence bundle exists; refusing to overwrite")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise EvidenceValidationError("evidence bundle directory could not be created") from None
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(json_safe(bundle), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise EvidenceValidationError("evidence bundle exists; refusing to overwrite") from None
        except OSError:
            raise EvidenceValidationError(
                "evidence bundle could not be written atomically"
            ) from None
    except OSError:
        raise EvidenceValidationError("evidence bundle could not be written atomically") from None
    finally:
        if created:
            try:
                temporary.unlink()
            except OSError:
                pass


def create_replication_record(
    *,
    source_bundle_id: str,
    reproduced_bundle_id: str,
    operator_id: str,
    organization: str,
    relationship: str,
    disclosure: str,
    executed_at: str,
    environment_sha256: str,
    command_sha256: str,
    outcome: str,
    deviations: Sequence[str] = (),
    tolerance_assessment_sha256: str | None = None,
    attestation_sha256: str | None = None,
) -> dict[str, Any]:
    record = {
        "schema_version": REPLICATION_SCHEMA_VERSION,
        "record_type": "dewatermark_independent_replication",
        "source_bundle_id": source_bundle_id,
        "reproduced_bundle_id": reproduced_bundle_id,
        "operator": {
            "id": operator_id,
            "organization": organization,
            "relationship": relationship,
            "disclosure": disclosure,
        },
        "executed_at": executed_at,
        "environment_sha256": environment_sha256,
        "command_sha256": command_sha256,
        "outcome": outcome,
        "tolerance_assessment_sha256": tolerance_assessment_sha256,
        "deviations": list(deviations),
        "attestation": {
            "state": "detached_signature" if attestation_sha256 else "not_signed",
            "artifact_sha256": attestation_sha256,
        },
    }
    _require_public_values(record)
    record["record_id"] = replication_identity(record)
    validate_replication_record(record)
    return record


def validate_replication_record(
    record: Mapping[str, Any],
    *,
    source_bundle: Mapping[str, Any] | None = None,
    reproduced_bundle: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _require_plain_tree(record)
    if type(record) is not dict:
        raise EvidenceValidationError("replication record must be a plain object")
    required = {
        "schema_version",
        "record_type",
        "record_id",
        "source_bundle_id",
        "reproduced_bundle_id",
        "operator",
        "executed_at",
        "environment_sha256",
        "command_sha256",
        "outcome",
        "tolerance_assessment_sha256",
        "deviations",
        "attestation",
    }
    if set(record) != required:
        raise EvidenceValidationError("replication fields do not match the v1 contract")
    if (
        record.get("schema_version") != REPLICATION_SCHEMA_VERSION
        or record.get("record_type") != "dewatermark_independent_replication"
    ):
        raise EvidenceValidationError("unsupported replication schema")
    if _contains_forbidden_fields(record):
        raise EvidenceValidationError("replication record contains credential fields")
    _require_public_values(record)
    for field in (
        "record_id",
        "source_bundle_id",
        "reproduced_bundle_id",
        "environment_sha256",
        "command_sha256",
    ):
        if not isinstance(record.get(field), str) or not _SHA256.fullmatch(record[field]):
            raise EvidenceValidationError(f"replication {field} is invalid")
    if replication_identity(record) != record["record_id"]:
        raise EvidenceValidationError("replication record content digest mismatch")
    operator = record.get("operator")
    if not isinstance(operator, Mapping) or set(operator) != {
        "id",
        "organization",
        "relationship",
        "disclosure",
    }:
        raise EvidenceValidationError("replication operator disclosure is incomplete")
    if operator.get("relationship") not in {
        "independent",
        "same_organization",
        "original_operator",
    }:
        raise EvidenceValidationError("invalid replication relationship")
    if any(
        not isinstance(operator.get(field), str) or not operator[field].strip()
        for field in ("id", "organization", "disclosure")
    ):
        raise EvidenceValidationError("replication operator strings cannot be empty")
    if not _PUBLIC_ID.fullmatch(operator["id"]) or not _PUBLIC_ID.fullmatch(
        operator["organization"]
    ):
        raise EvidenceValidationError("replication operator identity must use public identifiers")
    if len(operator["disclosure"]) > 4096 or "\x00" in operator["disclosure"]:
        raise EvidenceValidationError("replication disclosure is not bounded public metadata")
    if record.get("outcome") not in {
        "exact_match",
        "within_registered_tolerance",
        "deviated",
        "failed",
    }:
        raise EvidenceValidationError("invalid replication outcome")
    if not isinstance(record.get("executed_at"), str) or not _RFC3339_UTC.fullmatch(
        record["executed_at"]
    ):
        raise EvidenceValidationError("replication executed_at must be an RFC 3339 UTC timestamp")
    deviations = record.get("deviations")
    if not isinstance(deviations, list) or any(
        not isinstance(value, str) or not _PUBLIC_ID.fullmatch(value) for value in deviations
    ):
        raise EvidenceValidationError("replication deviations must be public reason codes")
    tolerance = record.get("tolerance_assessment_sha256")
    if record["outcome"] == "within_registered_tolerance":
        if not isinstance(tolerance, str) or not _SHA256.fullmatch(tolerance):
            raise EvidenceValidationError("tolerance outcome requires an assessment digest")
    elif tolerance is not None:
        raise EvidenceValidationError("tolerance digest is allowed only for its matching outcome")
    attestation = record.get("attestation")
    if not isinstance(attestation, Mapping) or set(attestation) != {"state", "artifact_sha256"}:
        raise EvidenceValidationError("replication attestation is incomplete")
    if attestation.get("state") == "not_signed" and attestation.get("artifact_sha256") is not None:
        raise EvidenceValidationError("unsigned replication cannot name a signature artifact")
    if attestation.get("state") == "detached_signature":
        if not isinstance(attestation.get("artifact_sha256"), str) or not _SHA256.fullmatch(
            attestation["artifact_sha256"]
        ):
            raise EvidenceValidationError("detached signature requires an artifact digest")
    elif attestation.get("state") != "not_signed":
        raise EvidenceValidationError("invalid attestation state")
    if source_bundle is not None:
        validate_bundle(source_bundle, verify_artifacts=False)
        if source_bundle["bundle_id"] != record["source_bundle_id"]:
            raise EvidenceValidationError("replication source bundle id does not match")
    if reproduced_bundle is not None:
        validate_bundle(reproduced_bundle, verify_artifacts=False)
        if reproduced_bundle["bundle_id"] != record["reproduced_bundle_id"]:
            raise EvidenceValidationError("replication result bundle id does not match")
    if (
        record["outcome"] == "exact_match"
        and source_bundle is not None
        and reproduced_bundle is not None
        and source_bundle["bundle_id"] != reproduced_bundle["bundle_id"]
    ):
        raise EvidenceValidationError("exact_match requires byte-equivalent content identities")
    independence_metadata_satisfied = (
        operator["relationship"] == "independent"
        and record["outcome"] in {"exact_match", "within_registered_tolerance"}
        and source_bundle is not None
        and reproduced_bundle is not None
    )
    return {
        "valid": True,
        "record_id": record["record_id"],
        "independence_metadata_satisfied": independence_metadata_satisfied,
        "detached_signature_declared": attestation["state"] == "detached_signature",
        "cryptographic_attestation_verified": False,
    }


def verified_claim_eligibility(
    bundle: Mapping[str, Any],
    replication_records: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, Any]:
    """Upgrade comparative eligibility only after a cross-bound replication."""
    validate_bundle(bundle, verify_artifacts=False)
    candidate_records: list[str] = []
    for record, reproduced in replication_records:
        result = validate_replication_record(
            record, source_bundle=bundle, reproduced_bundle=reproduced
        )
        if result["independence_metadata_satisfied"]:
            candidate_records.append(str(result["record_id"]))
    core_complete = all(
        value.get("state") == "complete"
        for area, value in bundle["protocol_coverage"].items()
        if area != "independent_replication"
    )
    # A public digest declaring a detached signature is not cryptographic
    # verification. This library therefore never upgrades a claim solely from
    # self-declared replication metadata.
    protocol_complete = False
    return {
        "protocol_complete": protocol_complete,
        "core_protocol_complete": core_complete,
        "independent_replication_verified": False,
        "comparative_performance_eligible": False,
        # "Best" additionally requires a frozen comparator registry and a
        # multiple-comparison-aware analysis, neither inferred here.
        "best_in_class_eligible": False,
        "candidate_replication_record_ids": sorted(candidate_records),
        "reason_codes": ["external_cryptographic_attestation_verification_required"],
    }


def _reference_coverage() -> dict[str, Any]:
    protocol = load_protocol_registry()
    exercised = {
        "reproducible_identity": "synthetic_fixture_content_addressed",
        "independent_splits": "synthetic_calibration_and_test_arrays_distinct",
        "detector_statistics": "fixed_fpr_serialization_exercised",
        "artifact_handling": "evidence_bundle_validation_exercised",
        "resource_accounting": "offline_zero_cost_declarations_exercised",
    }
    return {
        area: {
            "state": "complete" if area in exercised else "not_run",
            "reason": exercised.get(area, "not_exercised_by_synthetic_fixture"),
        }
        for area in protocol["coverage_areas"]
    }


def create_reference_bundle() -> dict[str, Any]:
    """Deterministic offline fixture; explicitly ineligible for efficacy claims."""
    fixture_digest = _sha256_bytes(b"dewatermark-evidence-reference-v1")
    return create_bundle(
        purpose="harness_conformance",
        manifest={
            "schema_version": "1.0",
            "fixture": "dewatermark-evidence-reference-v1",
            "fixture_sha256": fixture_digest,
            "network_allowed": False,
            "model_download_allowed": False,
        },
        protocol_coverage=_reference_coverage(),
        results={
            "classification": "synthetic_harness_fixture_not_performance_evidence",
            "positive_scores": [0.9, 0.8, 0.7, 0.6],
            "calibration_null_scores": [index / 100.0 for index in range(100)],
            "test_null_scores": [index / 200.0 for index in range(100)],
            "failures": 0,
            "abstentions": 0,
            "attempted": 4,
        },
        resource_telemetry=zero_network_telemetry(operations={"fixture_cases": 204}),
        reproduction=reproduction_descriptor(
            reference_replay_recipe(),
            timeout_seconds=60,
            network_required=False,
            model_download_required=False,
        ),
    )


def replay_bundle(
    bundle: Mapping[str, Any],
    *,
    workspace: Path,
    recipe: Mapping[str, Any] | None = None,
    execute: bool = False,
    allow_network: bool = False,
    allow_model_download: bool = False,
) -> dict[str, Any]:
    """Return a content-free plan, or execute a digest-bound local recipe."""
    validate_bundle(bundle, verify_artifacts=False)
    reproduction = _validate_reproduction(bundle["reproduction"])
    if reproduction["network_required"] and not allow_network:
        raise EvidenceValidationError("replay requires explicit --allow-network consent")
    if reproduction["model_download_required"] and not (allow_network and allow_model_download):
        raise EvidenceValidationError(
            "replay model download requires --allow-network and --allow-model-download"
        )
    selected_recipe = (
        _validate_replay_recipe(recipe, expected_sha256=reproduction["recipe_sha256"])
        if recipe is not None
        else _builtin_replay_recipe(str(reproduction["recipe_sha256"]))
    )
    plan = {
        "bundle_id": bundle["bundle_id"],
        "recipe_sha256": reproduction["recipe_sha256"],
        "recipe_available": selected_recipe is not None,
        "network_required": reproduction["network_required"],
        "model_download_required": reproduction["model_download_required"],
        "executed": False,
    }
    if not execute:
        return plan
    if selected_recipe is None:
        raise EvidenceValidationError(
            "replay requires a local --recipe whose digest matches the bundle"
        )
    selected_recipe = _validate_replay_recipe(
        selected_recipe, expected_sha256=reproduction["recipe_sha256"]
    )
    selected_workspace = workspace.resolve()
    if selected_workspace.exists() and not selected_workspace.is_dir():
        raise EvidenceValidationError("replay workspace must be a directory")
    selected_workspace.mkdir(parents=True, exist_ok=True)
    working_path = _relative_path(
        selected_recipe["working_directory"], "working_directory", allow_root=True
    )
    run_directory = selected_workspace.joinpath(*working_path.parts)
    try:
        run_directory.resolve().relative_to(selected_workspace)
    except ValueError:
        raise EvidenceValidationError("replay working directory escapes the workspace") from None
    if not run_directory.is_dir():
        raise EvidenceValidationError("replay working directory does not exist")
    if run_directory.is_symlink():
        raise EvidenceValidationError("replay working directory cannot be a symbolic link")
    result_path = _relative_path(selected_recipe["result_bundle_path"], "result_bundle_path")
    output = run_directory.joinpath(*result_path.parts)

    def require_absent_output_entry() -> None:
        # ``Path.exists`` follows links and is false for a dangling link. The
        # directory entry itself must be absent, regardless of its target.
        try:
            output_status = output.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise EvidenceValidationError("replay result path cannot be inspected safely") from None
        if stat.S_ISLNK(output_status.st_mode):
            raise EvidenceValidationError("replay result bundle cannot be a symbolic link")
        raise EvidenceValidationError("replay refuses to overwrite an existing result bundle")

    require_absent_output_entry()
    try:
        output.resolve().relative_to(selected_workspace)
    except ValueError:
        raise EvidenceValidationError("replay result path escapes the workspace") from None
    cursor = output.parent
    while cursor != selected_workspace:
        if cursor.is_symlink():
            raise EvidenceValidationError("replay result path cannot traverse symbolic links")
        if cursor.parent == cursor:
            raise EvidenceValidationError("replay result path escapes the workspace")
        cursor = cursor.parent
    process_argv, process_environment = _resolved_replay_process(
        selected_recipe, str(reproduction["recipe_sha256"])
    )
    # Recheck immediately before process launch to cover a directory entry
    # introduced while resolving the digest-bound command and environment.
    require_absent_output_entry()
    try:
        run_bounded_process(
            process_argv,
            b"",
            timeout_seconds=float(reproduction["timeout_seconds"]),
            max_stdout_bytes=1024 * 1024,
            max_stderr_bytes=1024 * 1024,
            environment=process_environment,
            working_directory=run_directory,
        )
    except BoundedProcessFailure as exc:
        if exc.kind == "nonzero_exit":
            detail = f" exited with status {exc.returncode}"
        elif exc.kind == "timed_out":
            detail = " timed out"
        elif exc.kind == "output_limit":
            detail = " exceeded its output limit"
        else:
            detail = " failed or could not be cleaned up"
        raise EvidenceValidationError(f"replay command{detail}; output was redacted") from None
    if output.is_symlink():
        raise EvidenceValidationError("replay result bundle cannot be a symbolic link")
    try:
        output.resolve(strict=True).relative_to(selected_workspace)
    except (FileNotFoundError, ValueError):
        raise EvidenceValidationError("replay did not create a contained result bundle") from None
    reproduced = read_bundle(output)
    plan.update(executed=True, reproduced_bundle_id=reproduced["bundle_id"])
    return plan


def _load_replication(path: Path) -> dict[str, Any]:
    try:
        data = _read_bounded_file(
            path,
            MAX_BUNDLE_BYTES,
            "replication record is not a bounded regular file",
        )
        value = strict_json_loads(data)
    except EvidenceValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise EvidenceValidationError("replication record is not readable bounded JSON") from None
    if not isinstance(value, dict):
        raise EvidenceValidationError("replication record must contain one object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate, replay, and attest dewatermark benchmark evidence"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify an evidence bundle and its artifacts")
    verify.add_argument("bundle", type=Path)
    reference = commands.add_parser("reference", help="write the deterministic offline fixture")
    reference.add_argument("--output", type=Path, required=True)
    reference_protocol = commands.add_parser(
        "reference-protocol",
        help="write a deterministic sample/observation/bundle conformance run",
    )
    reference_protocol.add_argument("--output-directory", type=Path, required=True)
    replay = commands.add_parser("replay", help="inspect or execute a bundle replay plan")
    replay.add_argument("bundle", type=Path)
    replay.add_argument("--workspace", type=Path, default=Path.cwd())
    replay.add_argument(
        "--recipe",
        type=Path,
        help="bounded local recipe; required unless the bundle names a built-in reference recipe",
    )
    replay.add_argument("--execute", action="store_true")
    replay.add_argument("--allow-network", action="store_true")
    replay.add_argument("--allow-model-download", action="store_true")
    replication = commands.add_parser(
        "verify-replication", help="cross-check a replication record and both bundles"
    )
    replication.add_argument("record", type=Path)
    replication.add_argument("--source", type=Path, required=True)
    replication.add_argument("--reproduced", type=Path, required=True)
    assemble = commands.add_parser(
        "assemble", help="assemble a bundle from frozen samples and content-free observations"
    )
    assemble.add_argument("--sample-registry", type=Path, required=True)
    assemble.add_argument("--observations", type=Path, required=True)
    assemble.add_argument("--comparator-registry", type=Path)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument(
        "--purpose",
        choices=("exploratory", "frozen_evaluation"),
        default="exploratory",
    )
    assemble.add_argument("--bootstrap-replicates", type=int)
    assemble.add_argument("--bootstrap-seed", type=int)
    run = commands.add_parser(
        "run",
        help="execute a frozen adapter matrix and assemble content-free evidence",
    )
    run.add_argument(
        "--protocol-manifest",
        type=Path,
        default=Path(__file__).with_name("protocols") / "kgw-v1.json",
    )
    run.add_argument(
        "--comparator-registry",
        type=Path,
        default=Path(__file__).with_name("comparator-registry-v1.json"),
    )
    run.add_argument("--run-config", type=Path, required=True)
    run.add_argument("--input-corpus", type=Path, required=True)
    run.add_argument("--output-directory", type=Path, required=True)
    run.add_argument("--checkpoint", type=Path)
    run.add_argument("--resume", action="store_true")
    run.add_argument("--allow-network", action="store_true")
    run.add_argument("--allow-model-download", action="store_true")
    run.add_argument("--bootstrap-replicates", type=int, default=500)
    run.add_argument("--bootstrap-seed", type=int, default=0)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            result = validate_bundle(read_bundle(args.bundle), artifact_root=args.bundle.parent)
        elif args.command == "reference":
            bundle = create_reference_bundle()
            write_bundle(args.output, bundle)
            result = {"written": True, "bundle_id": bundle["bundle_id"]}
        elif args.command == "reference-protocol":
            try:
                from .reference_run import write_reference_protocol_run
            except ImportError:
                from reference_run import write_reference_protocol_run  # type: ignore

            result = write_reference_protocol_run(args.output_directory)
        elif args.command == "replay":
            bundle = read_bundle(args.bundle)
            result = replay_bundle(
                bundle,
                workspace=args.workspace,
                recipe=load_replay_recipe(args.recipe) if args.recipe is not None else None,
                execute=args.execute,
                allow_network=args.allow_network,
                allow_model_download=args.allow_model_download,
            )
        elif args.command == "verify-replication":
            source = read_bundle(args.source)
            reproduced = read_bundle(args.reproduced)
            result = validate_replication_record(
                _load_replication(args.record),
                source_bundle=source,
                reproduced_bundle=reproduced,
            )
        elif args.command == "run":
            try:
                from .benchmark_run import run_benchmark
            except ImportError:
                from benchmark_run import run_benchmark  # type: ignore

            result = run_benchmark(
                protocol_manifest_path=args.protocol_manifest,
                comparator_registry_path=args.comparator_registry,
                run_config_path=args.run_config,
                input_corpus_path=args.input_corpus,
                output_directory=args.output_directory,
                checkpoint_path=args.checkpoint,
                resume=args.resume,
                allow_network=args.allow_network,
                allow_model_download=args.allow_model_download,
                bootstrap_replicates=args.bootstrap_replicates,
                bootstrap_seed=args.bootstrap_seed,
            )
        else:
            try:
                from .comparisons import comparator_registry_sha256, load_comparator_registry
                from .observations import aggregate_observation_set, read_observation_set
                from .protocol import load_sample_registry
            except ImportError:
                from comparisons import (  # type: ignore
                    comparator_registry_sha256,
                    load_comparator_registry,
                )
                from observations import (  # type: ignore
                    aggregate_observation_set,
                    read_observation_set,
                )
                from protocol import load_sample_registry  # type: ignore

            sample_registry, sample_report = load_sample_registry(args.sample_registry)
            observations = read_observation_set(args.observations)
            manifest = observations.get("run_manifest")
            if type(manifest) is not dict:
                raise EvidenceValidationError("observation run manifest is invalid")
            _validate_public_manifest(manifest)
            contract_version = manifest.get("aggregation_contract_version")
            if contract_version not in {None, _AGGREGATION_CONTRACT_VERSION}:
                raise EvidenceValidationError("observation aggregation contract is unsupported")

            if contract_version == _AGGREGATION_CONTRACT_VERSION:
                manifest_replicates = manifest.get("bootstrap_replicates_count")
                manifest_seed = manifest.get("bootstrap_seed_count")
                if (
                    type(manifest_replicates) is not int
                    or not 2 <= manifest_replicates <= 10_000
                    or type(manifest_seed) is not int
                    or not 0 <= manifest_seed <= (1 << 63) - 1
                ):
                    raise EvidenceValidationError("bound aggregate bootstrap settings are invalid")
                if (
                    args.bootstrap_replicates is not None
                    and args.bootstrap_replicates != manifest_replicates
                ) or (args.bootstrap_seed is not None and args.bootstrap_seed != manifest_seed):
                    raise EvidenceValidationError(
                        "requested bootstrap settings do not match the observation manifest"
                    )
                bootstrap_replicates = manifest_replicates
                bootstrap_seed = manifest_seed
            else:
                bootstrap_replicates = (
                    500 if args.bootstrap_replicates is None else args.bootstrap_replicates
                )
                bootstrap_seed = 0 if args.bootstrap_seed is None else args.bootstrap_seed

            declared_comparator_digest = manifest.get("comparator_registry_sha256")
            comparator_registry = None
            if contract_version == _AGGREGATION_CONTRACT_VERSION and (
                (declared_comparator_digest is None) != (args.comparator_registry is None)
            ):
                raise EvidenceValidationError(
                    "bound aggregate comparator declaration and artifact do not match"
                )
            if args.comparator_registry is not None:
                comparator_registry = load_comparator_registry(args.comparator_registry)
                observed_comparator_digest = comparator_registry_sha256(comparator_registry)
                if (
                    declared_comparator_digest is not None
                    and observed_comparator_digest != declared_comparator_digest
                ):
                    raise EvidenceValidationError(
                        "comparator registry does not match the observation manifest"
                    )

            aggregate = aggregate_observation_set(
                observations,
                sample_registry,
                bootstrap_replicates=bootstrap_replicates,
                bootstrap_seed=bootstrap_seed,
                comparator_registry=comparator_registry,
            )
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
            public_results["aggregate_sha256"] = results_identity(public_results)
            output_root = args.output.parent.resolve()
            artifacts = [
                artifact_descriptor(args.sample_registry, root=output_root),
                artifact_descriptor(args.observations, root=output_root),
            ]
            if args.comparator_registry is not None:
                artifacts.append(artifact_descriptor(args.comparator_registry, root=output_root))
            bundle = create_bundle(
                purpose=args.purpose,
                manifest=manifest,
                protocol_coverage=coverage,
                results=public_results,
                resource_telemetry=aggregate["resource_telemetry"],
                reproduction=observations["reproduction"],
                artifacts=artifacts,
                sample_registry_sha256=sample_report["sample_registry_sha256"],
                sample_count=sample_report["sample_count"],
            )
            write_bundle(args.output, bundle)
            result = {
                "written": True,
                "bundle_id": bundle["bundle_id"],
                "protocol_complete": bundle["claim_eligibility"]["protocol_complete"],
            }
    except (EvidenceValidationError, ProtocolValidationError, OSError, RuntimeError, ValueError):
        parser.error("evidence validation failed; exception details were redacted")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

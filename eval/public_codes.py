"""Registered, content-free codes used by public benchmark artifacts.

Public evidence may carry one of these stable codes or a ``sha256:<digest>``
commitment to operator-local prose.  It must never carry the prose itself.
"""

from __future__ import annotations

import re
from typing import AbstractSet, Any

PUBLIC_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
SHA256_COMMITMENT = re.compile(r"^sha256:[0-9a-f]{64}$")

COVERAGE_REASON_CODES = frozenset(
    {
        "aggregate_content_addressed_bundle_binding_pending",
        "blinded_human_review_not_assessed",
        "blinded_review_metadata_complete",
        "cross_detector_negative_effects_complete",
        "cross_detector_negative_effects_incomplete",
        "detector_results_not_assessed",
        "detector_token_bins_complete",
        "detector_token_bins_missing",
        "evidence_bundle_not_assessed",
        "evidence_bundle_validation_exercised",
        "final_test_freeze_record_missing",
        "fixed_fpr_serialization_exercised",
        "fixed_fpr_stable_independent_complete",
        "fixed_fpr_unstable_independence_or_rows_incomplete",
        "independent_replication_not_attached",
        "key_partitions_frozen_before_final_test",
        "language_script_groups_complete",
        "language_script_groups_missing",
        "matched_controls_complete",
        "matched_controls_missing",
        "model_resource_telemetry_complete",
        "model_size_or_peak_memory_unavailable",
        "not_exercised_by_synthetic_fixture",
        "offline_zero_cost_declarations_exercised",
        "quality_and_task_outcomes_complete",
        "quality_gate_outcomes_not_assessed",
        "quality_or_task_outcomes_missing",
        "registry_inputs_and_freeze_content_addressed",
        "required_splits_incomplete",
        "source_artifacts_bound_by_digest",
        "splits_populated_and_clusters_disjoint",
        "synthetic_calibration_and_test_arrays_distinct",
        "synthetic_fixture_content_addressed",
        "task_checker_matrix_complete",
        "task_or_checker_matrix_incomplete",
        "transformed_control_scores_not_assessed",
        "tuning_and_final_key_fingerprints_required",
        "tuning_and_final_key_partitions_disjoint",
        "execution_telemetry_not_assessed",
    }
)

_NOT_EXERCISED = {"not_exercised_by_synthetic_fixture"}
COVERAGE_REASON_CODES_BY_AREA: dict[str, frozenset[str]] = {
    "reproducible_identity": frozenset(
        _NOT_EXERCISED
        | {
            "final_test_freeze_record_missing",
            "registry_inputs_and_freeze_content_addressed",
            "synthetic_fixture_content_addressed",
        }
    ),
    "independent_splits": frozenset(
        _NOT_EXERCISED
        | {
            "required_splits_incomplete",
            "splits_populated_and_clusters_disjoint",
            "synthetic_calibration_and_test_arrays_distinct",
        }
    ),
    "matched_controls": frozenset(
        _NOT_EXERCISED | {"matched_controls_complete", "matched_controls_missing"}
    ),
    "held_out_keys": frozenset(
        _NOT_EXERCISED
        | {
            "key_partitions_frozen_before_final_test",
            "tuning_and_final_key_fingerprints_required",
            "tuning_and_final_key_partitions_disjoint",
        }
    ),
    "length_coverage": frozenset(
        _NOT_EXERCISED | {"detector_token_bins_complete", "detector_token_bins_missing"}
    ),
    "task_coverage": frozenset(
        _NOT_EXERCISED | {"task_checker_matrix_complete", "task_or_checker_matrix_incomplete"}
    ),
    "language_coverage": frozenset(
        _NOT_EXERCISED | {"language_script_groups_complete", "language_script_groups_missing"}
    ),
    "detector_statistics": frozenset(
        _NOT_EXERCISED
        | {
            "detector_results_not_assessed",
            "fixed_fpr_serialization_exercised",
            "fixed_fpr_stable_independent_complete",
            "fixed_fpr_unstable_independence_or_rows_incomplete",
        }
    ),
    "negative_effects": frozenset(
        _NOT_EXERCISED
        | {
            "cross_detector_negative_effects_complete",
            "cross_detector_negative_effects_incomplete",
            "transformed_control_scores_not_assessed",
        }
    ),
    "quality_preservation": frozenset(
        _NOT_EXERCISED
        | {
            "quality_and_task_outcomes_complete",
            "quality_gate_outcomes_not_assessed",
            "quality_or_task_outcomes_missing",
        }
    ),
    "human_evaluation": frozenset(
        _NOT_EXERCISED
        | {
            "blinded_human_review_not_assessed",
            "blinded_review_metadata_complete",
        }
    ),
    "resource_accounting": frozenset(
        _NOT_EXERCISED
        | {
            "execution_telemetry_not_assessed",
            "model_resource_telemetry_complete",
            "model_size_or_peak_memory_unavailable",
            "offline_zero_cost_declarations_exercised",
        }
    ),
    "artifact_handling": frozenset(
        _NOT_EXERCISED
        | {
            "aggregate_content_addressed_bundle_binding_pending",
            "evidence_bundle_not_assessed",
            "evidence_bundle_validation_exercised",
            "source_artifacts_bound_by_digest",
        }
    ),
    "independent_replication": frozenset(_NOT_EXERCISED | {"independent_replication_not_attached"}),
}

COVERAGE_COMPLETE_REASON_CODES_BY_AREA: dict[str, frozenset[str]] = {
    "reproducible_identity": frozenset(
        {"registry_inputs_and_freeze_content_addressed", "synthetic_fixture_content_addressed"}
    ),
    "independent_splits": frozenset(
        {
            "splits_populated_and_clusters_disjoint",
            "synthetic_calibration_and_test_arrays_distinct",
        }
    ),
    "matched_controls": frozenset({"matched_controls_complete"}),
    "held_out_keys": frozenset(
        {
            "key_partitions_frozen_before_final_test",
            "tuning_and_final_key_partitions_disjoint",
        }
    ),
    "length_coverage": frozenset({"detector_token_bins_complete"}),
    "task_coverage": frozenset({"task_checker_matrix_complete"}),
    "language_coverage": frozenset({"language_script_groups_complete"}),
    "detector_statistics": frozenset(
        {"fixed_fpr_serialization_exercised", "fixed_fpr_stable_independent_complete"}
    ),
    "negative_effects": frozenset({"cross_detector_negative_effects_complete"}),
    "quality_preservation": frozenset({"quality_and_task_outcomes_complete"}),
    "human_evaluation": frozenset({"blinded_review_metadata_complete"}),
    "resource_accounting": frozenset(
        {"model_resource_telemetry_complete", "offline_zero_cost_declarations_exercised"}
    ),
    "artifact_handling": frozenset(
        {"evidence_bundle_validation_exercised", "source_artifacts_bound_by_digest"}
    ),
    "independent_replication": frozenset(),
}

HUMAN_CONTROL_RISK_CODES = frozenset(
    {
        "high",
        "low",
        "medium",
        "not_assessed",
        "not_assessed_synthetic_fixture",
        "unknown",
    }
)

HUMAN_REVIEW_REASON_CODES = frozenset(
    {
        "blinded_human_review_not_available",
        "blinded_human_review_not_run",
        "synthetic_fixture_not_human_evaluation",
    }
)

DETECTOR_LIMITATION_CODES = frozenset(
    {
        "not_a_watermark_detector",
        "not_official_exp_its_implementation",
        "not_performance_evidence",
    }
)

REPRODUCIBILITY_BLOCKER_CODES = frozenset(
    {
        "adapter_executable_digest_unresolved",
        "adapter_sidecar_digest_unresolved",
        "configuration_sha256_invalid",
        "family_mismatch",
        "golden_conformance_not_passed",
        "golden_report_sha256_invalid",
        "golden_vectors_sha256_invalid",
        "id_unresolved",
        "implementation_unresolved",
        "implementation_version_unresolved",
        "independent_classification_not_requested",
        "minimum_effective_tokens_not_positive",
        "model_download_required_unresolved",
        "model_revision_unresolved",
        "network_required_unresolved",
        "no_static_adapter_sidecar",
        "source_mismatch",
        "tokenizer_revision_unresolved",
    }
)

METRIC_NARRATIVE_CODES: dict[str, frozenset[str]] = {
    "clear_rate_ci95_condition": frozenset(
        {"descriptive_row_wilson_cluster_bootstrap_source_detected_fixed_thresholds"}
    ),
    "denominator_policy": frozenset({"all_attempts_in_primary_denominator"}),
    "false_insertion_rate_ci95_condition": frozenset(
        {"descriptive_row_wilson_cluster_bootstrap_source_unflagged_fixed_thresholds"}
    ),
    "interpretation_scope": frozenset(
        {"named_detector_and_registered_gates_not_authorship_or_universal_removal"}
    ),
    "interval_scope": frozenset(
        {
            "descriptive_row_wilson_cluster_bootstrap_registered_clusters",
            "descriptive_row_wilson_cluster_bootstrap_disjoint_null_thresholds",
        }
    ),
    "method": frozenset({"held_out_empirical_null"}),
    "null_flag_rate_delta_ci95_method": frozenset(
        {
            "paired_cluster_percentile_bootstrap_fixed_thresholds",
            "paired_row_percentile_bootstrap_fixed_thresholds",
        }
    ),
    "positive_flag_rate_delta_ci95_method": frozenset(
        {
            "paired_cluster_percentile_bootstrap_fixed_thresholds",
            "paired_row_percentile_bootstrap_fixed_thresholds",
        }
    ),
    "row_level_interval_scope": frozenset(
        {"descriptive_row_binomial_not_cluster_independent_inference"}
    ),
    "score_population_denominator": frozenset({"all_supplied_score_rows"}),
}

RESULT_REASON_CODES = frozenset(
    {
        "calibration_null_not_estimable",
        "held_out_test_null_clusters_not_estimable",
        "held_out_test_null_not_estimable",
        "positive_population_empty",
        "threshold_not_estimable",
    }
)


def is_code_or_commitment(value: Any, allowed: AbstractSet[str]) -> bool:
    """Return whether ``value`` is a registered code or SHA-256 commitment."""
    return type(value) is str and (
        value in allowed or SHA256_COMMITMENT.fullmatch(value) is not None
    )


def is_public_token(value: Any) -> bool:
    """Return whether ``value`` is a bounded, whitespace-free public identifier."""
    return type(value) is str and PUBLIC_TOKEN.fullmatch(value) is not None

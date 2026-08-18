"""Detection and quality metrics for the removal harness.

Detection uses TPR at a fixed FPR calibrated on matched unwatermarked controls,
plus AUROC. Low FPRs are returned as not estimable unless enough null samples
exist. Quality includes perplexity, MiniLM cosine, BERTScore, MAUVE, and
deterministic preservation gates; none is mislabeled as P-SP.
"""

from __future__ import annotations

import bisect
import math
import random
from dataclasses import dataclass
from typing import Hashable, Sequence

from dewatermark.quality import evaluate_quality


# ------------------------------------------------------------------ detection
def _require_finite_scores(label: str, *populations: Sequence[float]) -> None:
    for population in populations:
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            for value in population
        ):
            raise ValueError(f"{label} scores must be finite numbers")


def auroc(pos: list[float], neg: list[float]) -> float:
    """Probability a positive score outranks a matched null (Mann-Whitney)."""
    _require_finite_scores("AUROC", pos, neg)
    if not pos or not neg:
        return float("nan")
    ordered = sorted(neg)
    wins = ties = 0
    for p in pos:
        left = bisect.bisect_left(ordered, p)
        right = bisect.bisect_right(ordered, p)
        wins += left
        ties += right - left
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def bootstrap_auroc_interval(
    pos: list[float],
    neg: list[float],
    *,
    confidence: float = 0.95,
    replicates: int = 500,
    seed: int = 0,
) -> tuple[float, float]:
    """Stratified percentile bootstrap interval with a deterministic seed."""
    _require_finite_scores("bootstrap AUROC", pos, neg)
    if not pos or not neg or replicates < 2 or not 0 < confidence < 1:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    values = sorted(
        auroc(
            [pos[rng.randrange(len(pos))] for _ in pos],
            [neg[rng.randrange(len(neg))] for _ in neg],
        )
        for _ in range(replicates)
    )
    alpha = (1 - confidence) / 2
    return _quantile(values, alpha), _quantile(values, 1 - alpha)


def _cluster_indices(size: int, cluster_ids: Sequence[Hashable] | None) -> list[list[int]]:
    if cluster_ids is None:
        return [[index] for index in range(size)]
    if len(cluster_ids) != size:
        raise ValueError("cluster_ids must align with the population")
    grouped: dict[Hashable, list[int]] = {}
    for index, cluster_id in enumerate(cluster_ids):
        grouped.setdefault(cluster_id, []).append(index)
    return list(grouped.values())


def _resample_cluster_indices(rng: random.Random, clusters: list[list[int]]) -> list[int]:
    selected: list[int] = []
    for _ in clusters:
        selected.extend(clusters[rng.randrange(len(clusters))])
    return selected


def cluster_bootstrap_auroc_interval(
    pos: list[float],
    neg: list[float],
    *,
    positive_cluster_ids: Sequence[Hashable] | None = None,
    negative_cluster_ids: Sequence[Hashable] | None = None,
    confidence: float = 0.95,
    replicates: int = 500,
    seed: int = 0,
) -> tuple[float, float]:
    """AUROC interval that resamples prompt/document clusters as whole units."""
    _require_finite_scores("cluster AUROC", pos, neg)
    positive_clusters = _cluster_indices(len(pos), positive_cluster_ids)
    negative_clusters = _cluster_indices(len(neg), negative_cluster_ids)
    if not pos or not neg or replicates < 2 or not 0 < confidence < 1:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    values = []
    for _ in range(replicates):
        positive_indices = _resample_cluster_indices(rng, positive_clusters)
        negative_indices = _resample_cluster_indices(rng, negative_clusters)
        values.append(
            auroc(
                [pos[index] for index in positive_indices],
                [neg[index] for index in negative_indices],
            )
        )
    values.sort()
    alpha = (1 - confidence) / 2
    return _quantile(values, alpha), _quantile(values, 1 - alpha)


def paired_cluster_bootstrap_auroc_delta_interval(
    positive_before: list[float],
    positive_after: list[float],
    null_before: list[float],
    null_after: list[float],
    *,
    positive_cluster_ids: Sequence[Hashable] | None = None,
    null_cluster_ids: Sequence[Hashable] | None = None,
    confidence: float = 0.95,
    replicates: int = 500,
    seed: int = 0,
) -> tuple[float, float]:
    """Paired candidate-minus-source AUROC interval with cluster resampling."""
    if len(positive_before) != len(positive_after) or len(null_before) != len(null_after):
        raise ValueError("source and candidate AUROC populations must be paired")
    _require_finite_scores(
        "paired cluster AUROC", positive_before, positive_after, null_before, null_after
    )
    positive_clusters = _cluster_indices(len(positive_before), positive_cluster_ids)
    null_clusters = _cluster_indices(len(null_before), null_cluster_ids)
    if not positive_before or not null_before or replicates < 2 or not 0 < confidence < 1:
        return float("nan"), float("nan")
    joint_cluster_maps = None
    if (
        positive_cluster_ids is not None
        and null_cluster_ids is not None
        and set(positive_cluster_ids) == set(null_cluster_ids)
    ):
        cluster_order = list(dict.fromkeys(positive_cluster_ids))
        joint_cluster_maps = (
            cluster_order,
            {
                cluster_id: [
                    index for index, value in enumerate(positive_cluster_ids) if value == cluster_id
                ]
                for cluster_id in cluster_order
            },
            {
                cluster_id: [
                    index for index, value in enumerate(null_cluster_ids) if value == cluster_id
                ]
                for cluster_id in cluster_order
            },
        )
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(replicates):
        if joint_cluster_maps is not None:
            cluster_order, positive_by_cluster, null_by_cluster = joint_cluster_maps
            selected = [cluster_order[rng.randrange(len(cluster_order))] for _ in cluster_order]
            positive_indices = [
                index for cluster_id in selected for index in positive_by_cluster[cluster_id]
            ]
            null_indices = [
                index for cluster_id in selected for index in null_by_cluster[cluster_id]
            ]
        else:
            positive_indices = _resample_cluster_indices(rng, positive_clusters)
            null_indices = _resample_cluster_indices(rng, null_clusters)
        before = auroc(
            [positive_before[index] for index in positive_indices],
            [null_before[index] for index in null_indices],
        )
        after = auroc(
            [positive_after[index] for index in positive_indices],
            [null_after[index] for index in null_indices],
        )
        values.append(after - before)
    values.sort()
    alpha = (1 - confidence) / 2
    return _quantile(values, alpha), _quantile(values, 1 - alpha)


def paired_bootstrap_delta_interval(
    source: list[float],
    candidate: list[float],
    *,
    cluster_ids: list[Hashable] | None = None,
    confidence: float = 0.95,
    replicates: int = 500,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile interval for a paired candidate-minus-source mean delta.

    Pairs are resampled together. When ``cluster_ids`` is provided, whole
    clusters are resampled so repeated observations from one prompt/document
    are not treated as independent. This interval conditions on any fixed
    thresholds used to create the supplied outcomes; it does not propagate
    threshold-calibration uncertainty.
    """
    if len(source) != len(candidate):
        raise ValueError("source and candidate populations must be paired")
    _require_finite_scores("paired bootstrap", source, candidate)
    if cluster_ids is not None and len(cluster_ids) != len(source):
        raise ValueError("cluster_ids must align with paired populations")
    if not source or replicates < 2 or not 0 < confidence < 1:
        return float("nan"), float("nan")

    deltas = [after - before for before, after in zip(source, candidate)]
    if cluster_ids is None:
        clusters = [[index] for index in range(len(deltas))]
    else:
        grouped: dict[Hashable, list[int]] = {}
        for index, cluster_id in enumerate(cluster_ids):
            grouped.setdefault(cluster_id, []).append(index)
        clusters = list(grouped.values())

    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(replicates):
        sampled_indices: list[int] = []
        for _ in clusters:
            sampled_indices.extend(clusters[rng.randrange(len(clusters))])
        values.append(sum(deltas[index] for index in sampled_indices) / len(sampled_indices))
    values.sort()
    alpha = (1 - confidence) / 2
    return _quantile(values, alpha), _quantile(values, 1 - alpha)


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    idx = min(len(sorted_vals) - 1, max(0, int(math.ceil(q * len(sorted_vals))) - 1))
    return sorted_vals[idx]


def cluster_bootstrap_rate_interval(
    outcomes: Sequence[bool],
    *,
    cluster_ids: Sequence[Hashable] | None,
    confidence: float = 0.95,
    replicates: int = 500,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile rate interval resampling whole prompt/document clusters."""
    if any(not isinstance(value, bool) for value in outcomes):
        raise ValueError("rate outcomes must be booleans")
    clusters = _cluster_indices(len(outcomes), cluster_ids)
    if not outcomes or replicates < 2 or not 0 < confidence < 1:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    numeric = [float(value) for value in outcomes]
    values: list[float] = []
    for _ in range(replicates):
        indices = _resample_cluster_indices(rng, clusters)
        values.append(sum(numeric[index] for index in indices) / len(indices))
    values.sort()
    alpha = (1 - confidence) / 2
    return _quantile(values, alpha), _quantile(values, 1 - alpha)


def minimum_nulls(fpr: float) -> int:
    """Smallest null set that can resolve one false positive at ``fpr``."""
    if not 0 < fpr < 1:
        raise ValueError("fpr must be between 0 and 1")
    return math.ceil(1.0 / fpr)


def recommended_nulls(fpr: float, expected_false_positives: int = 20) -> int:
    """Null count recommended for a less fragile empirical tail estimate."""
    if expected_false_positives < 1:
        raise ValueError("expected_false_positives must be positive")
    return expected_false_positives * minimum_nulls(fpr)


def threshold_at_fpr(neg: list[float], fpr: float) -> float:
    _require_finite_scores("threshold calibration", neg)
    if len(neg) < minimum_nulls(fpr):
        return float("nan")
    # Strictly greater than this order statistic yields at most the requested
    # empirical FPR. Scores equal to the threshold are not flagged.
    return _quantile(sorted(neg), 1.0 - fpr)


def tpr_at_fpr(pos: list[float], neg: list[float], fpr: float) -> float:
    """Empirical TPR at a threshold giving `fpr` false positives on `neg`."""
    _require_finite_scores("fixed-FPR", pos, neg)
    if not pos or not neg:
        return float("nan")
    tau = threshold_at_fpr(neg, fpr)
    if math.isnan(tau):
        return float("nan")
    return sum(1 for p in pos if p > tau) / len(pos)


def calibration_report(
    neg: list[float],
    fpr: float,
    *,
    cluster_ids: Sequence[Hashable] | None = None,
) -> dict:
    """Auditable empirical detector threshold and its sampling uncertainty."""
    clusters = _cluster_indices(len(neg), cluster_ids)
    cluster_count = len(clusters)
    tau = threshold_at_fpr(neg, fpr)
    if math.isnan(tau) or cluster_count < minimum_nulls(fpr):
        return {
            "method": "held_out_empirical_null",
            "requested_fpr": fpr,
            "null_samples": len(neg),
            "null_clusters": cluster_count,
            "minimum_null_samples": minimum_nulls(fpr),
            "minimum_null_clusters": minimum_nulls(fpr),
            "recommended_null_samples": recommended_nulls(fpr),
            "recommended_null_clusters": recommended_nulls(fpr),
            "adequate_for_stable_estimate": False,
            "estimable": False,
            "threshold": None,
            "threshold_operator": ">",
            "resampling_unit": "prompt_or_document_cluster"
            if cluster_ids is not None
            else "row_no_cluster_ids_supplied",
        }
    false_positives = sum(value > tau for value in neg)
    return {
        "method": "held_out_empirical_null",
        "requested_fpr": fpr,
        "null_samples": len(neg),
        "null_clusters": cluster_count,
        "minimum_null_samples": minimum_nulls(fpr),
        "minimum_null_clusters": minimum_nulls(fpr),
        "recommended_null_samples": recommended_nulls(fpr),
        "recommended_null_clusters": recommended_nulls(fpr),
        "adequate_for_stable_estimate": len(neg) >= recommended_nulls(fpr)
        and cluster_count >= recommended_nulls(fpr),
        "estimable": True,
        "threshold": tau,
        "threshold_operator": ">",
        "false_positives": false_positives,
        "empirical_fpr": false_positives / len(neg),
        "empirical_fpr_row_level_wilson_ci95": wilson_interval(false_positives, len(neg)),
        "row_level_interval_scope": "descriptive_row_binomial_not_cluster_independent_inference",
        "resampling_unit": "prompt_or_document_cluster"
        if cluster_ids is not None
        else "row_no_cluster_ids_supplied",
    }


def fixed_fpr_paired_report(
    positive_before: list[float],
    positive_after: list[float],
    test_null_before: list[float],
    test_null_after: list[float],
    calibration_null_before: list[float],
    calibration_null_after: list[float],
    *,
    fpr: float,
    positive_cluster_ids: list[Hashable] | None = None,
    null_cluster_ids: list[Hashable] | None = None,
    calibration_cluster_ids: list[Hashable] | None = None,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
) -> dict:
    """Complete fixed-FPR report using disjoint threshold and test nulls.

    Wilson intervals quantify each observed binomial rate. Paired cluster
    intervals quantify pre/post deltas while holding the independently
    calibrated thresholds fixed. This avoids silently reusing the test null for
    threshold selection and labels the remaining conditioning explicitly.
    """
    if len(positive_before) != len(positive_after):
        raise ValueError("positive source/candidate populations must be paired")
    if len(test_null_before) != len(test_null_after):
        raise ValueError("test-null source/candidate populations must be paired")
    _require_finite_scores(
        "fixed-FPR",
        positive_before,
        positive_after,
        test_null_before,
        test_null_after,
        calibration_null_before,
        calibration_null_after,
    )
    source_calibration = calibration_report(
        calibration_null_before, fpr, cluster_ids=calibration_cluster_ids
    )
    candidate_calibration = calibration_report(
        calibration_null_after, fpr, cluster_ids=calibration_cluster_ids
    )
    source_threshold = source_calibration.get("threshold")
    candidate_threshold = candidate_calibration.get("threshold")
    minimum_test_nulls = minimum_nulls(fpr)
    recommended_test_nulls = recommended_nulls(fpr)
    test_null_clusters = len(_cluster_indices(len(test_null_before), null_cluster_ids))
    reason_codes = []
    if source_threshold is None or candidate_threshold is None:
        reason_codes.append("calibration_null_not_estimable")
    if len(test_null_before) < minimum_test_nulls:
        reason_codes.append("held_out_test_null_not_estimable")
    if test_null_clusters < minimum_test_nulls:
        reason_codes.append("held_out_test_null_clusters_not_estimable")
    if not positive_before:
        reason_codes.append("positive_population_empty")
    if reason_codes:
        return {
            "estimable": False,
            "requested_fpr": fpr,
            "source_calibration": source_calibration,
            "candidate_calibration": candidate_calibration,
            "positive_samples": len(positive_before),
            "test_null_samples": len(test_null_before),
            "test_null_clusters": test_null_clusters,
            "minimum_test_null_samples": minimum_test_nulls,
            "minimum_test_null_clusters": minimum_test_nulls,
            "recommended_test_null_samples": recommended_test_nulls,
            "recommended_test_null_clusters": recommended_test_nulls,
            "adequate_for_stable_estimate": False,
            "reason_codes": reason_codes,
            "score_population_denominator": "all_supplied_score_rows",
        }
    paired = paired_detection_outcomes(
        positive_before,
        positive_after,
        test_null_before,
        test_null_after,
        source_threshold=source_threshold,
        candidate_threshold=candidate_threshold,
        positive_cluster_ids=positive_cluster_ids,
        null_cluster_ids=null_cluster_ids,
        bootstrap_replicates=bootstrap_replicates,
        bootstrap_seed=bootstrap_seed,
    )
    positive_before_hits = sum(value > source_threshold for value in positive_before)
    positive_after_hits = sum(value > candidate_threshold for value in positive_after)
    null_before_hits = sum(value > source_threshold for value in test_null_before)
    null_after_hits = sum(value > candidate_threshold for value in test_null_after)
    positive_before_flags = [value > source_threshold for value in positive_before]
    positive_after_flags = [value > candidate_threshold for value in positive_after]
    null_before_flags = [value > source_threshold for value in test_null_before]
    null_after_flags = [value > candidate_threshold for value in test_null_after]
    return {
        "estimable": True,
        "requested_fpr": fpr,
        "threshold_operator": ">",
        "source_calibration": source_calibration,
        "candidate_calibration": candidate_calibration,
        "positive_samples": len(positive_before),
        "test_null_samples": len(test_null_before),
        "test_null_clusters": test_null_clusters,
        "minimum_test_null_samples": minimum_test_nulls,
        "minimum_test_null_clusters": minimum_test_nulls,
        "recommended_test_null_samples": recommended_test_nulls,
        "recommended_test_null_clusters": recommended_test_nulls,
        "adequate_for_stable_estimate": (
            source_calibration["adequate_for_stable_estimate"]
            and candidate_calibration["adequate_for_stable_estimate"]
            and len(test_null_before) >= recommended_test_nulls
            and test_null_clusters >= recommended_test_nulls
        ),
        "tpr_before": positive_before_hits / len(positive_before)
        if positive_before
        else float("nan"),
        "tpr_before_row_level_wilson_ci95": wilson_interval(
            positive_before_hits, len(positive_before)
        ),
        "tpr_before_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            positive_before_flags,
            cluster_ids=positive_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 10,
        ),
        "tpr_after": positive_after_hits / len(positive_after) if positive_after else float("nan"),
        "tpr_after_row_level_wilson_ci95": wilson_interval(
            positive_after_hits, len(positive_after)
        ),
        "tpr_after_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            positive_after_flags,
            cluster_ids=positive_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 11,
        ),
        "test_fpr_before": null_before_hits / len(test_null_before)
        if test_null_before
        else float("nan"),
        "test_fpr_before_row_level_wilson_ci95": wilson_interval(
            null_before_hits, len(test_null_before)
        ),
        "test_fpr_before_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            null_before_flags,
            cluster_ids=null_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 12,
        ),
        "test_fpr_after": null_after_hits / len(test_null_after)
        if test_null_after
        else float("nan"),
        "test_fpr_after_row_level_wilson_ci95": wilson_interval(
            null_after_hits, len(test_null_after)
        ),
        "test_fpr_after_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            null_after_flags,
            cluster_ids=null_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 13,
        ),
        "paired_outcomes": paired,
        "interval_scope": "descriptive_row_wilson_cluster_bootstrap_disjoint_null_thresholds",
        "cluster_resampling_unit": "prompt_or_document_cluster"
        if positive_cluster_ids is not None and null_cluster_ids is not None
        else "row_no_cluster_ids_supplied",
        "score_population_denominator": "all_supplied_score_rows",
    }


def attempt_outcome_report(
    states: Sequence[str],
    successes: Sequence[bool],
    *,
    cluster_ids: Sequence[Hashable] | None = None,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
) -> dict:
    """Report verified success with every failure and abstention retained."""
    if len(states) != len(successes):
        raise ValueError("states and successes must align")
    allowed = {"accepted", "failed", "abstained"}
    if any(state not in allowed for state in states):
        raise ValueError("unknown attempt state")
    if any(success and state != "accepted" for state, success in zip(states, successes)):
        raise ValueError("only accepted attempts can be successful")
    _cluster_indices(len(states), cluster_ids)
    attempted = len(states)
    success_count = sum(successes)
    accepted = sum(state == "accepted" for state in states)
    failed = sum(state == "failed" for state in states)
    abstained = sum(state == "abstained" for state in states)
    accepted_successes = [
        success for state, success in zip(states, successes) if state == "accepted"
    ]
    accepted_clusters = (
        [cluster_id for state, cluster_id in zip(states, cluster_ids) if state == "accepted"]
        if cluster_ids is not None
        else None
    )
    return {
        "attempted_denominator": attempted,
        "accepted": accepted,
        "failed": failed,
        "abstained": abstained,
        "detector_scoped_gate_successes": success_count,
        "detector_scoped_gate_success_rate_over_all_attempts": success_count / attempted
        if attempted
        else float("nan"),
        "detector_scoped_gate_success_rate_over_all_attempts_row_level_wilson_ci95": wilson_interval(
            success_count, attempted
        ),
        "detector_scoped_gate_success_rate_over_all_attempts_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            successes,
            cluster_ids=cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed,
        ),
        "detector_scoped_gate_success_rate_over_accepted": success_count / accepted
        if accepted
        else float("nan"),
        "detector_scoped_gate_success_rate_over_accepted_row_level_wilson_ci95": wilson_interval(
            success_count, accepted
        ),
        "detector_scoped_gate_success_rate_over_accepted_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            accepted_successes,
            cluster_ids=accepted_clusters,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 1,
        ),
        "denominator_policy": "all_attempts_in_primary_denominator",
        "interpretation_scope": (
            "named_detector_and_registered_gates_not_authorship_or_universal_removal"
        ),
        "interval_scope": "descriptive_row_wilson_cluster_bootstrap_registered_clusters",
    }


def paired_detection_outcomes(
    positive_before: list[float],
    positive_after: list[float],
    null_before: list[float],
    null_after: list[float],
    *,
    source_threshold: float | None = None,
    candidate_threshold: float | None = None,
    threshold: float | None = None,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
    positive_cluster_ids: list[Hashable] | None = None,
    null_cluster_ids: list[Hashable] | None = None,
) -> dict:
    """Count removals, residual detections, and watermark false insertions.

    ``cleared`` is conditional on the detector flagging the original positive
    under ``source_threshold``. ``false_inserted`` is a matched null crossing
    from source-unflagged to candidate-flagged. Candidate outcomes always use
    ``candidate_threshold``; this matters when rewriting shifts the null score
    distribution. The terms describe one named detector—not provenance.
    Optional cluster IDs make the pre/post rate-delta intervals resample whole
    prompt/document clusters.

    ``threshold`` is a compatibility alias that assigns both thresholds. New
    callers should pass both domain-specific thresholds explicitly.
    """
    if threshold is not None:
        if source_threshold is not None or candidate_threshold is not None:
            raise ValueError("threshold cannot be combined with domain-specific thresholds")
        source_threshold = candidate_threshold = threshold
    if source_threshold is None or candidate_threshold is None:
        raise ValueError("source_threshold and candidate_threshold are required")
    if len(positive_before) != len(positive_after):
        raise ValueError("positive before/after populations must be paired")
    if len(null_before) != len(null_after):
        raise ValueError("null before/after populations must be paired")
    _require_finite_scores(
        "paired detection", positive_before, positive_after, null_before, null_after
    )
    if any(not math.isfinite(value) for value in (source_threshold, candidate_threshold)):
        return {"estimable": False, "reason_codes": ["threshold_not_estimable"]}
    detected_before = [before > source_threshold for before in positive_before]
    detected_after = [after > candidate_threshold for after in positive_after]
    initially_detected = sum(detected_before)
    residual = sum(before and after for before, after in zip(detected_before, detected_after))
    cleared = sum(before and not after for before, after in zip(detected_before, detected_after))
    null_flagged_before = [value > source_threshold for value in null_before]
    null_flagged_after = [value > candidate_threshold for value in null_after]
    false_inserted = sum(
        not before and after for before, after in zip(null_flagged_before, null_flagged_after)
    )
    clear_rate = cleared / initially_detected if initially_detected else float("nan")
    insertion_denominator = sum(not value for value in null_flagged_before)
    insertion_rate = (
        false_inserted / insertion_denominator if insertion_denominator else float("nan")
    )
    clear_flags = [
        after is False for before, after in zip(detected_before, detected_after) if before
    ]
    clear_clusters = (
        [cluster_id for cluster_id, before in zip(positive_cluster_ids, detected_before) if before]
        if positive_cluster_ids is not None
        else None
    )
    insertion_flags = [
        after for before, after in zip(null_flagged_before, null_flagged_after) if not before
    ]
    insertion_clusters = (
        [
            cluster_id
            for cluster_id, before in zip(null_cluster_ids, null_flagged_before)
            if not before
        ]
        if null_cluster_ids is not None
        else None
    )
    positive_before_numeric = [float(value) for value in detected_before]
    positive_after_numeric = [float(value) for value in detected_after]
    null_before_numeric = [float(value) for value in null_flagged_before]
    null_after_numeric = [float(value) for value in null_flagged_after]
    positive_rate_before = (
        sum(positive_before_numeric) / len(positive_before_numeric)
        if positive_before_numeric
        else float("nan")
    )
    positive_rate_after = (
        sum(positive_after_numeric) / len(positive_after_numeric)
        if positive_after_numeric
        else float("nan")
    )
    null_rate_before = (
        sum(null_before_numeric) / len(null_before_numeric) if null_before_numeric else float("nan")
    )
    null_rate_after = (
        sum(null_after_numeric) / len(null_after_numeric) if null_after_numeric else float("nan")
    )
    return {
        "estimable": True,
        # Compatibility field: the old single-threshold consumer most closely
        # corresponds to candidate classification. New consumers use both.
        "threshold": candidate_threshold,
        "source_threshold": source_threshold,
        "candidate_threshold": candidate_threshold,
        "threshold_operator": ">",
        "positive_samples": len(positive_before),
        "positive_flag_rate_before": positive_rate_before,
        "positive_flag_rate_after": positive_rate_after,
        "positive_flag_rate_delta": positive_rate_after - positive_rate_before,
        "positive_flag_rate_delta_ci95": paired_bootstrap_delta_interval(
            positive_before_numeric,
            positive_after_numeric,
            cluster_ids=positive_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed,
        ),
        "positive_flag_rate_delta_ci95_method": (
            "paired_cluster_percentile_bootstrap_fixed_thresholds"
            if positive_cluster_ids is not None
            else "paired_row_percentile_bootstrap_fixed_thresholds"
        ),
        "initially_detected": initially_detected,
        "cleared": cleared,
        "residual": residual,
        "clear_rate": clear_rate,
        "clear_rate_row_level_wilson_ci95": wilson_interval(cleared, initially_detected),
        "clear_rate_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            clear_flags,
            cluster_ids=clear_clusters,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 2,
        ),
        "clear_rate_conditional_on_source_detection": clear_rate,
        "clear_rate_conditional_row_level_wilson_ci95": wilson_interval(
            cleared, initially_detected
        ),
        "clear_rate_ci95_condition": (
            "descriptive_row_wilson_cluster_bootstrap_source_detected_fixed_thresholds"
        ),
        "null_samples": len(null_before),
        "null_flag_rate_before": null_rate_before,
        "null_flag_rate_after": null_rate_after,
        "null_flag_rate_delta": null_rate_after - null_rate_before,
        "null_flag_rate_delta_ci95": paired_bootstrap_delta_interval(
            null_before_numeric,
            null_after_numeric,
            cluster_ids=null_cluster_ids,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 1,
        ),
        "null_flag_rate_delta_ci95_method": (
            "paired_cluster_percentile_bootstrap_fixed_thresholds"
            if null_cluster_ids is not None
            else "paired_row_percentile_bootstrap_fixed_thresholds"
        ),
        "false_inserted": false_inserted,
        "false_insertion_denominator": insertion_denominator,
        "false_insertion_rate": insertion_rate,
        "false_insertion_rate_row_level_wilson_ci95": wilson_interval(
            false_inserted, insertion_denominator
        ),
        "false_insertion_rate_cluster_bootstrap_ci95": cluster_bootstrap_rate_interval(
            insertion_flags,
            cluster_ids=insertion_clusters,
            replicates=bootstrap_replicates,
            seed=bootstrap_seed + 3,
        ),
        "false_insertion_rate_conditional_on_source_unflagged": insertion_rate,
        "false_insertion_rate_conditional_row_level_wilson_ci95": wilson_interval(
            false_inserted, insertion_denominator
        ),
        "false_insertion_rate_ci95_condition": (
            "descriptive_row_wilson_cluster_bootstrap_source_unflagged_fixed_thresholds"
        ),
        "cluster_resampling_unit": "prompt_or_document_cluster"
        if positive_cluster_ids is not None and null_cluster_ids is not None
        else "row_no_cluster_ids_supplied",
    }


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if (
        not isinstance(successes, int)
        or isinstance(successes, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or successes < 0
        or successes > total
        or not math.isfinite(z)
        or z <= 0
    ):
        raise ValueError("Wilson interval inputs are invalid")
    if total <= 0:
        return float("nan"), float("nan")
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - half), min(1.0, center + half)


# -------------------------------------------------------------------- quality
@dataclass(frozen=True)
class MetricPolicy:
    """Explicit permission boundary for learned evaluation metrics."""

    allow_network: bool = False
    allow_model_download: bool = False

    @property
    def remote_download_allowed(self) -> bool:
        return self.allow_network and self.allow_model_download


def perplexity(text: str, tok, model) -> float:
    """Perplexity of `text` under the reference LM (lower = more fluent)."""
    import torch

    ids = tok(text, return_tensors="pt", add_special_tokens=False).input_ids
    if ids.shape[-1] < 2:
        return float("nan")
    with torch.no_grad():
        out = model(ids, labels=ids)
    return float(torch.exp(out.loss).item())


class SemanticScorer:
    """MiniLM cosine similarity with a lexical fallback."""

    def __init__(
        self,
        *,
        allow_network: bool = False,
        allow_model_download: bool = False,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        self._model = None
        self._ok = None
        self._policy = MetricPolicy(allow_network, allow_model_download)
        self._model_name = model_name
        self.backend = "uninitialized"

    def _load(self):
        if self._ok is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer

            # ``local_files_only`` is the enforceable no-network boundary.  A
            # cache miss degrades to the deterministic lexical metric.
            self._model = SentenceTransformer(
                self._model_name,
                local_files_only=not self._policy.remote_download_allowed,
            )
            self._ok = True
            self.backend = f"minilm:{self._model_name}"
        except Exception:
            self._ok = False
            self.backend = "lexical-bow-cosine"

    def similarity(self, a: str, b: str) -> float:
        self._load()
        if not self._ok:
            return _bow_cosine(a, b)  # fallback: lexical cosine
        emb = self._model.encode([a, b], normalize_embeddings=True)
        return float(sum(float(left) * float(right) for left, right in zip(emb[0], emb[1])))


class BERTScoreScorer:
    """BERTScore-F1 with a NaN fallback when the optional package is absent."""

    def __init__(
        self,
        *,
        allow_network: bool = False,
        allow_model_download: bool = False,
    ):
        self._scorer = None
        self.backend = "unavailable"
        # bert-score does not consistently expose transformers'
        # ``local_files_only`` flag.  Refuse to construct it unless both
        # permissions were explicitly granted.
        if not MetricPolicy(allow_network, allow_model_download).remote_download_allowed:
            return
        try:
            from bert_score import BERTScorer

            self._scorer = BERTScorer(lang="en")
            self.backend = "bert-score:default-en"
        except Exception:
            pass

    def similarity(self, a: str, b: str) -> float:
        if self._scorer is None:
            return float("nan")
        _, _, f1 = self._scorer.score([b], [a])
        return float(f1[0])


def corpus_mauve(
    sources: list[str],
    candidates: list[str],
    *,
    allow_network: bool = False,
    allow_model_download: bool = False,
) -> float:
    """Distributional MAUVE; requires multiple texts and optional mauve-text."""
    if len(sources) < 2 or len(candidates) < 2:
        return float("nan")
    # MAUVE loads a featurization model internally and offers no reliable
    # local-files-only control across supported versions.
    if not MetricPolicy(allow_network, allow_model_download).remote_download_allowed:
        return float("nan")
    try:
        import mauve

        result = mauve.compute_mauve(
            p_text=sources, q_text=candidates, device_id=-1, max_text_length=512, verbose=False
        )
        return float(result.mauve)
    except Exception:
        return float("nan")


def deterministic_quality_pass(source: str, candidate: str) -> bool:
    return evaluate_quality(source, candidate).passed


def _bow_cosine(a: str, b: str) -> float:
    from collections import Counter

    ca, cb = Counter(a.lower().split()), Counter(b.lower().split())
    keys = set(ca) | set(cb)
    dot = sum(ca[k] * cb[k] for k in keys)
    na = math.sqrt(sum(v * v for v in ca.values()))
    nb = math.sqrt(sum(v * v for v in cb.values()))
    return dot / (na * nb) if na and nb else 0.0

"""Equal-initial-strength calibration helpers (WaterBench-style)."""

from __future__ import annotations

try:
    from . import metrics
except ImportError:  # direct-script compatibility
    import metrics  # type: ignore


def select_strength(
    strength_to_scores: dict[float, list[float]],
    null_scores: list[float],
    *,
    target_tpr: float = 0.95,
    fpr: float = 0.01,
) -> dict:
    """Choose the weakest strength meeting ``target_tpr`` at fixed FPR.

    The returned threshold is calibrated only on the supplied null split.  The
    caller must evaluate final outcomes on a disjoint test split to avoid
    optimistic estimates.
    """
    calibration = metrics.calibration_report(null_scores, fpr)
    rows = []
    chosen = None
    for strength in sorted(strength_to_scores):
        tpr = metrics.tpr_at_fpr(strength_to_scores[strength], null_scores, fpr)
        successes = (
            sum(score > calibration["threshold"] for score in strength_to_scores[strength])
            if calibration.get("estimable")
            else 0
        )
        rows.append(
            {
                "strength": strength,
                "tpr": tpr,
                "tpr_ci95": metrics.wilson_interval(successes, len(strength_to_scores[strength])),
                "positive_samples": len(strength_to_scores[strength]),
            }
        )
        if tpr == tpr and tpr >= target_tpr and chosen is None:
            chosen = strength
    return {
        "schema_version": "1.0",
        "chosen": chosen,
        "target_tpr": target_tpr,
        "fpr": fpr,
        "null_calibration": calibration,
        "selection_rule": "weakest strength meeting target TPR",
        "requires_disjoint_test_split": True,
        "candidates": rows,
    }

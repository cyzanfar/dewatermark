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
    """Choose the weakest strength meeting ``target_tpr`` at fixed FPR."""
    rows = []
    chosen = None
    for strength in sorted(strength_to_scores):
        tpr = metrics.tpr_at_fpr(strength_to_scores[strength], null_scores, fpr)
        rows.append({"strength": strength, "tpr": tpr})
        if tpr == tpr and tpr >= target_tpr and chosen is None:
            chosen = strength
    return {"chosen": chosen, "target_tpr": target_tpr, "fpr": fpr, "candidates": rows}

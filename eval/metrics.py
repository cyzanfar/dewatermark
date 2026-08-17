"""Detection and quality metrics for the removal harness.

Detection uses TPR at a fixed FPR calibrated on matched unwatermarked controls,
plus AUROC. Low FPRs are returned as not estimable unless enough null samples
exist. Quality includes perplexity, MiniLM cosine, BERTScore, MAUVE, and
deterministic preservation gates; none is mislabeled as P-SP.
"""

from __future__ import annotations

import math
import statistics

from dewatermark.quality import evaluate_quality


# ------------------------------------------------------------------ detection
def auroc(pos: list[float], neg: list[float]) -> float:
    """Probability a positive score outranks a matched null (Mann-Whitney)."""
    if not pos or not neg:
        return float("nan")
    wins = ties = 0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1
            elif p == n:
                ties += 1
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    idx = min(len(sorted_vals) - 1, max(0, int(math.ceil(q * len(sorted_vals))) - 1))
    return sorted_vals[idx]


def minimum_nulls(fpr: float) -> int:
    """Smallest null set that can resolve one false positive at ``fpr``."""
    if not 0 < fpr < 1:
        raise ValueError("fpr must be between 0 and 1")
    return math.ceil(1.0 / fpr)


def threshold_at_fpr(neg: list[float], fpr: float) -> float:
    if len(neg) < minimum_nulls(fpr):
        return float("nan")
    # Strictly greater than this order statistic yields at most the requested
    # empirical FPR (ties are conservatively treated as positives by callers).
    return _quantile(sorted(neg), 1.0 - fpr)


def tpr_at_fpr(pos: list[float], neg: list[float], fpr: float) -> float:
    """Empirical TPR at a threshold giving `fpr` false positives on `neg`."""
    if not pos or not neg:
        return float("nan")
    tau = threshold_at_fpr(neg, fpr)
    if math.isnan(tau):
        return float("nan")
    return sum(1 for p in pos if p > tau) / len(pos)


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if total <= 0:
        return float("nan"), float("nan")
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - half), min(1.0, center + half)


def tpr_at_fpr_parametric(pos: list[float], neg: list[float], fpr: float) -> float:
    """Gaussian-fit TPR@FPR — lets us report very low FPRs (1e-5) that need far
    more null samples than a CPU harness can draw. Clearly an extrapolation."""
    if len(neg) < 2 or not pos:
        return float("nan")
    mu, sd = statistics.mean(neg), statistics.pstdev(neg) or 1e-9
    # inverse normal CDF (Acklam approximation) for the (1-fpr) quantile
    z = _norm_ppf(1.0 - fpr)
    tau = mu + z * sd
    return sum(1 for p in pos if p >= tau) / len(pos)


def _norm_ppf(p: float) -> float:
    """Acklam's inverse normal CDF approximation."""
    a = [
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    ]
    b = [
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    ]
    c = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    ]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e00, 3.754408661907416e00]
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    if p <= phigh:
        q = p - 0.5
        r = q * q
        return (
            (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
            * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
        )
    q = math.sqrt(-2 * math.log(1 - p))
    return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
        (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
    )


# -------------------------------------------------------------------- quality
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

    def __init__(self):
        self._model = None
        self._ok = None

    def _load(self):
        if self._ok is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
            self._ok = True
        except Exception:
            self._ok = False

    def similarity(self, a: str, b: str) -> float:
        self._load()
        if not self._ok:
            return _bow_cosine(a, b)  # fallback: lexical cosine
        emb = self._model.encode([a, b], normalize_embeddings=True)
        return float((emb[0] * emb[1]).sum())


class BERTScoreScorer:
    """BERTScore-F1 with a NaN fallback when the optional package is absent."""

    def __init__(self):
        self._scorer = None
        try:
            from bert_score import BERTScorer

            self._scorer = BERTScorer(lang="en")
        except Exception:
            pass

    def similarity(self, a: str, b: str) -> float:
        if self._scorer is None:
            return float("nan")
        _, _, f1 = self._scorer.score([b], [a])
        return float(f1[0])


def corpus_mauve(sources: list[str], candidates: list[str]) -> float:
    """Distributional MAUVE; requires multiple texts and optional mauve-text."""
    if len(sources) < 2 or len(candidates) < 2:
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

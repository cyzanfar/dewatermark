import math
import sys
from types import SimpleNamespace

import metrics


def test_low_fpr_is_not_reported_without_enough_nulls():
    assert math.isnan(metrics.tpr_at_fpr([10.0], [0.0] * 99, 0.01))
    assert math.isnan(metrics.tpr_at_fpr([10.0], [0.0] * 999, 0.001))


def test_empirical_fpr_with_sufficient_nulls():
    negatives = [float(i) for i in range(100)]
    assert metrics.tpr_at_fpr([100.0, 0.0], negatives, 0.01) == 0.5


def test_wilson_interval_contains_observed_rate():
    low, high = metrics.wilson_interval(50, 100)
    assert low < 0.5 < high


def test_calibration_and_paired_outcomes_are_explicit():
    calibration = metrics.calibration_report([float(i) for i in range(100)], 0.01)
    assert calibration["estimable"] is True
    assert calibration["threshold_operator"] == ">"
    result = metrics.paired_detection_outcomes(
        [101.0, 101.0],
        [0.0, 101.0],
        [0.0, 0.0],
        [101.0, 0.0],
        source_threshold=100.0,
        candidate_threshold=100.0,
    )
    assert result["cleared"] == 1
    assert result["residual"] == 1
    assert result["false_inserted"] == 1
    assert result["clear_rate_ci95"][0] < 0.5 < result["clear_rate_ci95"][1]
    assert result["clear_rate_conditional_on_source_detection"] == 0.5
    assert "conditional on source detection" in result["clear_rate_ci95_condition"]


def test_paired_outcomes_classify_source_and_candidate_domains_separately():
    result = metrics.paired_detection_outcomes(
        [6.0, 9.0],
        [9.0, 11.0],
        [6.0, 4.0],
        [9.0, 11.0],
        source_threshold=5.0,
        candidate_threshold=10.0,
        bootstrap_replicates=20,
    )

    assert result["source_threshold"] == 5.0
    assert result["candidate_threshold"] == 10.0
    assert result["initially_detected"] == 2
    assert result["cleared"] == 1
    assert result["residual"] == 1
    assert result["false_inserted"] == 1
    assert result["false_insertion_denominator"] == 1
    assert result["positive_flag_rate_before"] == 1.0
    assert result["positive_flag_rate_after"] == 0.5


def test_paired_bootstrap_delta_is_seeded_and_cluster_aware():
    kwargs = {
        "cluster_ids": ["prompt-a", "prompt-a", "prompt-b"],
        "seed": 19,
        "replicates": 100,
    }
    first = metrics.paired_bootstrap_delta_interval([0.0, 0.0, 0.0], [1.0, 1.0, -1.0], **kwargs)
    second = metrics.paired_bootstrap_delta_interval([0.0, 0.0, 0.0], [1.0, 1.0, -1.0], **kwargs)
    assert first == second
    assert first == (-1.0, 1.0)


def test_paired_bootstrap_rejects_misaligned_pairs_and_clusters():
    try:
        metrics.paired_bootstrap_delta_interval([0.0], [0.0, 1.0])
    except ValueError as exc:
        assert "paired" in str(exc)
    else:
        raise AssertionError("misaligned pairs must fail")

    try:
        metrics.paired_bootstrap_delta_interval([0.0], [1.0], cluster_ids=[])
    except ValueError as exc:
        assert "cluster_ids" in str(exc)
    else:
        raise AssertionError("misaligned clusters must fail")


def test_gaussian_low_fpr_extrapolation_is_not_exposed():
    assert not hasattr(metrics, "tpr_at_fpr_parametric")


def test_bootstrap_auroc_is_seeded():
    first = metrics.bootstrap_auroc_interval([2.0, 3.0], [0.0, 1.0], seed=7, replicates=20)
    second = metrics.bootstrap_auroc_interval([2.0, 3.0], [0.0, 1.0], seed=7, replicates=20)
    assert first == second


def test_semantic_metric_enforces_local_files_only(monkeypatch):
    calls = []

    class FakeModel:
        def __init__(self, name, **kwargs):
            calls.append((name, kwargs))

        def encode(self, _texts, normalize_embeddings=True):
            assert normalize_embeddings
            return [[1.0, 0.0], [1.0, 0.0]]

    monkeypatch.setitem(
        sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=FakeModel)
    )
    scorer = metrics.SemanticScorer()
    assert scorer.similarity("a", "a") == 1.0
    assert calls[0][1]["local_files_only"] is True


def test_bertscore_requires_both_network_and_download_consent(monkeypatch):
    class Forbidden:
        def __getattr__(self, _name):
            raise AssertionError("bert-score must not be imported")

    monkeypatch.setitem(sys.modules, "bert_score", Forbidden())
    scorer = metrics.BERTScoreScorer(allow_network=False, allow_model_download=True)
    assert math.isnan(scorer.similarity("a", "a"))

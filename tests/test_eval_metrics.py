import math
import sys
from types import SimpleNamespace

import metrics
import pytest


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
    assert calibration["adequate_for_stable_estimate"] is False
    assert calibration["recommended_null_clusters"] == 2000
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
    assert (
        result["clear_rate_row_level_wilson_ci95"][0]
        < 0.5
        < result["clear_rate_row_level_wilson_ci95"][1]
    )
    assert result["clear_rate_conditional_on_source_detection"] == 0.5
    assert (
        result["clear_rate_ci95_condition"]
        == "descriptive_row_wilson_cluster_bootstrap_source_detected_fixed_thresholds"
    )


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


def test_cluster_auroc_and_paired_delta_intervals_are_seeded():
    before_pos = [0.9, 0.8, 0.7, 0.6]
    after_pos = [0.6, 0.5, 0.4, 0.3]
    before_null = [0.1, 0.2, 0.3, 0.4]
    after_null = [0.2, 0.3, 0.4, 0.5]
    clusters = ["a", "a", "b", "b"]
    first = metrics.paired_cluster_bootstrap_auroc_delta_interval(
        before_pos,
        after_pos,
        before_null,
        after_null,
        positive_cluster_ids=clusters,
        null_cluster_ids=clusters,
        replicates=100,
        seed=17,
    )
    second = metrics.paired_cluster_bootstrap_auroc_delta_interval(
        before_pos,
        after_pos,
        before_null,
        after_null,
        positive_cluster_ids=clusters,
        null_cluster_ids=clusters,
        replicates=100,
        seed=17,
    )
    assert first == second
    assert first[1] <= 0


def test_fixed_fpr_report_uses_disjoint_calibration_and_paired_clusters():
    calibration = [float(value) for value in range(100)]
    report = metrics.fixed_fpr_paired_report(
        [101.0, 102.0, 103.0],
        [0.0, 102.0, 0.0],
        [0.0] * 100,
        [101.0] + [0.0] * 99,
        calibration,
        calibration,
        fpr=0.01,
        positive_cluster_ids=["a", "a", "b"],
        null_cluster_ids=[f"null-{index}" for index in range(100)],
        bootstrap_replicates=50,
    )
    assert report["estimable"] is True
    assert report["adequate_for_stable_estimate"] is False
    assert report["recommended_test_null_samples"] == 2000
    assert report["tpr_before"] == 1.0
    assert report["tpr_after"] == 1 / 3
    assert report["paired_outcomes"]["false_inserted"] == 1
    assert (
        report["interval_scope"]
        == "descriptive_row_wilson_cluster_bootstrap_disjoint_null_thresholds"
    )
    assert report["cluster_resampling_unit"] == "prompt_or_document_cluster"
    assert "tpr_after_cluster_bootstrap_ci95" in report
    assert "tpr_after_ci95" not in report


def test_detection_metrics_reject_non_finite_scores_and_thresholds_are_narrow():
    with pytest.raises(ValueError, match="finite"):
        metrics.auroc([float("nan")], [0.0])
    with pytest.raises(ValueError, match="finite"):
        metrics.threshold_at_fpr([float("inf")] * 100, 0.01)
    outcome = metrics.paired_detection_outcomes(
        [1.0],
        [0.0],
        [0.0],
        [0.0],
        source_threshold=float("nan"),
        candidate_threshold=0.5,
    )
    assert outcome == {"estimable": False, "reason_codes": ["threshold_not_estimable"]}


def test_low_fpr_requires_enough_registered_clusters_not_only_rows():
    calibration = [float(value) for value in range(100)]
    report = metrics.fixed_fpr_paired_report(
        [101.0] * 100,
        [0.0] * 100,
        [0.0] * 100,
        [0.0] * 100,
        calibration,
        calibration,
        fpr=0.01,
        positive_cluster_ids=[f"positive-{index}" for index in range(100)],
        null_cluster_ids=["one-repeated-null-cluster"] * 100,
        calibration_cluster_ids=["one-repeated-calibration-cluster"] * 100,
        bootstrap_replicates=10,
    )
    assert report["estimable"] is False
    assert "calibration_null_not_estimable" in report["reason_codes"]
    assert "held_out_test_null_clusters_not_estimable" in report["reason_codes"]


def test_stable_fixed_fpr_label_requires_recommended_samples_and_clusters():
    calibration = [float(value) for value in range(2000)]
    clusters = [f"cluster-{index}" for index in range(2000)]
    report = metrics.fixed_fpr_paired_report(
        [2001.0],
        [0.0],
        [0.0] * 2000,
        [0.0] * 2000,
        calibration,
        calibration,
        fpr=0.01,
        positive_cluster_ids=["positive"],
        null_cluster_ids=clusters,
        calibration_cluster_ids=clusters,
        bootstrap_replicates=2,
    )
    assert report["estimable"] is True
    assert report["adequate_for_stable_estimate"] is True


def test_attempt_report_keeps_failures_and_abstentions_in_primary_denominator():
    report = metrics.attempt_outcome_report(
        ["accepted", "accepted", "failed", "abstained"],
        [True, False, False, False],
    )
    assert report["attempted_denominator"] == 4
    assert report["detector_scoped_gate_success_rate_over_all_attempts"] == 0.25
    assert report["failed"] == 1
    assert report["abstained"] == 1
    with pytest.raises(ValueError, match="only accepted"):
        metrics.attempt_outcome_report(["failed"], [True])


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

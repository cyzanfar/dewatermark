import math

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

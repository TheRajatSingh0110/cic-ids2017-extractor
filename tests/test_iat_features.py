"""OnlineStatistics behaviour - must reproduce Commons Math SummaryStatistics."""

import math

import pytest

from features.iat_features import OnlineStats


def test_empty_stats_are_zero_and_finite():
    s = OnlineStats()
    assert s.n == 0
    assert s.mean() == 0.0
    assert s.std() == 0.0
    assert s.variance() == 0.0
    assert s.min() == 0.0
    assert s.max() == 0.0
    assert s.get_sum() == 0.0
    for v in (s.mean(), s.std(), s.variance(), s.min(), s.max()):
        assert not math.isnan(v)
        assert not math.isinf(v)


def test_single_value_std_is_zero():
    s = OnlineStats()
    s.add(5)
    assert s.n == 1
    assert s.mean() == 5.0
    assert s.std() == 0.0
    assert s.variance() == 0.0
    assert s.min() == 5.0
    assert s.max() == 5.0


def test_sample_variance_matches_reference_formula():
    vals = [1.0, 2.0, 3.0, 4.0, 10.0]
    s = OnlineStats()
    for v in vals:
        s.add(v)
    n = len(vals)
    mean = sum(vals) / n
    s2 = sum((v - mean) ** 2 for v in vals) / (n - 1)
    assert s.mean() == pytest.approx(mean)
    assert s.variance() == pytest.approx(s2)
    assert s.std() == pytest.approx(math.sqrt(s2))
    assert s.min() == min(vals)
    assert s.max() == max(vals)


def test_variance_stable_with_large_values():
    s = OnlineStats()
    base = 1e6
    for v in (base - 2, base - 1, base, base + 1, base + 2):
        s.add(v)
    assert s.variance() == pytest.approx(2.5)
    assert s.std() == pytest.approx(math.sqrt(2.5))
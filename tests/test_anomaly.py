"""Pure-unit tests for the statistical detectors (baseline, spike, change point, flapping)."""

from __future__ import annotations

import random

from mcpsonar import anomaly as ad


def _noisy(center: float, n: int, jitter: float = 0.08, seed: int = 1) -> list[float]:
    rnd = random.Random(seed)
    return [center * (1 + rnd.uniform(-jitter, jitter)) for _ in range(n)]


def test_baseline_needs_enough_samples():
    assert ad.robust_baseline([100.0] * 5) is None
    b = ad.robust_baseline(_noisy(100, 40))
    assert b is not None and 90 < b.median < 110 and b.samples == 40


def test_baseline_is_robust_to_outliers():
    values = _noisy(100, 40) + [5000.0, 7000.0]
    b = ad.robust_baseline(values)
    assert 90 < b.median < 110 and b.spread < 20


def test_spread_is_floored_for_flat_series():
    b = ad.robust_baseline([50.0] * 30)
    assert b.spread == 2.5  # 5% of the median, not ~0


def test_spike_detection():
    b = ad.robust_baseline(_noisy(100, 50))
    assert ad.is_spike(400, b, sensitivity=4)
    assert not ad.is_spike(108, b, sensitivity=4)


def test_spike_requires_practical_relevance():
    # 3 ms -> 12 ms is many sigmas but only +9 ms: not worth an alert
    b = ad.robust_baseline(_noisy(3, 50, jitter=0.02))
    assert not ad.is_spike(12, b, sensitivity=4)


def test_change_point_found_at_the_shift():
    series = _noisy(80, 40, seed=2) + _noisy(240, 15, seed=3)
    cp = ad.find_change_point(series)
    assert cp is not None
    assert abs(cp.index - 40) <= 1
    assert cp.after_ms > cp.before_ms * 2.5 and cp.t_stat > 0


def test_change_point_detects_improvement_too():
    cp = ad.find_change_point(_noisy(300, 30) + _noisy(100, 20, seed=5))
    assert cp is not None and cp.after_ms < cp.before_ms and cp.t_stat < 0


def test_no_change_point_in_stationary_noise():
    assert ad.find_change_point(_noisy(100, 60, jitter=0.3, seed=7)) is None


def test_single_spike_is_not_a_shift():
    series = _noisy(100, 59) + [3000.0]
    assert ad.find_change_point(series) is None


def test_flapping():
    assert ad.is_flapping(["up", "down"] * 5)
    assert not ad.is_flapping(["up"] * 15 + ["down"] * 5)
    assert ad.count_transitions(["up", "up", "down", "up"]) == 2


def test_zero_mad_falls_back_to_the_mean_deviation():
    values = [40.0] * 25 + [60.0] * 10  # over half identical: MAD is 0
    b = ad.robust_baseline(values)
    assert b.median == 40.0 and b.spread > 2.0  # > the 5% floor: the 60s count


def test_provisional_baseline_only_flags_blatant_spikes():
    b = ad.robust_baseline(_noisy(80, 10), min_samples=ad.COLD_START_MIN)
    assert b.provisional and ad.robust_baseline(_noisy(80, 10)) is None
    assert ad.is_spike(400, b, sensitivity=4)
    assert not ad.is_spike(140, b, sensitivity=4)  # 1.75x: a spike only once trusted
    trusted = ad.robust_baseline(_noisy(80, 30))
    assert not trusted.provisional and ad.is_spike(140, trusted, sensitivity=4)


def test_short_burst_is_not_a_shift():
    # 5 slow checks: the 8-check "after" segment would be padded with 3 normal ones
    assert ad.find_change_point(_noisy(80, 40) + [400.0] * 5) is None
    assert ad.find_change_point(_noisy(80, 40) + [400.0] * 8) is not None

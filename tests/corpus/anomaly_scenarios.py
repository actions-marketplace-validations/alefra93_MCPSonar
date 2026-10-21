"""Reproducible latency scenarios for the anomaly pipeline (seeded noise, no clock).

Each scenario is a list of (status, latency_ms) checks. ``expect`` lists the anomalies the
pipeline must report, as ``(check_index, kind, ongoing)``; nothing else may be reported.
Used by ``tests/test_anomaly_scenarios.py``.
"""

from __future__ import annotations

import random

UP, DOWN = "up", "down"


def noisy(center: float, n: int, jitter: float = 0.08, seed: int = 1) -> list[tuple[str, float]]:
    rnd = random.Random(seed)
    return [(UP, round(center * (1 + rnd.uniform(-jitter, jitter)), 1)) for _ in range(n)]


def slow(latency: float, n: int) -> list[tuple[str, float]]:
    return [(UP, latency)] * n


def _poisoning() -> list[tuple[str, float]]:
    """8 bursts of 5 slow checks, 6 normal checks apart: ~40% of the window is slow. A
    baseline learned from every check would have a spread of ~12 ms and miss the final,
    milder 130 ms spike (1.6x); with the bursts left out the spread stays ~4.5 ms."""
    checks = noisy(80, 20)
    for i in range(8):
        checks += slow(400, 5) + noisy(80, 6, seed=10 + i)
    return checks + slow(130, 1)


SCENARIOS: dict[str, list[tuple[str, float]]] = {
    "stable": noisy(80, 120),
    "cold_start_blatant_spike": noisy(80, 10) + slow(400, 1) + noisy(80, 5, seed=2),
    "cold_start_mild_bump": noisy(80, 10) + slow(140, 1) + noisy(80, 5, seed=2),
    "single_spike": noisy(80, 40) + slow(400, 1) + noisy(80, 20, seed=2),
    "burst": noisy(80, 40) + slow(400, 5) + noisy(80, 20, seed=2),
    "burst_across_an_outage": noisy(80, 40) + slow(400, 2) + [(DOWN, 0.0)] + slow(400, 2)
    + noisy(80, 10, seed=2),
    "sustained_regression": noisy(80, 40) + noisy(250, 60, seed=2),
    "regression_and_back": noisy(80, 40) + noisy(250, 40, seed=2) + noisy(80, 40, seed=3),
    "quantized": [(UP, 40.0)] * 30 + [(UP, 41.0)] * 3 + [(UP, 40.0)] * 30,
    "quantized_spike": [(UP, 40.0)] * 30 + slow(200, 1) + [(UP, 40.0)] * 5,
    "poisoning": _poisoning(),
}

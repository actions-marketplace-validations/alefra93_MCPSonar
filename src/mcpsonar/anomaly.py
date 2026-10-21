"""Statistical anomaly detection on a server's check history. Pure Python, no numpy.

Fixed latency thresholds are a blunt tool: 800 ms is alarming for a server that normally
answers in 40 ms and perfectly normal for one that sits at 700 ms. Instead, every server
gets its own baseline, learned from its recent healthy checks:

* **Latency spike** — a robust z-score, ``(x - median) / (1.4826 · MAD)``. Median and MAD
  (median absolute deviation) are not dragged around by the very outliers we are looking
  for, unlike mean and standard deviation.
* **Latency shift** — a change point: the server did not have one bad check, it *became*
  slower (or faster) and stayed that way, e.g. after a deploy. Found by scanning every split
  of the recent window for the largest difference in mean log-latency (a two-sample
  t-statistic); log space makes a 2× slowdown look the same at 40 ms and at 700 ms.
* **Flapping** — too many up/degraded/down transitions in a short window.

Before :data:`MIN_BASELINE` checks the baseline is *provisional* (from
:data:`COLD_START_MIN` checks on): spikes are still caught, but only blatant ones
(:data:`COLD_START_SENSITIVITY` × the sensitivity and at least :data:`COLD_START_MIN_RATIO` ×
the median). When more than half the samples are identical (quantized timers, cached
answers) the MAD is 0: the mean absolute deviation stands in for it, then the floor applies.

Everything here is a pure function of plain lists; policy, persistence and de-duplication
live in :mod:`mcpsonar.monitor`.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from statistics import median

MAD_SCALE = 1.4826  # makes MAD a consistent estimator of sigma for normal data

# Baseline
MIN_BASELINE = 20  # checks needed before a baseline is trusted
BASELINE_WINDOW = 100

# Cold start: a provisional baseline, with stricter spike rules
COLD_START_MIN = 8
COLD_START_SENSITIVITY = 1.5  # multiplier on the configured sensitivity
COLD_START_MIN_RATIO = 2.0

MEAN_AD_SCALE = 1.2533  # sqrt(pi/2): mean absolute deviation -> sigma for normal data

# Spike: besides being statistically unusual, it must matter in practice.
SPIKE_MIN_DELTA_MS = 20.0
SPIKE_MIN_RATIO = 1.3

# Shift
SHIFT_WINDOW = 60
SHIFT_MIN_SEGMENT = 8  # checks on each side of the change point
SHIFT_MAX_AGE = 20  # only report shifts whose "after" segment is recent
SHIFT_T_THRESHOLD = 6.0
SHIFT_MIN_RATIO = 1.25
SHIFT_MIN_DELTA_MS = 20.0
SHIFT_MAX_MISFIT = 0.2  # share of "after" checks that may still look like the old level

# Flapping
FLAP_WINDOW = 20
FLAP_TRANSITIONS = 6


@dataclass(frozen=True)
class Baseline:
    median: float
    spread: float  # scaled MAD, floored so a very stable server doesn't divide by ~0
    samples: int

    @property
    def provisional(self) -> bool:
        return self.samples < MIN_BASELINE


@dataclass(frozen=True)
class ChangePoint:
    index: int  # first index of the "after" segment
    before_ms: float  # median latency before
    after_ms: float  # median latency after
    t_stat: float

    @property
    def ratio(self) -> float:
        return self.after_ms / self.before_ms if self.before_ms > 0 else math.inf


def robust_baseline(values: list[float], min_samples: int = MIN_BASELINE) -> Baseline | None:
    """Median and scaled MAD of ``values``, or None if there are too few to trust."""
    if len(values) < min_samples:
        return None
    med = median(values)
    mad = median(abs(v - med) for v in values) * MAD_SCALE
    if mad == 0:  # over half the samples identical: fall back to the mean deviation
        mad = sum(abs(v - med) for v in values) / len(values) * MEAN_AD_SCALE
    # Floor: 5% of the median (and 1 ms) — below that, variation is noise, not signal.
    spread = max(mad, 0.05 * med, 1.0)
    return Baseline(med, spread, len(values))


def robust_score(value: float, baseline: Baseline) -> float:
    return (value - baseline.median) / baseline.spread


def is_spike(value: float, baseline: Baseline, sensitivity: float) -> bool:
    """A latency far above the baseline both statistically and in absolute terms (stricter
    on a provisional baseline)."""
    min_ratio = SPIKE_MIN_RATIO
    if baseline.provisional:
        sensitivity *= COLD_START_SENSITIVITY
        min_ratio = COLD_START_MIN_RATIO
    return (
        robust_score(value, baseline) >= sensitivity
        and value - baseline.median >= SPIKE_MIN_DELTA_MS
        and value >= baseline.median * min_ratio
    )


def find_change_point(
    values: list[float],
    min_segment: int = SHIFT_MIN_SEGMENT,
    t_threshold: float = SHIFT_T_THRESHOLD,
) -> ChangePoint | None:
    """The most significant single mean shift in ``values`` (latencies, ms), if any.

    Returns None unless the shift is statistically strong (|t| >= ``t_threshold``),
    practically relevant (medians differ by >= 25% and >= 20 ms) *and* sustained: at most
    :data:`SHIFT_MAX_MISFIT` of the "after" segment may sit closer to the old level. Without
    that, a short burst (fewer slow checks than ``min_segment``) is read as a shift whose
    "after" segment is padded with normal checks.
    """
    n = len(values)
    if n < 2 * min_segment:
        return None
    logs = [math.log(max(v, 1e-3)) for v in values]

    # Prefix sums make each split O(1).
    s1 = [0.0]
    s2 = [0.0]
    for x in logs:
        s1.append(s1[-1] + x)
        s2.append(s2[-1] + x * x)

    best: tuple[float, int] | None = None
    for k in range(min_segment, n - min_segment + 1):
        n1, n2 = k, n - k
        m1 = s1[k] / n1
        m2 = (s1[n] - s1[k]) / n2
        ss1 = s2[k] - n1 * m1 * m1
        ss2 = (s2[n] - s2[k]) - n2 * m2 * m2
        pooled = max((ss1 + ss2) / (n - 2), 1e-4)  # floor: perfectly flat series
        t = (m2 - m1) / math.sqrt(pooled * (1 / n1 + 1 / n2))
        if best is None or abs(t) > abs(best[0]):
            best = (t, k)

    assert best is not None
    t, k = best
    before, after = median(values[:k]), median(values[k:])
    ratio = max(before, after) / max(min(before, after), 1e-3)
    if abs(t) < t_threshold or ratio < SHIFT_MIN_RATIO or abs(after - before) < SHIFT_MIN_DELTA_MS:
        return None
    lb, la = math.log(max(before, 1e-3)), math.log(max(after, 1e-3))
    misfit = sum(abs(x - lb) < abs(x - la) for x in logs[k:]) / (n - k)
    if misfit > SHIFT_MAX_MISFIT:
        return None
    return ChangePoint(index=k, before_ms=before, after_ms=after, t_stat=t)


def count_transitions(statuses: list[str]) -> int:
    return sum(1 for a, b in itertools.pairwise(statuses) if a != b)


def is_flapping(statuses: list[str], threshold: int = FLAP_TRANSITIONS) -> bool:
    return count_transitions(statuses[-FLAP_WINDOW:]) >= threshold


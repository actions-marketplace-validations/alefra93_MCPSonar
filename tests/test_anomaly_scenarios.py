"""The anomaly pipeline against the reproducible scenarios in ``tests/corpus``.

Each scenario runs through :func:`mcpsonar.monitor.process_check` with a fake engine and an
in-memory database; the test asserts the *exact* anomalies reported — what is expected and
nothing else — so a detector change that adds noise or loses a signal fails here.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcpsonar import monitor
from mcpsonar.check_engine import CheckOutcome
from mcpsonar.models import CheckEvent, ServerConfig
from mcpsonar.storage import Storage

_spec = importlib.util.spec_from_file_location(
    "anomaly_scenarios", Path(__file__).parent / "corpus" / "anomaly_scenarios.py")
_corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_corpus)
SCENARIOS = _corpus.SCENARIOS

Report = tuple[int, str, bool]  # (check index, kind, ongoing)


def episode(start: int, slow: int, recovered_at: int | None = None) -> list[Report]:
    """A spike at ``start``, ``slow - 1`` ongoing checks, then the recovery."""
    reports = [(start, "latency_spike", False)]
    reports += [(i, "latency_spike", True) for i in range(start + 1, start + slow)]
    end = recovered_at if recovered_at is not None else start + slow
    return [*reports, (end, "latency_recovered", False)]


def _poisoning() -> list[Report]:
    reports: list[Report] = []
    for burst in range(8):
        reports += episode(20 + burst * 11, 5)
    return [*reports, (108, "latency_spike", False)]


EXPECTED: dict[str, list[Report]] = {
    "stable": [],
    "cold_start_blatant_spike": episode(10, 1),  # provisional baseline: blatant only
    "cold_start_mild_bump": [],
    "single_spike": episode(40, 1),
    "burst": episode(40, 5),  # one episode, one notification, no shift
    # the down check (index 42) neither ends nor joins the episode
    "burst_across_an_outage": [r for r in episode(40, 4, recovered_at=45)
                               if r[0] < 42] + [(43, "latency_spike", True),
                                                (44, "latency_spike", True),
                                                (45, "latency_recovered", False)],
    # sustained: the 7th slow check confirms a shift; the slow level becomes the
    # baseline, so no endless episode and no misleading recovery
    "sustained_regression": episode(40, 7)[:-1] + [(46, "latency_shift", False)],
    "regression_and_back": episode(40, 7)[:-1] + [(46, "latency_shift", False),
                                                  (90, "latency_shift", False)],
    "quantized": [],  # MAD is 0: the mean deviation and the floor keep it quiet
    "quantized_spike": episode(30, 1),
    "poisoning": _poisoning(),
}


@pytest.fixture
async def storage():
    s = await Storage.open(":memory:")
    yield s
    await s.close()


async def _run(storage, monkeypatch, checks) -> tuple[list[Report], CheckEvent]:
    clock = datetime(2026, 1, 1, tzinfo=UTC)
    current: dict = {}

    async def fake(server_id, cfg):
        return CheckOutcome(current["event"], None)

    monkeypatch.setattr(monitor, "run_check", fake)
    reports: list[Report] = []
    event = None
    for i, (status, latency) in enumerate(checks):
        clock += timedelta(minutes=1)
        current["event"] = CheckEvent(server_id="s", status=status, latency_ms=latency,
                                      checked_at=clock)
        event = await monitor.process_check(storage, "s", ServerConfig(url="http://x"))
        reports += [(i, a.kind, a.ongoing) for a in event.anomalies]
    return reports, event


def test_every_scenario_has_an_expectation():
    assert set(SCENARIOS) == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_scenario(name, storage, monkeypatch):
    reports, last = await _run(storage, monkeypatch, SCENARIOS[name])
    assert sorted(reports) == sorted(EXPECTED[name])
    if name in ("sustained_regression",):
        assert 230 < last.latency_baseline_ms < 270  # the new level is the new normal
    if name in ("poisoning", "regression_and_back", "burst"):
        assert 75 < last.latency_baseline_ms < 85  # the bursts did not move it

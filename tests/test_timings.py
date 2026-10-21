"""Per-phase and per-tool timings: measured by the engine, stored, exported to Prometheus.

``latency_ms`` keeps its meaning (the handshake), so existing baselines, anomaly detection
and dashboards are unaffected; the new fields only add detail.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from mcpsonar.adapters.prometheus import render_metrics
from mcpsonar.check_engine import run_check
from mcpsonar.models import CheckEvent, CheckStatus, MonitoredServer, ServerConfig
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"


def _stdio(mode: str, probes=()) -> ServerConfig:
    return ServerConfig(transport="stdio", command=sys.executable,
                        args=[str(FIXTURE), mode], tools_to_test=list(probes))


async def test_phases_are_measured_and_consistent():
    ev = (await run_check("s", _stdio("pages"))).event
    t = ev.timings_ms
    assert set(t) == {"handshake", "discovery", "probes", "total"}
    assert all(v >= 0 for v in t.values())
    assert t["handshake"] == round(ev.latency_ms, 1)  # latency_ms keeps its meaning
    assert t["total"] >= t["handshake"] + t["discovery"]
    assert t["probes"] == 0 and ev.tool_latency_ms == {}


async def test_tool_latency_only_for_tools_actually_called():
    ev = (await run_check("s", _stdio("probes", ["status", "wipe", "ghost"]))).event
    # wipe is skipped (annotated destructive), ghost isn't listed: neither is timed
    assert set(ev.tool_latency_ms) == {"status"}
    assert ev.tool_latency_ms["status"] >= 0 and ev.timings_ms["probes"] > 0


async def test_no_timings_when_the_server_is_not_reached():
    ev = (await run_check("s", ServerConfig(url="http://127.0.0.1:1/mcp"))).event
    assert ev.status == CheckStatus.DOWN and ev.timings_ms is None and ev.tool_latency_ms == {}


async def test_timings_roundtrip_and_old_rows(tmp_path):
    storage = await Storage.open(tmp_path / "m.db")
    try:
        timed = CheckEvent(server_id="s", status="up", latency_ms=10,
                           timings_ms={"handshake": 10, "discovery": 3, "probes": 7,
                                       "total": 25},
                           tool_latency_ms={"search": 7})
        await storage.record_check(timed)
        await storage.record_check(CheckEvent(server_id="s", status="down", latency_ms=0))
        first, second = await storage.get_history("s")
        assert first.timings_ms == timed.timings_ms and first.tool_latency_ms == {"search": 7}
        assert second.timings_ms is None and second.tool_latency_ms == {}
    finally:
        await storage.close()


async def test_migration_adds_the_column_to_a_v07_database(tmp_path):
    db = tmp_path / "old.db"
    storage = await Storage.open(db)
    await storage.record_check(CheckEvent(server_id="s", status="up", latency_ms=5))
    await storage.close()
    with sqlite3.connect(db) as conn:  # make it look like a v0.7 database
        conn.execute("ALTER TABLE checks DROP COLUMN timings_json")
        conn.execute("PRAGMA user_version = 1")  # v0.7.0's schema
    storage = await Storage.open(db)
    try:
        (old,) = await storage.get_history("s")
        assert old.timings_ms is None
        await storage.record_check(CheckEvent(server_id="s", status="up", latency_ms=5,
                                              timings_ms={"total": 9}))
        assert (await storage.get_history("s"))[-1].timings_ms == {"total": 9}
    finally:
        await storage.close()


def test_prometheus_exports_new_series_without_renaming_old_ones():
    store = StateStore()
    store.update(CheckEvent(server_id="s1", status="up", latency_ms=10,
                            timings_ms={"handshake": 10, "discovery": 2, "probes": 5,
                                        "total": 20},
                            tool_latency_ms={'get "x"': 5}))
    servers = [MonitoredServer(id="s1", name="one", url="http://h/mcp")]
    text = render_metrics(servers, store)
    assert 'mcpsonar_latency_ms{server_id="s1"} 10.000' in text  # unchanged
    assert 'mcpsonar_check_duration_ms{server_id="s1"} 20.000' in text
    assert 'mcpsonar_phase_latency_ms{server_id="s1",phase="discovery"} 2.000' in text
    assert 'phase="total"' not in text  # total has its own series
    assert 'mcpsonar_tool_latency_ms{server_id="s1",tool="get \\"x\\""} 5.000' in text

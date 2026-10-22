"""Tests for the config loader (YAML on/off footgun) and the storage-backed dashboard app.

The dashboard routes are async and read from an aiosqlite Storage, so these drive the app
with httpx2's ASGITransport inside the test's own event loop (keeps the DB connection and the
request handling on one loop).
"""

from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.dashboard import create_app
from mcpsonar.loader import ConfigError, load_config
from mcpsonar.models import CheckEvent, CheckStatus, ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


def test_loader_reads_unquoted_on_as_string(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        """
servers:
  s1:
    url: "http://127.0.0.1:8000/mcp"
    webhooks:
      - type: generic
        url: "http://hook"
        on: [down, degraded]
""".lstrip(),
        encoding="utf-8",
    )
    config = load_config(cfg_file)
    generic = config.servers["s1"].webhooks[0]
    assert [s.value for s in generic.on] == ["down", "degraded"]


def test_loader_reports_directory_config_clearly(tmp_path):
    # Simulates the Docker bind-mount footgun: /config/config.yaml is a directory.
    (tmp_path / "config.yaml").mkdir()
    with pytest.raises(ConfigError, match="is a directory"):
        load_config(tmp_path / "config.yaml")


def test_loader_reports_missing_config_clearly(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


async def test_index_serves_the_management_shell():
    storage = await Storage.open(":memory:")
    scheduler = Scheduler(storage, StateStore())
    app = create_app(storage, StateStore(), scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        # The page is a JS shell; data arrives via /api/status, not server-rendered HTML.
        assert "Add server" in resp.text and "/api/status" in resp.text
    await scheduler.stop()
    await storage.close()


async def test_api_status_reports_name_enabled_and_event():
    storage = await Storage.open(":memory:")
    server = await storage.create_server("Beta", ServerConfig(url="http://127.0.0.1:8000/mcp"))
    store = StateStore()
    store.update(
        CheckEvent(
            server_id=server.id,
            status=CheckStatus.UP,
            latency_ms=42.0,
            spec_version="2025-11-25",
            spec_version_supported=True,
        )
    )
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        data = (await client.get("/api/status")).json()
        assert data[server.id]["name"] == "Beta"
        assert data[server.id]["enabled"] is True
        assert data[server.id]["event"]["status"] == "up"

        metrics = (await client.get("/metrics")).text
        assert f'mcpsonar_up{{server_id="{server.id}"}} 1' in metrics
        assert 'name="Beta"' in metrics
    await scheduler.stop()
    await storage.close()


async def test_api_status_with_a_latency_shift_as_last_anomaly():
    # v0.8.0 regression: a shift's `since` (a datetime) made /api/status answer 500, so the
    # dashboard stayed on "Loading...".
    from datetime import UTC, datetime

    from mcpsonar.models import Anomaly

    storage = await Storage.open(":memory:")
    server = await storage.create_server("Gamma", ServerConfig(url="http://127.0.0.1:8000/mcp"))
    since = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    await storage.record_check(CheckEvent(
        server_id=server.id, status=CheckStatus.UP, latency_ms=160.0,
        anomalies=[Anomaly(kind="latency_shift", detail="40ms → 160ms", since=since)],
    ))
    scheduler = Scheduler(storage, store := StateStore())
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/status")
        assert resp.status_code == 200
        last = resp.json()[server.id]["last_anomaly"]
        assert last["kind"] == "latency_shift" and last["since"].startswith("2026-01-01T12:00")
    await scheduler.stop()
    await storage.close()


async def test_insights_report_incidents_from_start_to_recovery():
    from datetime import UTC, datetime, timedelta

    storage = await Storage.open(":memory:")
    server = await storage.create_server("Delta", ServerConfig(url="http://127.0.0.1:8000/mcp"))
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    for minute, status, detail in [(0, "up", None), (1, "down", "connection refused"),
                                   (2, "degraded", None), (3, "up", None), (4, "down", "503")]:
        await storage.record_check(CheckEvent(server_id=server.id, status=status, latency_ms=5,
                                              checked_at=t0 + timedelta(minutes=minute),
                                              detail=detail))
    scheduler = Scheduler(storage, store := StateStore())
    app = create_app(storage, store, scheduler, require_auth=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incidents = (await client.get(f"/api/servers/{server.id}/insights")).json()["incidents"]
        page = (await client.get("/")).text
    assert [(i["worst"], i["checks"], i["detail"]) for i in incidents] == [
        ("down", 2, "connection refused"), ("down", 1, "503")]
    assert incidents[0]["recovered"].startswith("2026-01-01T12:03")
    assert incidents[1]["recovered"] is None  # still ongoing
    # the dashboard has its filter bar, API error banner and incident view
    assert 'id="filters"' in page and 'id="apiErr"' in page and "renderIncidents" in page
    await scheduler.stop()
    await storage.close()

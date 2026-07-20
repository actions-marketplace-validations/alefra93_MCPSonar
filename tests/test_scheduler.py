"""Dynamic scheduler: runtime add/remove of check loops + history persistence.

Uses an unreachable URL (127.0.0.1:1 -> connection refused, fast) so a check completes
quickly as 'down' without needing a live MCP server.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from mcpsonar.models import CheckEvent, CheckStatus, ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

DEAD_URL = "http://127.0.0.1:1/mcp"


async def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_scheduler_starts_enabled_servers_and_records_history():
    storage = await Storage.open(":memory:")
    server = await storage.create_server(
        "dead", ServerConfig(url=DEAD_URL, check_interval_seconds=1)
    )
    store = StateStore()
    scheduler = Scheduler(storage, store)
    await scheduler.start()
    try:
        assert scheduler.is_running(server.id)
        # a check should land in the store and the history table
        assert await _wait_until(lambda: store.get(server.id) is not None)
        assert store.get(server.id).status.value == "down"
        hist = await storage.get_history(server.id)
        assert len(hist) >= 1 and hist[-1].status.value == "down"
    finally:
        await scheduler.stop()
        await storage.close()


async def test_scheduler_add_and_remove_at_runtime():
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    await scheduler.start()  # no servers yet
    try:
        server = await storage.create_server(
            "late", ServerConfig(url=DEAD_URL, check_interval_seconds=1)
        )
        assert not scheduler.is_running(server.id)
        scheduler.add(server)  # added at runtime, no restart
        assert scheduler.is_running(server.id)

        await scheduler.remove(server.id)
        assert not scheduler.is_running(server.id)
    finally:
        await scheduler.stop()
        await storage.close()


async def test_scheduler_skips_disabled_servers():
    storage = await Storage.open(":memory:")
    server = await storage.create_server(
        "paused", ServerConfig(url=DEAD_URL), enabled=False
    )
    store = StateStore()
    scheduler = Scheduler(storage, store)
    await scheduler.start()
    try:
        assert not scheduler.is_running(server.id)
    finally:
        await scheduler.stop()
        await storage.close()


async def test_scheduler_prunes_old_history():
    storage = await Storage.open(":memory:")
    old = datetime.now(timezone.utc) - timedelta(days=30)
    await storage.record_check(
        CheckEvent(server_id="s1", status=CheckStatus.UP, checked_at=old, latency_ms=10,
                   spec_version="2025-11-25", spec_version_supported=True)
    )
    assert len(await storage.get_history("s1")) == 1
    # tiny prune interval so it fires almost immediately; retention 7d -> 30d-old row goes
    scheduler = Scheduler(storage, StateStore(), retention_days=7, prune_interval_s=0.1)
    await scheduler.start()
    try:
        for _ in range(30):
            if not await storage.get_history("s1"):
                break
            await asyncio.sleep(0.05)
        assert await storage.get_history("s1") == []
    finally:
        await scheduler.stop()
        await storage.close()

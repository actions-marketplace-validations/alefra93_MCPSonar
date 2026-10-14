"""Persistence layer: server CRUD + check history + pruning (in-memory SQLite)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mcpsonar.models import CheckEvent, CheckStatus, ServerConfig, ToolProbe, TransportType
from mcpsonar.storage import Storage


async def _store() -> Storage:
    return await Storage.open(":memory:")


async def test_server_crud_roundtrip():
    storage = await _store()
    cfg = ServerConfig(
        url="http://x/mcp",
        transport=TransportType.SSE,
        tools_to_test=[ToolProbe(name="ping"), ToolProbe(name="echo", arguments={"t": "1"})],
    )
    created = await storage.create_server("My Server", cfg)
    assert created.id and created.name == "My Server" and created.enabled is True

    fetched = await storage.get_server(created.id)
    assert fetched is not None
    assert fetched.url == "http://x/mcp"
    assert fetched.transport == TransportType.SSE
    assert fetched.tools_to_test[1].arguments == {"t": "1"}  # config survived the round-trip

    # update: rename + pause + change interval
    cfg2 = fetched.to_server_config()
    cfg2 = cfg2.model_copy(update={"check_interval_seconds": 30})
    updated = await storage.update_server(created.id, "Renamed", cfg2, enabled=False)
    assert updated is not None and updated.name == "Renamed" and updated.enabled is False
    assert (await storage.get_server(created.id)).check_interval_seconds == 30

    assert len(await storage.list_servers()) == 1
    assert await storage.delete_server(created.id) is True
    assert await storage.get_server(created.id) is None
    await storage.close()


async def test_headers_and_stdio_fields_roundtrip():
    storage = await _store()
    # http server with auth headers
    http = await storage.create_server(
        "Protected",
        ServerConfig(url="https://x/mcp", headers={"Authorization": "Bearer tok"}),
    )
    got = await storage.get_server(http.id)
    assert got.headers == {"Authorization": "Bearer tok"}

    # stdio server with command/args/env
    stdio = await storage.create_server(
        "Local",
        ServerConfig(
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-everything"],
            env={"TOKEN": "x"},
        ),
    )
    got2 = await storage.get_server(stdio.id)
    assert got2.transport == TransportType.STDIO
    assert got2.command == "npx"
    assert got2.args == ["-y", "@modelcontextprotocol/server-everything"]
    assert got2.env == {"TOKEN": "x"}
    assert got2.url is None
    await storage.close()


async def test_update_and_delete_missing_return_falsy():
    storage = await _store()
    cfg = ServerConfig(url="http://x/mcp")
    assert await storage.update_server("nope", "n", cfg, enabled=True) is None
    assert await storage.delete_server("nope") is False
    await storage.close()


def _event(server_id: str, status: CheckStatus, at: datetime, latency: float) -> CheckEvent:
    return CheckEvent(
        server_id=server_id,
        status=status,
        checked_at=at,
        latency_ms=latency,
        spec_version="2025-11-25",
        spec_version_supported=True,
    )


async def test_tools_available_roundtrips():
    storage = await _store()
    await storage.record_check(
        CheckEvent(
            server_id="s1", status=CheckStatus.UP, checked_at=datetime.now(UTC),
            latency_ms=10, tools_available=7, spec_version="2025-11-25",
            spec_version_supported=True,
        )
    )
    hist = await storage.get_history("s1")
    assert hist[0].tools_available == 7
    await storage.close()


async def test_history_record_query_and_prune():
    storage = await _store()
    base = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
    for i in range(5):
        await storage.record_check(
            _event("s1", CheckStatus.UP, base + timedelta(minutes=i), latency=100 + i)
        )
    await storage.record_check(_event("other", CheckStatus.DOWN, base, latency=0))

    hist = await storage.get_history("s1")
    assert len(hist) == 5
    assert [e.latency_ms for e in hist] == [100, 101, 102, 103, 104]  # oldest -> newest
    assert all(e.server_id == "s1" for e in hist)

    since = base + timedelta(minutes=3)
    assert len(await storage.get_history("s1", since=since)) == 2  # minutes 3 and 4

    removed = await storage.prune_history(base + timedelta(minutes=2))
    assert removed == 3  # s1 minutes 0,1 (minute 2 == cutoff, kept) + 'other' at minute 0
    assert len(await storage.get_history("s1")) == 3  # minutes 2,3,4 remain
    await storage.close()

"""Cancelling an in-flight check must stop it — never turn into a "down" event.

Regression: the MCP SDK can surface a cancellation as an ordinary exception; caught as a
failed check, it kept the loop alive and `scheduler.remove()` (pause / edit / delete a
server) waited forever. Seen on Linux CI only, because it depends on timing.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from mcpsonar.check_engine import run_check
from mcpsonar.models import ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


@pytest.fixture
def silent_url():
    """A TCP server that accepts connections and never answers."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    conns: list[socket.socket] = []
    stop = threading.Event()

    def accept():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conns.append(srv.accept()[0])
            except OSError:
                pass

    threading.Thread(target=accept, daemon=True).start()
    yield f"http://127.0.0.1:{srv.getsockname()[1]}/mcp"
    stop.set()
    for c in conns:
        c.close()
    srv.close()


async def test_cancelled_check_raises_cancelled_error(silent_url):
    task = asyncio.create_task(run_check("s", ServerConfig(url=silent_url)))
    await asyncio.sleep(0.5)  # connected, waiting for the initialize response
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)


async def _remove_mid_check(url: str, delay: float) -> None:
    storage = await Storage.open(":memory:")
    scheduler = Scheduler(storage, StateStore())
    try:
        server = await storage.create_server("s", ServerConfig(url=url))
        scheduler.add(server)
        await asyncio.sleep(delay)
        await asyncio.wait_for(scheduler.remove(server.id), timeout=5)
        assert not scheduler.is_running(server.id)
    finally:
        await scheduler.stop()
        await storage.close()


@pytest.mark.parametrize("delay", [0.0, 0.05, 0.5])
async def test_removing_a_server_mid_check_returns_promptly(silent_url, delay):
    await _remove_mid_check(silent_url, delay)


async def test_removing_while_a_refused_connection_unwinds():
    # The original hang: cancellation landing while the SDK tears down a refused
    # connection. Sweep the timing window rather than hoping to hit it once.
    for i in range(30):
        await _remove_mid_check("http://127.0.0.1:1/mcp", delay=i * 0.002)

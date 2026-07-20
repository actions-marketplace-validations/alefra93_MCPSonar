"""Dynamic, storage-backed scheduler.

One asyncio task per enabled server, started/stopped **at runtime** as servers are added,
updated, or removed via the API — no restart. Each iteration:

1. runs the check (the engine never raises),
2. updates the in-memory StateStore (current state for the dashboard),
3. persists the event to the history table,
4. fans it out to that server's push adapters.

Owns the shared ``httpx.AsyncClient`` used by adapters, so adapter lifecycle follows the
server lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from .adapters import build_push_adapters
from .adapters.base import BaseAdapter
from .check_engine import check_server
from .models import CheckEvent, MonitoredServer
from .state import StateStore
from .storage import Storage

logger = logging.getLogger("mcpsonar.scheduler")


class Scheduler:
    def __init__(
        self,
        storage: Storage,
        store: StateStore,
        http_timeout: float = 10.0,
        retention_days: float = 7.0,
        prune_interval_s: float = 3600.0,
    ) -> None:
        self._storage = storage
        self._store = store
        self._client = httpx.AsyncClient(timeout=http_timeout)
        self._tasks: dict[str, asyncio.Task] = {}
        self._adapters: dict[str, list[BaseAdapter]] = {}
        self._retention_days = retention_days
        self._prune_interval_s = prune_interval_s
        self._prune_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Spawn a check loop for every enabled server currently in storage."""
        for server in await self._storage.list_servers():
            if server.enabled:
                self._spawn(server)
        if self._retention_days > 0:
            self._prune_task = asyncio.create_task(self._prune_loop(), name="prune")
        logger.info("scheduler started with %d active server(s)", len(self._tasks))

    async def stop(self) -> None:
        if self._prune_task is not None:
            self._prune_task.cancel()
            await asyncio.gather(self._prune_task, return_exceptions=True)
            self._prune_task = None
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        self._adapters.clear()
        await self._client.aclose()

    async def _prune_loop(self) -> None:
        """Periodically drop history older than the retention window."""
        while True:
            await asyncio.sleep(self._prune_interval_s)
            try:
                cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
                removed = await self._storage.prune_history(cutoff)
                if removed:
                    logger.info("pruned %d check(s) older than %.1f day(s)",
                                removed, self._retention_days)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("history pruning failed")

    # ---- runtime add/update/remove (called by the CRUD API) ---------------- #
    def add(self, server: MonitoredServer) -> None:
        if server.enabled and server.id not in self._tasks:
            self._spawn(server)

    async def update(self, server: MonitoredServer) -> None:
        await self.remove(server.id)
        if server.enabled:
            self._spawn(server)

    async def remove(self, server_id: str) -> None:
        task = self._tasks.pop(server_id, None)
        self._adapters.pop(server_id, None)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def is_running(self, server_id: str) -> bool:
        return server_id in self._tasks

    # ---- internals --------------------------------------------------------- #
    def _spawn(self, server: MonitoredServer) -> None:
        self._adapters[server.id] = build_push_adapters(server.to_server_config(), self._client)
        self._tasks[server.id] = asyncio.create_task(
            self._run_server(server), name=f"check:{server.id}"
        )

    async def _run_server(self, server: MonitoredServer) -> None:
        cfg = server.to_server_config()
        while True:
            try:
                event = await check_server(server.id, cfg)
                self._store.update(event)
                await self._storage.record_check(event)
                logger.info(
                    "%s (%s) -> %s (%.0fms, spec=%s)",
                    server.name,
                    server.id,
                    event.status.value,
                    event.latency_ms,
                    event.spec_version,
                )
                await self._emit(server.id, event)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("unexpected error checking %s", server.id)
            await asyncio.sleep(cfg.check_interval_seconds)

    async def _emit(self, server_id: str, event: CheckEvent) -> None:
        for adapter in self._adapters.get(server_id, []):
            try:
                await adapter.send(event)
            except Exception as exc:
                logger.warning(
                    "adapter %s failed for %s: %s", adapter.name, server_id, exc
                )

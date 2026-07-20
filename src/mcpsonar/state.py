"""In-memory store of the most recent CheckEvent per server.

v0.1 keeps only the current state — no history, lost on restart (by design). This is the
single source the dashboard and the Prometheus exporter read from. Everything runs in one
asyncio process and ``update`` does no ``await``, so a plain dict is safe enough.
"""

from __future__ import annotations

from .models import CheckEvent


class StateStore:
    def __init__(self) -> None:
        self._events: dict[str, CheckEvent] = {}

    def update(self, event: CheckEvent) -> None:
        """Record the latest event for its server."""
        self._events[event.server_id] = event

    def get(self, server_id: str) -> CheckEvent | None:
        """Latest event for a server, or None if it has not been checked yet."""
        return self._events.get(server_id)

    def snapshot(self) -> dict[str, CheckEvent]:
        """A shallow copy of the current state, for consistent reads while rendering."""
        return dict(self._events)

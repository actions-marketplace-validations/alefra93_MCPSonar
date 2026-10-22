"""Incidents: runs of checks that were not ``up``, from start to recovery.

One function for every interface (``mcpsonar history``, the API's insights, the dashboard's
History view), so they always agree on what an incident is.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

RANK = {"up": 0, "degraded": 1, "down": 2}


def _iso(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def incidents(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Runs of non-up checks, oldest first: when each started, its worst status, how many
    checks it lasted, the first reason given, and when it recovered (None: still ongoing).

    ``events`` are check events as dicts (oldest first) with ``status``, ``checked_at`` and
    optionally ``detail``.
    """
    found: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for e in events:
        status = getattr(e["status"], "value", e["status"])
        if status != "up":
            if current is None:
                current = {"started": _iso(e["checked_at"]), "worst": status, "checks": 0,
                           "recovered": None, "detail": e.get("detail")}
                found.append(current)
            current["checks"] += 1
            if RANK.get(status, 0) > RANK.get(current["worst"], 0):
                current["worst"] = status
        elif current is not None:
            current["recovered"] = _iso(e["checked_at"])
            current = None
    return found

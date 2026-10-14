"""CRUD API for managing monitored servers at runtime.

Every mutation updates both the store (persistence) and the live scheduler, so adding a
server starts checking it immediately — no restart. These routes back the management UI.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import anomaly as ad
from .check_engine import _format_exc, _open_session
from .lint import lint_tools
from .loader import parse_config_text
from .models import CheckStatus, ServerInput
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage
from .tooldefs import normalize_tool


def register_api(app: FastAPI, storage: Storage, store: StateStore, scheduler: Scheduler) -> None:
    background: set[asyncio.Task] = set()  # keep fire-and-forget tasks referenced

    @app.get("/api/servers")
    async def list_servers():
        servers = await storage.list_servers()
        return [s.model_dump(mode="json") for s in servers]

    @app.get("/api/servers/{server_id}")
    async def get_server(server_id: str):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        return server.model_dump(mode="json")

    @app.post("/api/servers", status_code=201)
    async def create_server(payload: ServerInput):
        server = await storage.create_server(
            payload.name, payload.to_server_config(), enabled=payload.enabled
        )
        scheduler.add(server)  # start checking immediately, no restart
        return server.model_dump(mode="json")

    @app.put("/api/servers/{server_id}")
    async def update_server(server_id: str, payload: ServerInput):
        server = await storage.update_server(
            server_id, payload.name, payload.to_server_config(), enabled=payload.enabled
        )
        if server is None:
            raise HTTPException(404, "server not found")
        await scheduler.update(server)  # restart its loop with the new config
        return server.model_dump(mode="json")

    @app.delete("/api/servers/{server_id}", status_code=204)
    async def delete_server(server_id: str):
        await scheduler.remove(server_id)
        if not await storage.delete_server(server_id):
            raise HTTPException(404, "server not found")
        return JSONResponse(status_code=204, content=None)

    @app.post("/api/servers/{server_id}/check")
    async def check_now(server_id: str):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        event = await scheduler.run_once(server)
        return event.model_dump(mode="json")

    @app.get("/api/servers/{server_id}/tools")
    async def list_server_tools(server_id: str):
        """Connect to the server right now and return the tools it exposes, each with its full
        definition and any tool-poisoning findings."""
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        cfg = server.to_server_config()
        timeout_s = cfg.thresholds.latency_down_ms / 1000.0 + 5.0
        try:
            async with _open_session(cfg, timeout_s) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
        except Exception as exc:
            raise HTTPException(502, f"could not list tools: {_format_exc(exc)}") from exc
        definitions = [normalize_tool(t) for t in tools]
        findings = lint_tools(definitions)
        return [
            {
                "name": d["name"],
                "title": d.get("title"),
                "description": d.get("description") or "",
                "definition": d,
                "findings": [f.to_dict() for f in findings if f.tool == d["name"]],
            }
            for d in definitions
        ]

    @app.get("/api/servers/{server_id}/tool-changes")
    async def tool_changes(server_id: str, all: bool = False):
        """Tool add/remove/change events vs. the pinned baseline (pending only, or ``all``)."""
        if await storage.get_server(server_id) is None:
            raise HTTPException(404, "server not found")
        return await storage.list_tool_changes(server_id, include_reviewed=all)

    @app.post("/api/servers/{server_id}/tool-changes/ack")
    async def acknowledge_tool_changes(server_id: str):
        """Mark pending tool changes as reviewed: the current definitions become trusted."""
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        count = await storage.acknowledge_tool_changes(server_id)
        current = store.get(server_id)
        if current is not None:
            store.update(current.model_copy(update={"tool_changes": 0}))
        # Re-check in the background so a 'degraded because of tool changes' clears promptly.
        task = asyncio.create_task(scheduler.run_once(server))
        background.add(task)
        task.add_done_callback(background.discard)
        return {"acknowledged": count}

    @app.get("/api/servers/{server_id}/insights")
    async def insights(server_id: str, minutes: int | None = None, limit: int = 500):
        """Anomaly-detection view of a window of history: learned baseline, the most
        significant latency change point, and every anomaly reported in the window."""
        if await storage.get_server(server_id) is None:
            raise HTTPException(404, "server not found")
        since = (
            datetime.now(UTC) - timedelta(minutes=minutes)
            if minutes is not None
            else None
        )
        events = await storage.get_history(server_id, since=since, limit=limit)
        healthy = [e for e in events if e.status != CheckStatus.DOWN]
        baseline = ad.robust_baseline([e.latency_ms for e in healthy])
        cp = ad.find_change_point([e.latency_ms for e in healthy])
        return {
            "baseline": None
            if baseline is None
            else {"median_ms": baseline.median, "spread_ms": baseline.spread},
            "change_point": None
            if cp is None
            else {
                "at": healthy[cp.index].checked_at.isoformat(),
                "before_ms": cp.before_ms,
                "after_ms": cp.after_ms,
                "t_stat": cp.t_stat,
            },
            "anomalies": [
                {"checked_at": e.checked_at.isoformat(), **a.model_dump(mode="json")}
                for e in events
                for a in e.anomalies
            ],
        }

    @app.get("/api/servers/{server_id}/history")
    async def history(server_id: str, minutes: int | None = None, limit: int = 500):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        since = (
            datetime.now(UTC) - timedelta(minutes=minutes)
            if minutes is not None
            else None
        )
        events = await storage.get_history(server_id, since=since, limit=limit)
        return [e.model_dump(mode="json") for e in events]

    @app.get("/api/export")
    async def export_yaml() -> PlainTextResponse:
        """Export all servers as a YAML config (same shape as the seed file)."""
        servers = await storage.list_servers()
        out: dict = {"servers": {}}
        for s in servers:
            key = s.name
            if key in out["servers"]:  # keep names unique in the exported file
                key = f"{s.name} ({s.id})"
            out["servers"][key] = s.to_server_config().model_dump(mode="json")
        text = yaml.safe_dump(out, sort_keys=False, allow_unicode=True)
        return PlainTextResponse(
            text,
            media_type="application/x-yaml",
            headers={"Content-Disposition": 'attachment; filename="mcpsonar-servers.yaml"'},
        )

    @app.post("/api/import")
    async def import_yaml(request: Request):
        """Import servers from a YAML config body; each becomes a new monitored server."""
        body = (await request.body()).decode("utf-8")
        try:
            config = parse_config_text(body)
        except Exception as exc:
            raise HTTPException(400, f"invalid YAML config: {exc}") from exc
        created = 0
        for name, cfg in config.servers.items():
            server = await storage.create_server(name=name, config=cfg)
            scheduler.add(server)
            created += 1
        return {"imported": created}

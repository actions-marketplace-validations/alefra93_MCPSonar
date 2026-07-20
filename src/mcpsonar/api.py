"""CRUD API for managing monitored servers at runtime.

Every mutation updates both the store (persistence) and the live scheduler, so adding a
server starts checking it immediately — no restart. These routes back the management UI.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .check_engine import _format_exc, _open_session, check_server
from .loader import parse_config_text
from .models import ServerInput
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage


def register_api(app: FastAPI, storage: Storage, store: StateStore, scheduler: Scheduler) -> None:
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
        event = await check_server(server.id, server.to_server_config())
        store.update(event)
        await storage.record_check(event)
        return event.model_dump(mode="json")

    @app.get("/api/servers/{server_id}/tools")
    async def list_server_tools(server_id: str):
        """Connect to the server right now and return the tools it exposes (name + description)."""
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
        return [
            {
                "name": t.name,
                "title": getattr(t, "title", None),
                "description": t.description or "",
            }
            for t in tools
        ]

    @app.get("/api/servers/{server_id}/history")
    async def history(server_id: str, minutes: int | None = None, limit: int = 500):
        server = await storage.get_server(server_id)
        if server is None:
            raise HTTPException(404, "server not found")
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=minutes)
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

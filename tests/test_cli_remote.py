"""Remote-mode CLI (status, servers, check, diff, history) against a real instance app,
in-process, with real checks of local stdio fixture servers.

The rug pull here is real: the instance pins a clean ``add`` tool, then the fixture serves a
poisoned one; `check` records the change and `diff` must show it as SUSPICIOUS.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport

from mcpsonar.cli import _build_parser
from mcpsonar.commands import _remote
from mcpsonar.dashboard import create_app
from mcpsonar.models import ServerConfig
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"
SECRET = "sk-live-0123456789abcdef"
CLEAN_ADD = {"name": "add", "description": "Adds two numbers.", "inputSchema": {
    "type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}}
PING = {"name": "ping", "description": "tool ping",
        "inputSchema": {"type": "object", "properties": {}}}


@pytest.fixture
async def instance(monkeypatch):
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=True)
    monkeypatch.setattr(_remote, "TRANSPORT_OVERRIDE", ASGITransport(app=app))
    await storage.create_admin("admin", "supersecret")
    _, read = await storage.create_api_token("ro", "read", "admin")
    _, write = await storage.create_api_token("rw", "write", "admin")
    calc = await storage.create_server("calculator", ServerConfig(
        transport="stdio", command=sys.executable, args=[str(FIXTURE), "poisoned"]))
    await storage.save_tool_snapshot(calc.id, {"ping": PING, "add": CLEAN_ADD})  # trusted
    await storage.create_server("remote-api", ServerConfig(
        url="http://127.0.0.1:1/mcp", headers={"Authorization": f"Bearer {SECRET}"}))
    await storage.create_server("old", ServerConfig(url="http://127.0.0.1:1/mcp"),
                                enabled=False)
    yield {"read": read, "write": write, "storage": storage, "calc": calc}
    await scheduler.stop()
    await storage.close()


async def cli(capsys, monkeypatch, token: str | None, *argv: str):
    if token is None:
        monkeypatch.delenv("MCPSONAR_TOKEN", raising=False)
    else:
        monkeypatch.setenv("MCPSONAR_TOKEN", token)
    args = _build_parser().parse_args([*argv, "--url", "http://127.0.0.1:8675"])
    code = await args.handler(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


async def test_check_then_status_and_diff_show_the_rug_pull(instance, capsys, monkeypatch):
    w, r = instance["write"], instance["read"]
    code, out, err = await cli(capsys, monkeypatch, w, "check", "--all", "--json")
    assert code == 1, err  # remote-api is down (port 1) and the default --fail-on is down
    results = {x["name"]: x["event"] for x in json.loads(out)["results"]}
    assert set(results) == {"calculator", "remote-api"}  # paused "old" is not checked
    assert results["calculator"]["tool_changes"] >= 1
    assert SECRET not in out and SECRET not in err

    code, out, _ = await cli(capsys, monkeypatch, r, "status")
    assert code == 0  # --fail-on defaults to never
    for word in ("calculator", "DEGRADED", "remote-api", "DOWN", "old", "PAUSED"):
        assert word in out
    assert "unreviewed tool definition change" in out
    assert "\x1b[" not in out

    code, out, _ = await cli(capsys, monkeypatch, r, "status", "--fail-on", "down")
    assert code == 1

    code, out, _ = await cli(capsys, monkeypatch, r, "diff", "calculator")
    assert code == 1  # unreviewed changes
    assert "add" in out and "SUSPICIOUS" in out
    assert "+sidenote" in out and "fake-system-tag" in out
    assert "never approves" in out

    code, out, _ = await cli(capsys, monkeypatch, r, "diff", "calculator", "--json")
    doc = json.loads(out)
    add = next(c for c in doc["changes"] if c["tool"] == "add")
    assert add["classification"] == "suspicious" and doc["pending"] >= 1
    pending = await instance["storage"].count_pending_tool_changes(instance["calc"].id)
    assert pending == doc["pending"]  # diff only read; nothing was approved


async def test_status_json_matches_dashboard_api(instance, capsys, monkeypatch):
    await cli(capsys, monkeypatch, instance["write"], "check", "calculator")
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "status", "--json")
    doc = json.loads(out)
    assert doc["kind"] == "status" and code == 0
    calc = next(s for s in doc["servers"] if s["name"] == "calculator")
    assert calc["status"] == "degraded" and calc["event"]["tool_risks"] >= 1


async def test_history_after_checks(instance, capsys, monkeypatch):
    for _ in range(2):
        await cli(capsys, monkeypatch, instance["write"], "check", "remote-api",
                  "--fail-on", "never")
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "history", "remote-api",
                             "--last", "1h", "--json")
    summary = json.loads(out)["summary"]
    assert code == 0 and summary["checks"] == 2 and summary["uptime_pct"] == 0
    assert summary["incidents"][0]["worst"] == "down"
    assert summary["incidents"][0]["recovered"] is None
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "history", "remote-api")
    assert "ongoing" in out and "uptime 0.0%" in out


@pytest.mark.parametrize("bad", ["90", "1w", "h"])
async def test_history_rejects_bad_duration(instance, capsys, monkeypatch, bad):
    code, _, err = await cli(capsys, monkeypatch, instance["read"], "history", "old",
                             "--last", bad)
    assert code == 2 and "invalid duration" in err


async def test_servers_list_and_show_mask_secrets(instance, capsys, monkeypatch):
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "servers", "list")
    assert code == 0 and "calculator" in out and "paused" in out
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "servers", "show",
                             "REMOTE-API")  # case-insensitive name match
    assert code == 0 and "********" in out and SECRET not in out
    code, out, _ = await cli(capsys, monkeypatch, instance["read"], "servers", "list", "--json")
    assert SECRET not in out and json.loads(out)["kind"] == "servers"


async def test_errors_are_actionable_exit_2(instance, capsys, monkeypatch):
    code, _, err = await cli(capsys, monkeypatch, None, "status")
    assert code == 2 and "MCPSONAR_TOKEN" in err and "requires a login" in err
    code, _, err = await cli(capsys, monkeypatch, "mcps_wrong", "status")
    assert code == 2 and "rejected" in err
    code, _, err = await cli(capsys, monkeypatch, instance["read"], "check", "calculator")
    assert code == 2 and "read-only" in err
    code, _, err = await cli(capsys, monkeypatch, instance["read"], "diff", "nope")
    assert code == 2 and "servers: calculator" in err
    code, _, err = await cli(capsys, monkeypatch, instance["read"], "check")
    assert code == 2 and "--all" in err


async def test_no_instance_listening(capsys, monkeypatch):
    monkeypatch.setattr(_remote, "TRANSPORT_OVERRIDE", None)
    monkeypatch.delenv("MCPSONAR_TOKEN", raising=False)
    args = _build_parser().parse_args(["status", "--url", "http://127.0.0.1:1"])
    code = await args.handler(args)
    assert code == 2 and "no MCPSonar instance" in capsys.readouterr().err


async def test_token_over_plain_http_to_remote_host_warns(capsys, monkeypatch):
    monkeypatch.setattr(_remote, "TRANSPORT_OVERRIDE", None)
    monkeypatch.setenv("MCPSONAR_TOKEN", "mcps_x")
    args = _build_parser().parse_args(["status", "--url", "http://192.0.2.1:9"])
    monkeypatch.setattr(_remote.httpx, "AsyncClient", _FailingClient)
    await args.handler(args)
    assert "plain HTTP" in capsys.readouterr().err


class _FailingClient:
    def __init__(self, *a, **kw):
        pass

    async def request(self, *a, **kw):
        raise _remote.httpx.ConnectError("offline")

    async def aclose(self):
        pass

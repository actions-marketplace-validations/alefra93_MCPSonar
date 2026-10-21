"""Protocol edges and safe probing, against a real stdio MCP server (tests/fixtures).

* ``tools/list`` pagination is followed to the end (a rug pull on page 2 is not invisible);
  a cursor loop is reported, not followed forever, and never diffed as "tools removed";
* duplicate tool names are a validation issue;
* a server that never answers ends as ``down`` within the check budget;
* probes never call a tool annotated destructive (unless allowed) or one the server
  does not list;
* fingerprints ignore ``required`` order but nothing meaningful.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from mcpsonar.check_engine import check_budget_s, run_check
from mcpsonar.models import CheckStatus, ServerConfig, ToolProbe
from mcpsonar.tooldefs import diff_tools, fingerprint

FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"


def _stdio(mode: str, *extra: str, **kw) -> ServerConfig:
    return ServerConfig(transport="stdio", command=sys.executable,
                        args=[str(FIXTURE), mode, *extra], **kw)


async def test_all_pages_are_listed():
    out = await run_check("s", _stdio("pages"))
    assert out.event.status == CheckStatus.UP, out.event.detail
    assert out.event.tools_available == 12
    assert sorted(t["name"] for t in out.tools) == [f"t{i:02d}" for i in range(12)]


async def test_cursor_loop_is_reported_and_not_diffed():
    out = await run_check("s", _stdio("loop"))
    assert out.event.status == CheckStatus.DEGRADED
    assert "cursor" in out.event.detail
    assert out.tools is None  # an incomplete listing must not look like removed tools


async def test_duplicate_tool_names_flagged():
    out = await run_check("s", _stdio("dup"))
    assert out.event.status == CheckStatus.DEGRADED
    assert "'twin' is listed more than once" in out.event.detail


async def test_hung_stdio_server_ends_as_down():
    cfg = _stdio("hang", thresholds={"latency_degraded_ms": 200, "latency_down_ms": 500})
    t0 = time.monotonic()
    ev = (await run_check("s", cfg)).event
    elapsed = time.monotonic() - t0
    assert ev.status == CheckStatus.DOWN
    assert elapsed < check_budget_s(cfg) + 5


async def test_destructive_tool_is_not_probed(tmp_path):
    marker = tmp_path / "calls.txt"
    cfg = _stdio("probes", str(marker), tools_to_test=["status", "wipe", "ghost"])
    ev = (await run_check("s", cfg)).event
    assert not marker.exists(), "a destructive tool was called"
    assert "wipe (annotated destructive" in ev.detail
    assert "ghost: not listed by the server (not called)" in ev.detail
    assert ev.tools_checked == 2 and ev.tools_failed == 1  # status ok, ghost failed
    assert ev.status == CheckStatus.DEGRADED


async def test_destructive_tool_probed_only_when_explicitly_allowed(tmp_path):
    marker = tmp_path / "calls.txt"
    probe = ToolProbe(name="wipe", allow_destructive=True, timeout_seconds=5)
    ev = (await run_check("s", _stdio("probes", str(marker), tools_to_test=[probe]))).event
    assert ev.status == CheckStatus.UP, ev.detail
    assert marker.read_text(encoding="utf-8").count("wipe called") == 1


def test_probe_options_parse_from_yaml_shape():
    cfg = ServerConfig(url="http://h/mcp", tools_to_test=[
        "ping", {"name": "echo", "arguments": {"t": "x"}, "timeout_seconds": 2},
    ])
    assert cfg.tools_to_test[1].timeout_seconds == 2
    assert cfg.tools_to_test[0].allow_destructive is False
    with pytest.raises(ValueError):
        ServerConfig(url="http://h/mcp", tools_to_test=[{"name": "x", "timeout_seconds": 0}])


# ---- fingerprints ------------------------------------------------------------ #
def _tool(required, enum=("a", "b"), desc="d"):
    return {"name": "t", "description": desc, "inputSchema": {
        "type": "object", "required": list(required),
        "properties": {"x": {"type": "string", "enum": list(enum)}, "y": {"type": "string"}},
    }}


def test_required_order_is_not_a_change():
    a, b = _tool(["x", "y"]), _tool(["y", "x"])
    assert fingerprint(a) == fingerprint(b)
    assert diff_tools({"t": a}, {"t": b}) == []


def test_meaningful_changes_still_detected():
    base = _tool(["x"])
    for changed, field in ((_tool(["x", "y"]), "inputSchema"),
                           (_tool(["x"], enum=("b", "a")), "inputSchema"),
                           (_tool(["x"], desc="d <IMPORTANT>"), "description")):
        diff = diff_tools({"t": base}, {"t": changed})
        assert len(diff) == 1 and diff[0].fields == [field]

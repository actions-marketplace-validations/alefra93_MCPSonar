"""``mcpsonar scan`` — one-shot security scan of an MCP server, for humans and CI.

Connects once, lists the tools, runs the tool-poisoning lint and (optionally) compares the
definitions against a **lockfile** — like a package lock, but for tool descriptions and
schemas. Commit the lockfile; CI fails the day a server you depend on silently changes
what its tools say.

Exit codes: 0 clean · 1 findings at/above ``--fail-on`` or lockfile drift · 2 could not
connect.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from .check_engine import _find_http_error, _format_exc, _open_session, raise_if_cancelling
from .lint import SEVERITY_ORDER, Finding, lint_tools
from .models import ServerConfig, TransportType
from .redact import redact_url, scrub, secret_values
from .tooldefs import ToolChange, diff_tools, fingerprint, index_tools, normalize_tool

LOCK_VERSION = 1


@dataclass
class ScanResult:
    target: str
    server_name: str | None = None
    server_version: str | None = None
    spec_version: str | None = None
    latency_ms: float = 0.0
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    changes: list[ToolChange] | None = None  # None: no lockfile comparison was made
    lock_written: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "server": {"name": self.server_name, "version": self.server_version},
            "spec_version": self.spec_version,
            "latency_ms": round(self.latency_ms, 1),
            "tools": sorted(self.tools),
            "findings": [f.to_dict() for f in self.findings],
            "lock": None
            if self.changes is None
            else [
                {"kind": c.kind, "tool": c.tool, "fields": c.fields} for c in self.changes
            ],
            "error": self.error,
        }


def build_config(
    target: str | None,
    stdio: str | None,
    transport: str | None,
    headers: list[str],
    env: list[str],
) -> tuple[ServerConfig, str]:
    """Turn CLI arguments into a ServerConfig (+ a display label)."""
    if stdio:
        argv = shlex.split(stdio, posix=os.name != "nt")
        env_map = dict(e.split("=", 1) for e in env)
        cfg = ServerConfig(transport=TransportType.STDIO, command=argv[0], args=argv[1:],
                           env=env_map)
        return cfg, stdio  # printed as given: argv is visible to the user anyway
    if not target:
        raise SystemExit("mcpsonar scan: give a server URL, or --stdio \"command args\"")
    t = transport or ("sse" if target.rstrip("/").endswith("/sse") else "http")
    hdrs = {}
    for h in headers:
        key, _, value = h.partition(":")
        hdrs[key.strip()] = value.strip()
    # The label is printed (often into CI logs): never echo an API key embedded in the URL.
    cfg = ServerConfig(transport=TransportType(t), url=target, headers=hdrs)
    return cfg, redact_url(target) or target


async def scan(cfg: ServerConfig, label: str, timeout_s: float = 20.0) -> ScanResult:
    result = ScanResult(target=label)
    try:
        async with _open_session(cfg, timeout_s) as session:
            start = perf_counter()
            init = await session.initialize()
            result.latency_ms = (perf_counter() - start) * 1000
            result.spec_version = init.protocolVersion
            if init.serverInfo:
                result.server_name = init.serverInfo.name
                result.server_version = init.serverInfo.version
            tools = (await session.list_tools()).tools
    except Exception as exc:
        raise_if_cancelling(exc)
        http_err = _find_http_error(exc)
        if http_err is not None and http_err.response.status_code in (401, 403):
            result.error = (
                f"authentication required ({http_err.response.status_code}) — pass a token "
                "with -H 'Authorization: Bearer <token>'"
            )
        else:
            result.error = scrub(_format_exc(exc), secret_values(cfg))
        return result
    definitions = [normalize_tool(t) for t in tools]
    result.tools = index_tools(definitions)
    result.findings = lint_tools(definitions)
    return result


# --------------------------------------------------------------------------- #
# Lockfile
# --------------------------------------------------------------------------- #
def write_lock(path: Path, result: ScanResult) -> None:
    data = {
        "mcpsonar_lock": LOCK_VERSION,
        "server": {"name": result.server_name, "version": result.server_version},
        "spec_version": result.spec_version,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": {
            name: {"sha256": fingerprint(d), "definition": d}
            for name, d in sorted(result.tools.items())
        },
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_lock(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("mcpsonar_lock") != LOCK_VERSION:
        raise SystemExit(f"{path}: not an mcpsonar lockfile (or unsupported version)")
    return {name: entry["definition"] for name, entry in data["tools"].items()}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
class _Style:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bold(self, t: str) -> str: return self(t, "1")
    def dim(self, t: str) -> str: return self(t, "2")
    def red(self, t: str) -> str: return self(t, "31")
    def green(self, t: str) -> str: return self(t, "32")
    def yellow(self, t: str) -> str: return self(t, "33")
    def cyan(self, t: str) -> str: return self(t, "36")


def render(result: ScanResult, fail_on: str, color: bool) -> str:
    s = _Style(color)
    sev_color = {"high": s.red, "medium": s.yellow, "low": s.dim}
    out = [f"{s.bold('mcpsonar scan')} · {result.target}"]
    if result.error:
        out.append(s.red(f"  ✗ could not connect: {result.error}"))
        return "\n".join(out)

    out.append(
        f"  {s.dim('server')}  {result.server_name or '?'} {result.server_version or ''}"
        f" · spec {result.spec_version} · {len(result.tools)} tools · {result.latency_ms:.0f} ms"
    )
    out.append("")
    by_tool: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_tool.setdefault(f.tool, []).append(f)
    width = max((len(n) for n in result.tools), default=4)
    for name in sorted(result.tools, key=lambda n: (not by_tool.get(n), n)):
        fs = by_tool.get(name, [])
        if not fs:
            out.append(f"  {s.green('✓')} {name.ljust(width)}  {s.dim('clean')}")
            continue
        worst = min(fs, key=lambda f: SEVERITY_ORDER[f.severity]).severity
        mark = s.red("✗") if worst == "high" else s.yellow("!") if worst == "medium" else s.dim("·")
        for i, f in enumerate(fs):
            head = f"  {mark} {name.ljust(width)}" if i == 0 else " " * (width + 4)
            sev = sev_color[f.severity](f.severity.upper().ljust(6))
            out.append(f"{head}  {sev} {s.bold(f.rule)} — {f.message}")
            out.append(" " * (width + 14) + s.dim(f"{f.location}: {f.excerpt}"))

    if result.changes is not None:
        out.append("")
        if result.changes:
            out.append(s.red(f"  lockfile: {len(result.changes)} change(s) since the tools "
                             "were pinned"))
            sym = {"added": s.green("+"), "removed": s.red("-"), "changed": s.yellow("~")}
            for c in result.changes:
                out.append(f"    {sym[c.kind]} {c.summary()}")
        else:
            out.append(s.green("  lockfile: ✓ tools match the pinned definitions"))
    if result.lock_written:
        out.append(s.cyan(f"  lockfile written: {result.lock_written}"))

    counts = {k: sum(1 for f in result.findings if f.severity == k) for k in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n) or "no findings"
    failed = exit_code(result, fail_on) != 0
    verdict = s.red(s.bold("FAIL")) if failed else s.green(s.bold("PASS"))
    out.append("")
    out.append(f"  {summary} → {verdict}")
    return "\n".join(out)


def exit_code(result: ScanResult, fail_on: str) -> int:
    if result.error:
        return 2
    if result.changes:
        return 1
    if fail_on != "never":
        limit = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in result.findings):
            return 1
    return 0


async def run_scan(args: Any) -> int:
    cfg, label = build_config(args.target, args.stdio, args.transport, args.header, args.env)
    result = await scan(cfg, label, timeout_s=args.timeout)
    if result.error is None and args.lock:
        lock = Path(args.lock)
        if lock.exists() and not args.update_lock:
            result.changes = diff_tools(read_lock(lock), result.tools)
        else:
            write_lock(lock, result)
            result.lock_written = str(lock)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render(result, args.fail_on, color))
    return exit_code(result, args.fail_on)

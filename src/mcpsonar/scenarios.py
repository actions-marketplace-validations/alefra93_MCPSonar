"""``mcpsonar demo --scenario NAME``: deterministic, step-by-step demos in the terminal.

Each scenario is a short story told in steps. Before each step the scenario sets exactly
what the local demo servers do (their latency, a clean or a poisoned tool set) through
their ``POST /__demo`` control endpoint, then runs the **real** engine on them: the same
check pipeline as the monitor (:func:`mcpsonar.monitor.process_check`), the same inspection
service as ``tools``/``risks``, the same lockfile and SARIF code as ``scan``. Nothing is
simulated on the MCPSonar side.

Every scenario also checks that MCPSonar reacted as expected (the rug pull was flagged, the
regression was reported once...). A scenario that does not is a failure, so
``mcpsonar demo --scenario all --auto`` doubles as an end-to-end smoke test: exit 0 when
every scenario behaved, 1 otherwise, 2 if the demo servers could not start.

With ``--dashboard`` the dashboard runs alongside, on a temporary database where the demo
servers are registered as ordinary monitored servers: each check goes through the scheduler
(like "Check now"), so statuses, tool changes and anomalies appear there as the steps run.

Fully local: the servers run on 127.0.0.1, no credentials, no network.
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import sys
import tempfile
import webbrowser
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2

from .demo import DemoServer, _QuietServer, scenario_servers, spawn
from .lint import SEVERITY_ORDER, lint_tool
from .models import CheckEvent, CheckStatus, ServerConfig
from .monitor import process_check
from .output import EXIT_ERROR, EXIT_FAILED, EXIT_OK, Output
from .storage import Storage


class ScenarioFailed(Exception):
    """MCPSonar did not react the way the scenario expects."""


@dataclass
class Step:
    title: str
    say: str  # the narration: what happens, in one or two sentences
    run: Callable[[Ctx], Awaitable[dict[str, Any]]]


@dataclass
class Scenario:
    key: str
    title: str
    summary: str
    steps: list[Step] = field(default_factory=list)


class Ctx:
    """What a step can do: steer a demo server, run the engine, print, assert."""

    def __init__(self, servers: list[DemoServer], storage: Storage, out: Output,
                 workdir: Path, live: _Live | None = None) -> None:
        self.servers = {s.key: s for s in servers}
        self.storage = storage
        self.out = out
        self.s = out.style
        self.workdir = workdir
        self.live = live

    def id(self, key: str) -> str:
        """The server's id in storage (the dashboard registers them with generated ids)."""
        return self.live.ids[key] if self.live else key

    def cfg(self, key: str) -> ServerConfig:
        return ServerConfig(url=self.servers[key].url)

    async def set(self, key: str, **state: Any) -> None:
        """Change what a demo server does from now on (latency_ms, tools)."""
        url = f"http://127.0.0.1:{self.servers[key].port}/__demo"
        async with httpx2.AsyncClient(timeout=5.0) as client:
            (await client.post(url, json=state)).raise_for_status()

    async def check(self, key: str) -> CheckEvent:
        if self.live:  # through the scheduler, so the dashboard sees it live
            return await self.live.scheduler.run_once(self.live.servers[key])
        return await process_check(self.storage, key, self.cfg(key))

    def print(self, text: str = "") -> None:
        self.out.print(text)

    def event_line(self, key: str, ev: CheckEvent) -> str:
        s = self.s
        status = {"up": s.green, "degraded": s.yellow, "down": s.red}[ev.status.value](
            ev.status.value.upper().ljust(8))
        line = f"    {self.servers[key].name.ljust(14)} {status} {ev.latency_ms:6.0f} ms"
        notes = [f"{a.kind}{' (ongoing)' if a.ongoing else ''}" for a in ev.anomalies]
        if ev.tool_changes:
            notes.append(f"{ev.tool_changes} unreviewed tool change(s)")
        return line + (f"  {s.yellow(' · '.join(notes))}" if notes else "")

    @staticmethod
    def expect(condition: bool, message: str) -> None:
        if not condition:
            raise ScenarioFailed(message)


def _kinds(events: list[CheckEvent], kind: str, ongoing: bool | None = None) -> int:
    return sum(1 for e in events for a in e.anomalies
               if a.kind == kind and (ongoing is None or a.ongoing == ongoing))


# ---- healthy ------------------------------------------------------------------------ #
async def _healthy_check(ctx: Ctx) -> dict[str, Any]:
    events = {}
    for key in ("weather", "docs"):
        events[key] = ev = await ctx.check(key)
        ctx.print(ctx.event_line(key, ev))
        phases = ev.timings_ms or {}
        ctx.print(ctx.s.dim(f"      handshake {phases.get('handshake', 0):.0f} ms · discovery "
                            f"{phases.get('discovery', 0):.0f} ms · {ev.tools_available} tools"))
    ctx.expect(all(e.status == CheckStatus.UP for e in events.values()),
               "a healthy demo server was not reported up")
    return {k: e.status.value for k, e in events.items()}


async def _healthy_scan(ctx: Ctx) -> dict[str, Any]:
    from .scan import render, scan

    findings = 0
    for key in ("weather", "docs"):
        result = await scan(ctx.cfg(key), ctx.servers[key].name)
        ctx.print(_indent(render(result, "high", ctx.s.on)))
        ctx.print()
        findings += len(result.findings)
    ctx.expect(findings == 0, "the healthy servers' tools should have no findings")
    return {"findings": findings}


# ---- poisoning ---------------------------------------------------------------------- #
async def _poisoning(ctx: Ctx) -> dict[str, Any]:
    from .commands.inspect_cmd import render_risks
    from .services import inspect_server

    await ctx.set("calculator", tools="poisoned")
    found = await inspect_server(ctx.cfg("calculator"), "calculator")
    ctx.expect(found.error is None, f"could not inspect the calculator: {found.error}")
    render_risks(found, found.findings, "low", _Indented(ctx.out))
    high = [f for f in found.findings if f.severity == "high"]
    ctx.expect(bool(high), "the poisoned add tool should have high-severity findings")
    return {"findings": [f.rule for f in found.findings]}


# ---- rug pull ----------------------------------------------------------------------- #
async def _rug_trust(ctx: Ctx) -> dict[str, Any]:
    await ctx.set("calculator", tools="clean")
    ev = await ctx.check("calculator")
    ctx.print(ctx.event_line("calculator", ev))
    ctx.print(ctx.s.dim("      first listing pinned as the trusted baseline: "
                        f"{ev.tools_available} tools"))
    ctx.expect(ev.status == CheckStatus.UP and ev.tool_changes == 0,
               "the clean calculator should be up with nothing to review")
    return {"status": ev.status.value}


async def _rug_pull(ctx: Ctx) -> dict[str, Any]:
    await ctx.set("calculator", tools="poisoned")
    ev = await ctx.check("calculator")
    ctx.print(ctx.event_line("calculator", ev))
    changes = await ctx.storage.list_tool_changes(ctx.id("calculator"))
    for change in changes:
        ctx.print(f"      {ctx.s.yellow('~')} tool {ctx.s.bold(change['tool'])}: "
                  f"{', '.join(change['fields'])} changed")
        before = (change["before"] or {}).get("description", "")
        after = (change["after"] or {}).get("description", "")
        ctx.print(ctx.s.dim(f"        before: {_short(before)}"))
        ctx.print(ctx.s.dim(f"        after:  {_short(after)}"))
        new_params = set(_params(change["after"])) - set(_params(change["before"]))
        if new_params:
            ctx.print(ctx.s.dim(f"        new parameter(s): {', '.join(sorted(new_params))}"))
        for f in lint_tool(change["after"] or {}):
            if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER["medium"]:
                ctx.print(f"        {ctx.s.severity(f.severity, 6)} {f.rule}")
    ctx.expect(ev.status == CheckStatus.DEGRADED and _kinds([ev], "tool_change") == 1,
               "the rug pull should be detected and degrade the server")
    return {"status": ev.status.value, "changes": [c["tool"] for c in changes]}


async def _rug_review(ctx: Ctx) -> dict[str, Any]:
    reviewed = await ctx.storage.acknowledge_tool_changes(ctx.id("calculator"))
    ev = await ctx.check("calculator")
    ctx.print(f"    {reviewed} change(s) reviewed")
    ctx.print(ctx.event_line("calculator", ev))
    ctx.expect(ev.status == CheckStatus.UP and ev.tool_changes == 0,
               "after the review the server should be up again")
    return {"reviewed": reviewed, "status": ev.status.value}


# ---- latency regression ------------------------------------------------------------- #
async def _checks(ctx: Ctx, key: str, n: int, show: bool) -> list[CheckEvent]:
    events = []
    for _ in range(n):
        ev = await ctx.check(key)
        events.append(ev)
        if show:
            ctx.print(ctx.event_line(key, ev))
    return events


QUIET_TAIL = 5  # checks in a row without anomalies before the story goes on
MAX_EXTRA = 30


async def _latency_baseline(ctx: Ctx) -> dict[str, Any]:
    await ctx.set("docs", latency_ms=40)
    events = await _checks(ctx, "docs", 24, show=False)
    # The demo server is steady, the machine running it may not be (a loaded CI runner, a
    # laptop compiling): a real hiccup is a real spike, and MCPSonar reports it. Keep
    # learning until the last checks are quiet, so the next step starts from a clean slate.
    while (any(e.anomalies for e in events[-QUIET_TAIL:])
           and len(events) < 24 + MAX_EXTRA):
        events.append(await ctx.check("docs"))
    last = events[-1]
    noise = sum(1 for e in events for a in e.anomalies if not a.ongoing)
    ctx.print(f"    {len(events)} checks · learned baseline {last.latency_baseline_ms:.0f} ms · "
              f"{noise} anomaly(ies)" + (" (this machine's own hiccups)" if noise else ""))
    ctx.expect(not any(a.kind == "latency_shift" for e in events for a in e.anomalies),
               "a steady server was reported as having shifted latency")
    ctx.expect(not any(e.anomalies for e in events[-QUIET_TAIL:]),
               "the server never settled into a quiet baseline")
    return {"baseline_ms": last.latency_baseline_ms, "checks": len(events),
            "noise_anomalies": noise}


async def _latency_slow(ctx: Ctx) -> dict[str, Any]:
    await ctx.set("docs", latency_ms=160)
    events = await _checks(ctx, "docs", 10, show=True)
    notified = sum(1 for e in events for a in e.anomalies if not a.ongoing)
    ctx.print(ctx.s.dim(f"      10 slow checks → {notified} notification(s): the first spike, "
                        "then the confirmed shift; the rest are marked ongoing"))
    ctx.expect(_kinds(events, "latency_spike", ongoing=False) == 1,
               "the slowdown should open exactly one spike episode")
    ctx.expect(_kinds(events, "latency_shift") == 1, "the slowdown should be confirmed as a shift")
    return {"notifications": notified, "checks": len(events)}


async def _latency_fixed(ctx: Ctx) -> dict[str, Any]:
    await ctx.set("docs", latency_ms=40)
    events = await _checks(ctx, "docs", 12, show=True)
    shifts = [a.detail for e in events for a in e.anomalies if a.kind == "latency_shift"]
    ctx.expect(len(shifts) == 1 and "faster" in shifts[0],
               "the fix should be reported once, as a shift back to faster")
    return {"shift": shifts[0]}


# ---- CI gate -------------------------------------------------------------------------- #
async def _ci_pin(ctx: Ctx) -> dict[str, Any]:
    from .scan import exit_code, render, scan, write_lock

    await ctx.set("calculator", tools="clean")
    lock = ctx.workdir / "mcp-tools.lock.json"
    result = await scan(ctx.cfg("calculator"), "calculator")
    write_lock(lock, result)
    result.lock_written = str(lock)
    ctx.print(ctx.s.dim("    $ mcpsonar scan <url> --lock mcp-tools.lock.json"))
    ctx.print(_indent(render(result, "high", ctx.s.on)))
    code = exit_code(result, "high")
    ctx.expect(code == 0, "the clean server should pass the CI gate")
    return {"exit_code": code, "lock": str(lock)}


async def _ci_fail(ctx: Ctx) -> dict[str, Any]:
    from .report import to_sarif
    from .scan import exit_code, read_lock, render, scan
    from .tooldefs import diff_tools

    await ctx.set("calculator", tools="poisoned")
    lock = ctx.workdir / "mcp-tools.lock.json"
    result = await scan(ctx.cfg("calculator"), "calculator")
    result.changes = diff_tools(read_lock(lock), result.tools)
    sarif = ctx.workdir / "mcpsonar.sarif"
    sarif.write_text(json.dumps(to_sarif([(result, str(lock))]), indent=2) + "\n",
                     encoding="utf-8")
    ctx.print(ctx.s.dim("    $ mcpsonar scan <url> --lock mcp-tools.lock.json "
                        "--sarif mcpsonar.sarif"))
    ctx.print(_indent(render(result, "high", ctx.s.on)))
    code = exit_code(result, "high")
    results = len(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"])
    ctx.print()
    ctx.print(f"    exit code {code} → the build fails · SARIF with {results} result(s): "
              f"{sarif}")
    ctx.expect(code == 1 and bool(result.changes), "the changed server should fail the gate")
    return {"exit_code": code, "sarif_results": results, "sarif": str(sarif)}


SCENARIOS: dict[str, Scenario] = {
    s.key: s for s in [
        Scenario("healthy", "Healthy servers", "What a normal check and scan look like.", [
            Step("Check two servers", "MCPSonar connects, negotiates the protocol, lists the "
                 "tools and times every phase.", _healthy_check),
            Step("Scan their tools", "Every tool definition is linted for poisoning patterns, "
                 "the way a CI job would.", _healthy_scan),
        ]),
        Scenario("poisoning", "Tool poisoning", "A tool whose text hides instructions for the "
                 "model.", [
            Step("Explain the findings", "The calculator's add tool now carries the classic "
                 "tool-poisoning proof of concept: a hidden <IMPORTANT> block asking the model "
                 "to read a config file and pass it in a new parameter.", _poisoning),
        ]),
        Scenario("rug-pull", "Rug pull", "A trusted tool changes after you approved it.", [
            Step("Trust the calculator", "On the first check MCPSonar pins every tool "
                 "definition as the trusted baseline.", _rug_trust),
            Step("The server swaps its add tool", "Same server, same tool name, new hidden "
                 "instructions. An uptime monitor still sees a healthy server.", _rug_pull),
            Step("A human reviews it", "Until someone reviews the change the server stays "
                 "degraded. Here we approve it, which makes it the new baseline; in real life "
                 "you would remove the server instead.", _rug_review),
        ]),
        Scenario("latency-regression", "Latency regression", "A deploy makes a server 4× "
                 "slower, then a fix ships.", [
            Step("Learn a baseline", "Checks at a steady latency: MCPSonar learns this "
                 "server's own normal, no fixed threshold.", _latency_baseline),
            Step("A bad deploy", "Every answer now takes about four times longer.",
                 _latency_slow),
            Step("The fix ships", "Answers are fast again.", _latency_fixed),
        ]),
        Scenario("ci-gate", "CI gate", "A pull request check that catches the change.", [
            Step("Pin the tools in CI", "The first run writes a lockfile of every tool "
                 "definition; commit it next to your workflow.", _ci_pin),
            Step("The server changes", "The next run compares the live tools with the "
                 "lockfile, fails the build and writes SARIF for code scanning.", _ci_fail),
        ]),
    ]
}


# ---- rendering helpers ---------------------------------------------------------------- #
def _indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line if line else line for line in text.splitlines())


def _short(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _params(definition: dict[str, Any] | None) -> list[str]:
    schema = (definition or {}).get("inputSchema") or {}
    return list((schema.get("properties") or {}).keys())


class _Indented:
    """An Output that indents what it prints (to nest a command's view in a step)."""

    def __init__(self, out: Output) -> None:
        self._out = out
        self.style = out.style

    def print(self, text: str = "") -> None:
        self._out.print(_indent(text) if text else text)


# ---- the live dashboard --------------------------------------------------------------- #
@dataclass
class _Live:
    storage: Storage
    scheduler: Any
    servers: dict[str, Any]  # key -> MonitoredServer
    ids: dict[str, str]
    url: str
    server: Any
    task: asyncio.Task

    @classmethod
    async def start(cls, cast: list[DemoServer], port: int, workdir: Path) -> _Live:
        import uvicorn

        from .dashboard import create_app
        from .scheduler import Scheduler
        from .state import StateStore

        with socket.socket() as probe:  # fail fast and clearly on a busy port
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                raise RuntimeError(f"port {port} is already in use") from None
        storage = await Storage.open(workdir / "demo.db")
        store = StateStore()
        scheduler = Scheduler(storage, store)  # never started: the scenario runs the checks
        servers = {}
        for d in cast:
            # A long interval: nothing runs on a timer, every check is a scenario step.
            servers[d.key] = await storage.create_server(
                d.name, ServerConfig(url=d.url, check_interval_seconds=86400))
        app = create_app(storage, store, scheduler, require_auth=False)
        server = _QuietServer(uvicorn.Config(app, host="127.0.0.1", port=port,
                                             log_level="warning", access_log=False))
        async def serve() -> None:
            try:
                await server.serve()
            except SystemExit:  # uvicorn exits the process when it cannot bind
                pass

        task = asyncio.create_task(serve(), name="demo:dashboard")
        for _ in range(200):
            if server.started or task.done():
                break
            await asyncio.sleep(0.05)
        if not server.started:
            await asyncio.gather(task, return_exceptions=True)
            await scheduler.stop()
            await storage.close()
            raise RuntimeError(f"the dashboard could not listen on port {port}")
        return cls(storage, scheduler, servers, {k: m.id for k, m in servers.items()},
                   f"http://127.0.0.1:{port}", server, task)

    async def stop(self) -> None:
        self.server.should_exit = True
        await asyncio.gather(self.task, return_exceptions=True)
        await self.scheduler.stop()
        await self.storage.close()


# ---- running -------------------------------------------------------------------------- #
async def _run_one(scenario: Scenario, servers: list[DemoServer], out: Output, pause: bool,
                   workdir: Path, live: _Live | None = None) -> dict[str, Any]:
    s = out.style
    record: dict[str, Any] = {"key": scenario.key, "title": scenario.title, "steps": [],
                              "passed": False, "error": None}
    out.print(s.bold(f"▶ {scenario.title}") + s.dim(f" — {scenario.summary}"))
    storage = live.storage if live else await Storage.open(":memory:")
    ctx = Ctx(servers, storage, out, workdir, live)
    try:
        for n, step in enumerate(scenario.steps, 1):
            out.print()
            out.print(f"  {s.cyan(f'Step {n}/{len(scenario.steps)}')} · {s.bold(step.title)}")
            out.print(s.dim(f"  {step.say}"))
            out.print()
            result = await step.run(ctx)
            record["steps"].append({"title": step.title, "result": result})
            if pause and n < len(scenario.steps):
                await asyncio.to_thread(input, s.dim("  ↵ next step "))
        record["passed"] = True
        out.print()
        out.print(f"  {s.green('✓')} {scenario.title}: MCPSonar reacted as expected.")
    except ScenarioFailed as exc:
        record["error"] = str(exc)
        out.print()
        out.print(f"  {s.red('✗')} {scenario.title}: {exc}")
    finally:
        if live is None:
            await storage.close()
    out.print()
    return record


async def run(args: Any, out: Output) -> int:
    keys = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    base = args.port + 40
    servers = scenario_servers(base)
    try:
        proc = await asyncio.to_thread(spawn, base, 1.0, True)
    except RuntimeError as exc:
        out.error(f"{exc}; choose another --port")
        return EXIT_ERROR
    view = out if not out.json_mode else Output(stdout=io.StringIO(), no_color=True)
    pause = not args.auto and not out.json_mode and sys.stdin.isatty() and sys.stdout.isatty()
    workdir = Path(tempfile.mkdtemp(prefix="mcpsonar-scenario-"))
    records = []
    live = None
    try:
        if args.dashboard:
            try:
                live = await _Live.start(servers, args.port, workdir)
            except RuntimeError as exc:
                out.error(f"{exc}; choose another --port")
                return EXIT_ERROR
            view.print(view.style.bold(f"Dashboard: {live.url}")
                       + view.style.dim("  (it follows every step)"))
            view.print()
            if not args.no_browser:
                webbrowser.open(live.url)
        for key in keys:
            records.append(await _run_one(SCENARIOS[key], servers, view, pause, workdir, live))
            if pause and key != keys[-1]:
                await asyncio.to_thread(input, view.style.dim("↵ next scenario "))
        if live and pause:
            await asyncio.to_thread(input, view.style.dim(f"Dashboard still at {live.url} · "
                                                          "↵ to quit "))
    finally:
        if live:
            await live.stop()
        proc.terminate()
        try:
            await asyncio.to_thread(proc.wait, 5)
        except Exception:
            proc.kill()
    passed = all(r["passed"] for r in records)
    if out.json_mode:
        out.emit_json("demo.scenarios", {"passed": passed, "scenarios": records,
                                         "files": str(workdir),
                                         "dashboard": live.url if live else None})
    elif len(records) > 1:
        ok = sum(r["passed"] for r in records)
        out.print(f"{ok}/{len(records)} scenarios behaved as expected.")
    return EXIT_OK if passed else EXIT_FAILED


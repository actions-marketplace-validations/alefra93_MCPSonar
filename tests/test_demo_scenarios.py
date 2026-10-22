"""``mcpsonar demo --scenario all``: every deterministic scenario, end to end, on the real
engine and real local demo servers. Each scenario asserts its own outcome; this test checks
that all of them passed, so the demo used on stage cannot silently break."""

from __future__ import annotations

import json
import random
import socket

from mcpsonar.cli import main
from mcpsonar.scenarios import SCENARIOS


def _free_base() -> int:
    # --port (dashboard) and --port + 40 .. + 42 (demo servers) must be free; stay below the
    # ephemeral range (Windows hands out 49152+).
    rnd = random.Random()
    for _ in range(50):
        base = rnd.randrange(20000, 40000)
        if all(_free(p) for p in (base - 40, base, base + 1, base + 2)):
            return base - 40
    raise RuntimeError("no free ports")


def _free(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def test_every_scenario_behaves(capsys):
    code = main(["demo", "--scenario", "all", "--auto", "--json", "--port", str(_free_base())])
    doc = json.loads(capsys.readouterr().out)
    failures = {s["key"]: s["error"] for s in doc["scenarios"] if not s["passed"]}
    assert code == 0 and doc["passed"] and not failures, failures
    assert [s["key"] for s in doc["scenarios"]] == list(SCENARIOS)
    by_key = {s["key"]: s for s in doc["scenarios"]}
    assert by_key["ci-gate"]["steps"][1]["result"]["exit_code"] == 1
    assert by_key["latency-regression"]["steps"][1]["result"]["notifications"] == 2


def test_dashboard_mode_follows_the_steps(capsys):
    # Checks go through the scheduler of an in-process dashboard (registered servers,
    # generated ids) instead of a private database: the rug pull must still be caught.
    base = _free_base()
    code = main(["demo", "--scenario", "rug-pull", "--auto", "--json", "--dashboard",
                 "--no-browser", "--port", str(base)])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc["passed"], doc["scenarios"]
    assert doc["dashboard"] == f"http://127.0.0.1:{base}"


def test_busy_dashboard_port_fails_fast(capsys):
    base = _free_base()
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", base))
        busy.listen()
        code = main(["demo", "--scenario", "healthy", "--auto", "--dashboard", "--no-browser",
                     "--port", str(base)])
    assert code == 2 and "already in use" in capsys.readouterr().err

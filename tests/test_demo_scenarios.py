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
    # The demo servers use --port + 40 .. + 42: find a free block of three, below the
    # ephemeral range (Windows hands out 49152+).
    rnd = random.Random()
    for _ in range(50):
        base = rnd.randrange(20000, 40000)
        if all(_free(base + i) for i in range(3)):
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

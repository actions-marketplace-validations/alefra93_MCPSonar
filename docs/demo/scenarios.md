# Demo scenarios

Each scenario is a short story in steps. The numbers below come from a laptop; measured
latencies vary by a few milliseconds between runs, and the outcomes do not.

## `healthy` — what normal looks like (2 steps, ~1 s)

1. **Check two servers.** `weather-api` and `docs-search` are checked once. MCPSonar
   negotiates the protocol (spec 2026-07-28 on these servers), lists the tools and times each
   phase.
2. **Scan their tools.** Each tool definition is linted, the way `mcpsonar scan` does in CI.
   The result is no findings, and both servers PASS.

**Point out:** the per-phase timings, and the fact that a clean scan really is clean (no
noise).

## `poisoning` — a tool that talks to the model (1 step)

1. **Explain the findings.** The calculator's `add` tool carries the classic tool-poisoning
   proof of concept: an `<IMPORTANT>` block telling the model to read `~/.cursor/mcp.json`,
   pass it in a new `sidenote` parameter and not tell the user. There is also a zero-width
   character at the end. `mcpsonar risks` reports 4 high and 2 medium findings. Each one
   shows its evidence (the matching text) and what to review.

**Point out:** the findings are heuristic. They are reasons for a human to look, not proof
of an attack. Every rule is documented, with its measured false positives, in
[detection-rules.md](../detection-rules.md).

## `rug-pull` — a trusted tool changes (3 steps)

1. **Trust the calculator.** The first check pins every tool definition as the trusted
   baseline. The server is up, with nothing to review.
2. **The server swaps its `add` tool.** Same server, same tool name, new hidden instructions
   and a new parameter. MCPSonar marks the server **degraded**. It shows which fields
   changed, the old and new descriptions and the new parameter, and lints the new
   definition.
3. **A human reviews it.** Until then the server stays degraded. The scenario approves the
   change, which makes it the new baseline; in real life you would remove the server. The
   next check is up.

**Point out:** an uptime monitor would show a green server through all of this.

## `latency-regression` — slower, then fixed (3 steps, ~10 s)

1. **Learn a baseline.** At least 24 checks at a steady latency. MCPSonar learns this
   server's own normal (~60 ms here, including connection set-up); there is no fixed
   threshold. If the machine running the demo hiccups (a busy laptop, a shared CI runner),
   MCPSonar reports that real spike. The step then keeps checking until the server has been
   quiet for 5 checks, and says how many such hiccups it saw.
2. **A bad deploy.** Answers take about four times longer. Over 10 slow checks, MCPSonar
   sends **2 notifications**: the first spike, then the confirmed shift (after the seventh
   slow check). The checks in between are marked `ongoing`, not re-notified.
3. **The fix ships.** Answers are fast again. The return is reported once, as a shift back to
   faster, after about eight fast checks.

**Point out:** one slow period produces one notification, not one per check. A burst is
not a regression: a level has to hold before it counts as a shift.

## `ci-gate` — catch it in a pull request (2 steps)

1. **Pin the tools in CI.** `scan --lock` writes a lockfile with every tool definition and
   its SHA-256, and the clean server passes.
2. **The server changes.** The next run compares the live tools with the lockfile. The
   build fails (exit code 1, with the drift and the findings) and a SARIF file is written.
   On GitHub, uploading it with `github/codeql-action/upload-sarif` turns the findings into
   code scanning alerts that point at the lockfile.

**Point out:** this works without running the monitor at all. It needs one workflow step,
the Action, pinned by tag or SHA.

## `all`

All five in the order above, in about 15 seconds with `--auto`. At the end it prints how many
scenarios behaved as expected.

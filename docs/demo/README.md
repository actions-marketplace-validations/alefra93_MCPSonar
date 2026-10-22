# MCPSonar demo

Two ways to show MCPSonar without any setup, credentials or network access. Everything runs
on `127.0.0.1`.

| | `mcpsonar demo` | `mcpsonar demo --scenario NAME` |
|---|---|---|
| What you see | The dashboard | The terminal (and the dashboard with `--dashboard`) |
| Pace | Timers: the story unfolds over ~5 minutes | You press Enter for each step |
| Repeatable | No: latencies and failures are random | Yes: every step sets exactly what the servers do |
| Best for | Leaving it running on a screen | Talks, recordings, articles, CI |

## Quick start

```bash
# with uv, nothing to install
uvx --from https://github.com/alefra93/MCPSonar/releases/download/v0.8.0/mcpsonar-0.8.0-py3-none-any.whl mcpsonar demo --scenario rug-pull

# or, with mcpsonar installed
mcpsonar demo --scenario all --dashboard
```

The scenarios are described in [scenarios.md](scenarios.md). The talk flow is in
[speaker-guide.md](speaker-guide.md), and common problems are in
[troubleshooting.md](troubleshooting.md).

## Options

| Option | Effect |
|---|---|
| `--scenario healthy\|poisoning\|rug-pull\|latency-regression\|ci-gate\|all` | Which story to tell. |
| `--dashboard` | Also serve the dashboard on `--port` (default 8675). It follows every step live and stays up until you press Enter at the end. |
| `--auto` | No pauses between steps. This is automatic when the output is not a terminal. |
| `--json` | One JSON document with every step's result. |
| `--port N` | Dashboard port. The demo servers use `N+40` to `N+42`. |
| `--no-browser`, `--no-color` | Self-explanatory. |

## How it works

1. Three small MCP servers start in a child process: `weather-api`, `docs-search` and
   `calculator`. They are the same servers as the dashboard tour, without timers or
   randomness.
2. Before each step, the scenario tells a server what to do through its local control
   endpoint (`POST /__demo`): a latency, or a clean or poisoned tool set. Only the demo
   servers have this endpoint.
3. MCPSonar's side is the real code. Checks go through the monitor's pipeline; with
   `--dashboard` they go through the scheduler, like "Check now". Findings come from the
   `risks` service, and the CI gate uses the `scan`, lockfile and SARIF code. Nothing on
   MCPSonar's side is simulated.
4. Each scenario checks MCPSonar's reaction (the rug pull was flagged, the regression was
   reported once...) and ends with ✓ or ✗.

## Exit codes

- **0**: every scenario behaved as expected.
- **1**: a scenario did not behave as expected. That is a bug: please
  [open an issue](https://github.com/alefra93/MCPSonar/issues) with the `--json` output.
- **2**: the demo could not start (for example, a port in use).

Because of this, `mcpsonar demo --scenario all --auto` is also an end-to-end smoke test.
The test suite runs it on every change.

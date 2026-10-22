# Speaker guide

A 10–12 minute live demo of MCPSonar, built on the deterministic scenarios. Every step is
reproducible, so a rehearsal is exactly what the audience will see.

## Before the talk

- **Rehearse with `--auto` first:** `mcpsonar demo --scenario all --auto`. Exit code 0 means
  every scenario behaves on this machine.
- **Two windows side by side:** a terminal on the left, the browser on the right (the
  dashboard at `http://127.0.0.1:8675`). Zoom the terminal to 150–200% and the browser to
  125%.
- **Start once before going on stage,** so the first run does not pay for downloads (uv) or
  firewall prompts (Windows). Then stop it with Ctrl+C.
- **Choose a free port** if 8675 is taken (`--port 9000`).
- **Fallback:** the `--json` output and a screen recording of a rehearsal.

## Running order

Start everything with one command and keep it running for the whole talk:

```bash
mcpsonar demo --scenario all --dashboard
```

Press Enter to advance. The order builds the argument: from what the risk is, to how you
catch it, to how you gate it.

| Time | Scenario | The one sentence to say |
|---|---|---|
| 0:00 | (slides) | "Agents trust whatever tools an MCP server announces, and that can change at any time." |
| 1:00 | `healthy` | "This is a normal check: protocol, tools, timings. Clean is clean: no noise." |
| 2:30 | `poisoning` | "This tool talks to the model, not to you. MCPSonar shows the text and why it matters." |
| 4:30 | `rug-pull` | "Yesterday this tool was fine. Today it isn't. Uptime monitors stay green; MCPSonar doesn't." Point at the dashboard: the server turns degraded. |
| 7:00 | `latency-regression` | "Ten slow checks, two notifications. It learns each server's normal; no thresholds to tune." |
| 9:00 | `ci-gate` | "Same detection in a pull request: the build fails and GitHub shows the alert." |
| 10:30 | (slides) | How to try it (one `uvx` line), the repository, questions. |

## Keep it honest

- **Findings are heuristics.** Say so on the poisoning step; the tool says it too. Rule
  documentation and measured false positives: [detection-rules.md](../detection-rules.md).
- **The demo servers are steered** (latency, tool set) through a local control endpoint.
  MCPSonar itself is not simulated: the same code runs against real servers.
- **Real-world numbers** if asked: 24 public MCP servers monitored continuously, 0 false rug
  pulls across SDK and spec upgrades (see the release notes).

## Likely questions

- *Does it block attacks?* No. It detects changes and suspicious text, and gates CI. It is
  not a proxy between the agent and the server.
- *Which transports?* Streamable HTTP, SSE and stdio; spec 2024-11-05 to 2026-07-28.
- *Where does the data go?* Nowhere. It is self-hosted, uses SQLite, and has no telemetry.
- *How do I start?* `uvx --from <release wheel> mcpsonar scan <your server URL>`, or the
  GitHub Action.

# Demo troubleshooting

## "port N is already in use" (exit code 2)

- **Dashboard port:** the dashboard uses `--port` (default 8675). Another MCPSonar, or the
  dashboard tour, may be running. Pick another port: `--port 9000`.
- **Demo server ports:** the demo servers use `--port + 40` to `--port + 42`. If one of
  those is taken, the demo reports that the demo servers failed to start. Changing `--port`
  moves them too.

## A scenario ends with ✗ (exit code 1)

MCPSonar did not react the way the scenario expects. That is a bug, not a setup problem.
Please [open an issue](https://github.com/alefra93/MCPSonar/issues) with:

```bash
mcpsonar demo --scenario all --auto --json > demo.json
mcpsonar version
```

The one exception is a heavily loaded machine. The latency scenario relies on relative
changes (about 4×), so it tolerates normal noise, but a machine that is swapping or busy
compiling can blur it. Run it again on an idle machine before reporting.

## No colors, or odd symbols on Windows

Colors are used only on a terminal. They are disabled with `--no-color` or with the
`NO_COLOR` environment variable. MCPSonar writes UTF-8. If `▶` or `✓` show up as `?` in an
old console, use Windows Terminal, or run `chcp 65001` first.

## The browser did not open

Open the URL printed at the start yourself (`Dashboard: http://127.0.0.1:8675`). Use
`--no-browser` to never open it.

## A firewall prompt appears (Windows)

Everything listens on `127.0.0.1` only. You can deny access from other networks; the demo
does not need it.

## `uvx` is not found

Install uv (https://docs.astral.sh/uv/), or install MCPSonar with pip:
`pip install https://github.com/alefra93/MCPSonar/releases/download/v0.9.0/mcpsonar-0.9.0-py3-none-any.whl`.

## Stopping

Press Ctrl+C at any time. The demo servers stop with the demo, and nothing is left running.
The temporary files (database, lockfile, SARIF) are in the folder printed by `--json`
(`"files"`); delete them whenever you like.

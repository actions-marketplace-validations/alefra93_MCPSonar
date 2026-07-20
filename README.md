# MCPSonar 🛰️

Lightweight, **protocol-aware** health checks for [MCP](https://modelcontextprotocol.io)
(Model Context Protocol) servers.

Generic uptime tools tell you a process is alive. mcpsonar understands MCP: it runs the
`initialize` handshake, records the declared **spec version**, lists tools, optionally
**test-calls** configured tools to prove they respond, and validates the server against
**version-specific** rules — then emits one standardized event you can push anywhere.

It's a small self-hosted **web app**: add, edit, pause and delete MCP servers from the
browser (no config files, no restart), watch live status, and see **uptime + latency history
graphs** — the Uptime-Kuma experience, but MCP-aware. Optional adapters push events to
**Uptime Kuma**, **generic webhooks**, and **Prometheus** for alerting/long-term storage.

## What it checks

- Connection + `initialize` handshake succeed
- Declared MCP **spec version** (and whether mcpsonar has a validator for it)
- Tools are listed, and configured tools actually **respond** when called
- Handshake **latency** against configurable thresholds
- Per-version schema validation (unknown versions get minimal common validation — never a
  false positive on rules we don't know)

Each check produces a `CheckEvent`: `status` (up / degraded / down), `latency_ms`,
`tools_available`, `tools_checked` / `tools_failed`, `spec_version`, `spec_version_supported`,
`detail`.

## Requirements

- **Docker + Docker Compose** — for the container install (Option A), or
- **Python 3.11+** — for the from-source install (Option B).
- **Node.js / `npx`** — *optional*, only needed to monitor **stdio** MCP servers you launch
  via `npx` (or `uvx` for Python-based ones). Not required for http/sse servers.

## Installation

### Option A — Docker (recommended)

```bash
git clone https://github.com/alefra93/MCPSonar.git
cd MCPSonar
docker compose up -d          # builds the image and starts the service
```

The SQLite database is stored in a named volume (`mcpsonar-data`), so your servers, history
and login survive restarts and image rebuilds.

### Option B — From source (Python)

```bash
git clone https://github.com/alefra93/MCPSonar.git
cd MCPSonar
python -m venv .venv
# activate the venv:
#   Windows (PowerShell):  .venv\Scripts\Activate.ps1
#   macOS / Linux:         source .venv/bin/activate
pip install -e .
mcpsonar run                  # dashboard at http://127.0.0.1:8675, db at ./mcpsonar.db
```

> On Windows, `python` may be `py`. Once the package is published to PyPI you'll be able to
> `pip install mcpsonar` directly; until then, install from source as above.

## First run

1. Open **http://localhost:8675** (Docker) or **http://127.0.0.1:8675** (source).
2. Create your **admin account** on the login page (password ≥ 8 characters).
3. Click **+ Add server**, enter an MCP server's URL (or a stdio command), and you're
   monitoring. Prometheus metrics are exposed at `/metrics`.

No config file is required — servers are managed from the UI. (You can optionally seed from a
YAML file on first run: `mcpsonar run --config config.example.yaml`.)

## Command-line options (`mcpsonar run`)

| Flag | Env var | Default | Purpose |
|------|---------|---------|---------|
| `--host` | | `127.0.0.1` | Bind address (`0.0.0.0` to expose on the network). |
| `--port` | | `8675` | HTTP port for the dashboard / API / `/metrics`. |
| `--db PATH` | `MCPSONAR_DB` | `./mcpsonar.db` | SQLite database location. |
| `--retention-days N` | `MCPSONAR_RETENTION_DAYS` | `7` | Drop history older than N days (`0` disables pruning). |
| `--config FILE` | | — | Seed servers from a YAML file on first run (only when the DB is empty). |
| `--no-auth` | | off | Disable the login (only behind a trusted proxy / on localhost). |

## Updating

```bash
git pull
docker compose up -d --build   # Docker
pip install -e .               # from source (inside the venv)
```

## Authentication

The dashboard is protected by a single admin login. On first run the login page prompts you
to **create the admin account**; after that, sign in with those credentials. Sessions are
signed cookies (7-day expiry); passwords are stored PBKDF2-hashed. `/metrics` stays open so
Prometheus can scrape it. Run `mcpsonar run --no-auth` to disable the login entirely — only
do this on localhost or behind a trusted reverse proxy.

## Managing servers

Everything is done from the dashboard or the JSON API — no restart required:

- **Add / Edit / Pause / Delete** a server; changes take effect immediately.
- **Check now** to run an on-demand check.
- **Tools** lists the tools a server exposes right now (name + description), queried live.
- **History** opens uptime % + latency/status graphs over a selectable window (1h / 6h / 24h).
- **Export / Import** all servers as YAML (bulk setup, backups, moving between instances).

### Transports

- **http** — Streamable HTTP (`https://host/mcp`). Optional **auth headers** (e.g.
  `Authorization: Bearer …`) for protected servers.
- **sse** — legacy HTTP+SSE (`https://host/sse`), same header support.
- **stdio** — a **local** MCP server that mcpsonar launches per check. Give it a `command`
  (e.g. `npx`), `args` (e.g. `-y @modelcontextprotocol/server-everything`) and optional `env`.
  The runtime must be available where mcpsonar runs (Node for `npx`, Python for `uvx`, …);
  the default Docker image is Python-only, so stdio-via-npx needs the pip install or a custom
  image. On Windows enter `npx` (bare) — it resolves `npx.cmd` via PATH.

API: `GET/POST/PUT/DELETE /api/servers`, `POST /api/servers/{id}/check`,
`GET /api/servers/{id}/tools`, `GET /api/servers/{id}/history`, `GET /api/export`,
`POST /api/import`, `GET /api/status`.

## Seeding from YAML (optional)

Prefer to start from a file? Pass one on first run — it seeds the DB only when it has no
servers yet (see [`config.example.yaml`](config.example.yaml)):

```bash
mcpsonar run --config config.example.yaml
```

Config shape, one section per server:

```yaml
servers:
  my-server:                     # http/sse server, optionally behind auth
    url: "https://example.com/mcp"
    transport: "http"            # "http" (Streamable HTTP), "sse" (legacy), or "stdio"
    headers:                     # optional — auth for a protected server
      Authorization: "Bearer <token>"
    check_interval_seconds: 60
    tools_to_test:               # bare name, or {name, arguments}
      - ping
      - name: search
        arguments: { query: "healthcheck" }
    thresholds:
      latency_degraded_ms: 2000
      latency_down_ms: 10000
    webhooks:                    # optional — all outputs are opt-in
      - type: uptime_kuma
        push_url: "https://kuma.example.com/api/push/xyz"
      - type: generic
        url: "https://hooks.example.com/webhook"
        on: ["down", "degraded"]

  local-server:                  # stdio server mcpsonar launches per check
    transport: "stdio"
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-everything"]
    # env: { API_TOKEN: "..." }
    tools_to_test:
      - name: echo
        arguments: { message: "healthcheck" }
```

### Outputs (adapters)

- **Uptime Kuma** — GET push. Kuma has no "degraded", so `degraded` maps to **up** with the
  detail in the message (avoids false down-alarms); `down` maps to down.
- **Generic webhook** — POSTs the raw `CheckEvent` JSON; `on` filters which statuses fire it;
  retries up to 3× with exponential backoff.
- **Prometheus** — scrape `GET /metrics` (`mcpsonar_up`, `mcpsonar_status_code`,
  `mcpsonar_latency_ms`, `mcpsonar_tools_failed`, `mcpsonar_spec_version_supported`, …).

## Status thresholds

- **down** — connect/handshake failed, or latency ≥ `latency_down_ms`, or *all* tested tools failed
- **degraded** — latency ≥ `latency_degraded_ms`, or *some* tested tools failed, or known-spec
  validation issues
- **up** — none of the above

An unrecognized spec version is **informational only** (`spec_version_supported: false`); it
never changes the status.

## Development

```bash
pip install -e ".[dev]"
pytest                                   # unit/integration suite (bundled mock, http + stdio)
bash scripts/smoke_e2e.sh                # full end-to-end smoke against the running app

# Try it against the mock manually:
python scripts/mock_mcp_server.py        # shell 1
python scripts/manual_check.py --tools ping   # shell 2
```

`scripts/smoke_e2e.sh` starts the app + a mock MCP server + a webhook receiver and exercises
auth, http/stdio checks, status/heartbeat, history, metrics, webhook delivery, export and CRUD
— printing a PASS/FAIL summary (exit non-zero on any failure). Node/npx enables the stdio case.

Adding support for a new MCP spec version = add one `validators/vYYYY_MM_DD.py` and register
it; existing validators are never touched.

## Scope (v0.4)

Self-service web UI with **admin login**, SQLite persistence, uptime/latency history with
configurable retention, YAML import/export, **http + sse + stdio** transports, and **auth
headers** for protected servers. Single admin account (no multi-user roles yet); ExeWatch
adapter not yet included.

## License

MIT © Alessandro Fraleoni

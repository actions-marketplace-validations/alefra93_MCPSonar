#!/usr/bin/env bash
# Rug-pull demo, end to end and fully local:
#   start MCPSonar -> start a clean MCP server -> register it -> check (pins the tools)
#   -> restart the server with a changed tool -> check again -> show the diff and the alert.
#
# Run it with the Python environment where mcpsonar is installed (pip or a venv): the demo
# server uses the MCP SDK and uvicorn that mcpsonar brings. Override with
#   PYTHON=...  MCPSONAR=...  SERVER_PORT=...  SONAR_PORT=...
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python}"
MCPSONAR="${MCPSONAR:-mcpsonar}"
SERVER_PORT="${SERVER_PORT:-18950}"
SONAR_PORT="${SONAR_PORT:-18951}"
WORK="$(mktemp -d)"
export MCPSONAR_URL="http://127.0.0.1:${SONAR_PORT}"
export NO_COLOR=1
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done  # let them close files
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# wait_port PORT up|down: until something listens on PORT (up) or nothing does (down)
wait_port() {
  "$PY" - "$1" "$2" <<'PYEOF'
import socket, sys, time
port, want = int(sys.argv[1]), sys.argv[2]
deadline = time.time() + 30
while time.time() < deadline:
    with socket.socket() as s:
        up = s.connect_ex(("127.0.0.1", port)) == 0
    if up == (want == "up"):
        sys.exit(0)
    time.sleep(0.2)
sys.exit(f"port {port} is not {want} after 30 s")
PYEOF
}

SERVER_PID=""
start_server() {  # start_server 0|1  (1 = the changed tool)
  MUTATE="$1" PORT="$SERVER_PORT" "$PY" server.py >>"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  PIDS+=("$SERVER_PID")
  wait_port "$SERVER_PORT" up
}

step() { printf '\n== %s\n' "$*"; }

step "1. Start MCPSonar (local only, no login, temporary database)"
# Started through Python itself, not the mcpsonar launcher: on Windows, stopping the launcher
# would leave its Python child running.
"$PY" -m mcpsonar.cli run --no-auth --port "$SONAR_PORT" --db "$WORK/mcpsonar.db" \
  >"$WORK/mcpsonar.log" 2>&1 &
PIDS+=($!)
wait_port "$SONAR_PORT" up
echo "MCPSonar at $MCPSONAR_URL"

step "2. Start the weather server: one harmless tool, get_weather(city)"
start_server 0

step "3. Register it in MCPSonar"
"$MCPSONAR" servers add weather --endpoint "http://127.0.0.1:${SERVER_PORT}/mcp" --interval 3600

step "4. First check: MCPSonar pins the tool definitions"
"$MCPSONAR" check weather --fail-on never

step "5. The server changes its tool (restarted with MUTATE=1)"
kill "$SERVER_PID"
wait_port "$SERVER_PORT" down
start_server 1
echo "same server, same URL, same tool name; new description and a new parameter"

step "6. Second check"
"$MCPSONAR" check weather --fail-on never

step "7. What changed: mcpsonar diff (exit 1 while the change is unreviewed)"
set +e
"$MCPSONAR" diff weather
echo "(exit code $?)"
set -e

step "8. The alert"
"$MCPSONAR" status --fail-on never
echo
echo "MCPSonar's log (the same event goes to webhooks, Slack, Discord or email if configured):"
grep -E "tool_change" "$WORK/mcpsonar.log" | sed -E 's/^[0-9-]+ [0-9:,]+ //' || true

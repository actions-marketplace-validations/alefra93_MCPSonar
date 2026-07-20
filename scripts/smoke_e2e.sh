#!/usr/bin/env bash
#
# End-to-end smoke test for mcpsonar.
#
# Starts the real app (auth on, fresh DB), a bundled mock MCP server, and a tiny
# webhook receiver, then drives the whole surface over HTTP: auth + session gating,
# http & stdio checks, live status/heartbeat, history, check-now, Prometheus metrics,
# generic webhook delivery, YAML export, and edit/pause/delete.
#
# Requires: bash, curl, and the `mcpsonar` package importable by $PY. Node/npx enables
# the stdio check (skipped automatically if npx is missing).
#
# Usage (from the repo root):
#   bash scripts/smoke_e2e.sh
#   PY=python PORT=8899 bash scripts/smoke_e2e.sh
#
set -u

# --- resolve the Python interpreter (prefer the project venv) ----------------
PY="${PY:-}"
if [ -z "$PY" ]; then
  if   [ -x ".venv/Scripts/python.exe" ]; then PY=".venv/Scripts/python.exe"
  elif [ -x ".venv/bin/python" ];        then PY=".venv/bin/python"
  else PY="python"; fi
fi
PORT="${PORT:-8688}"; MOCK_PORT="${MOCK_PORT:-8797}"; HOOK_PORT="${HOOK_PORT:-9200}"
B="http://127.0.0.1:$PORT"

WORK="$(mktemp -d)"
# On Windows/git-bash, convert the msys path (/tmp/..) to a mixed path (C:/..) so the
# native Python interpreter can open files we hand it. No-op elsewhere.
command -v cygpath >/dev/null 2>&1 && WORK="$(cygpath -m "$WORK")"
DB="$WORK/e2e.db"; JAR="$WORK/jar.txt"; HOOK="$WORK/hooks.log"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
           pkill -f server-everything 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

wait_port(){ for _ in $(seq 1 80); do (echo >"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.25; done; return 1; }

# --- tiny webhook receiver (logs each request) -------------------------------
cat > "$WORK/recv.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG = sys.argv[1]
class H(BaseHTTPRequestHandler):
    def _h(self, kind):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode() if n else ""
        open(LOG, "a", encoding="utf-8").write(f"{kind} {self.path} {body[:80]}\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def do_GET(self): self._h("GET")
    def do_POST(self): self._h("POST")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[2])), H).serve_forever()
PY

echo "python : $PY"
echo "app    : $B"

"$PY" "$WORK/recv.py" "$HOOK" "$HOOK_PORT" >/dev/null 2>&1 & PIDS+=("$!")
"$PY" scripts/mock_mcp_server.py --port "$MOCK_PORT" >"$WORK/mock.log" 2>&1 & PIDS+=("$!")
wait_port "$MOCK_PORT" || { echo "mock MCP server did not start"; exit 1; }
wait_port "$HOOK_PORT" || { echo "webhook receiver did not start"; exit 1; }
"$PY" -m mcpsonar.cli run --db "$DB" --port "$PORT" >"$WORK/sonar.log" 2>&1 & PIDS+=("$!")
wait_port "$PORT" || { echo "mcpsonar did not start:"; cat "$WORK/sonar.log"; exit 1; }

HAVE_NPX=0; command -v npx >/dev/null 2>&1 && HAVE_NPX=1

P=0; F=0
chk(){ if [ "$2" = "$3" ]; then echo "  PASS  $1"; P=$((P+1));
       else echo "  FAIL  $1 (got '$2' want '$3')"; F=$((F+1)); fi; }
code(){ curl -s -o /dev/null -w "%{http_code}" "$@"; }
jid(){ "$PY" -c "import sys,json;print(json.load(sys.stdin)['id'])"; }
jstatus(){ "$PY" -c "import sys,json;d=json.load(sys.stdin);e=d['$1']['event'];print(e['status'] if e else 'None')"; }
jrecent(){ "$PY" -c "import sys,json;d=json.load(sys.stdin);print(len(d['$1']['recent']))"; }

echo "=== AUTH ==="
chk "unauth /api/servers -> 401" "$(code $B/api/servers)" "401"
chk "setup admin -> 200" "$(curl -s -c "$JAR" -o /dev/null -w '%{http_code}' -X POST $B/api/auth/setup \
      -H 'Content-Type: application/json' -d '{"username":"admin","password":"supersecret"}')" "200"
chk "authed /api/servers -> 200" "$(code -b "$JAR" $B/api/servers)" "200"

echo "=== ADD SERVERS ==="
MID=$(curl -s -b "$JAR" -X POST $B/api/servers -H 'Content-Type: application/json' -d \
  '{"name":"Mock HTTP","url":"http://127.0.0.1:'"$MOCK_PORT"'/mcp","transport":"http","check_interval_seconds":2,"tools_to_test":["ping"],"thresholds":{"latency_degraded_ms":2000,"latency_down_ms":10000},"webhooks":[{"type":"generic","url":"http://127.0.0.1:'"$HOOK_PORT"'/hook","on":["up","degraded","down"]}]}' | jid)
chk "add http server" "$([ -n "$MID" ] && echo ok)" "ok"
DID=$(curl -s -b "$JAR" -X POST $B/api/servers -H 'Content-Type: application/json' -d \
  '{"name":"Dead","url":"http://127.0.0.1:1/mcp","transport":"http","check_interval_seconds":2,"thresholds":{"latency_degraded_ms":2000,"latency_down_ms":10000}}' | jid)
chk "add unreachable server" "$([ -n "$DID" ] && echo ok)" "ok"
SID=""
if [ "$HAVE_NPX" = "1" ]; then
  SID=$(curl -s -b "$JAR" -X POST $B/api/servers -H 'Content-Type: application/json' -d \
    '{"name":"Everything stdio","transport":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-everything"],"check_interval_seconds":4,"tools_to_test":[{"name":"echo","arguments":{"message":"hc"}}],"thresholds":{"latency_degraded_ms":8000,"latency_down_ms":30000}}' | jid)
  chk "add stdio server" "$([ -n "$SID" ] && echo ok)" "ok"
else
  echo "  SKIP  stdio server (npx not found)"
fi

WAIT=8; [ "$HAVE_NPX" = "1" ] && WAIT=14
echo "=== waiting ${WAIT}s for checks ==="
sleep "$WAIT"
ST=$(curl -s -b "$JAR" $B/api/status)

echo "=== STATUS / HEARTBEAT ==="
chk "mock http -> up"       "$(echo "$ST" | jstatus "$MID")" "up"
chk "unreachable -> down"   "$(echo "$ST" | jstatus "$DID")" "down"
[ -n "$SID" ] && chk "stdio -> up" "$(echo "$ST" | jstatus "$SID")" "up"
chk "mock heartbeat >=1"    "$([ "$(echo "$ST" | jrecent "$MID")" -ge 1 ] && echo ok)" "ok"

echo "=== HISTORY / CHECK-NOW / METRICS ==="
HN=$(curl -s -b "$JAR" $B/api/servers/$MID/history | "$PY" -c "import sys,json;print(len(json.load(sys.stdin)))")
chk "mock history rows >=1"     "$([ "$HN" -ge 1 ] && echo ok)" "ok"
chk "check-now -> 200"          "$(code -b "$JAR" -X POST $B/api/servers/$MID/check)" "200"
chk "/metrics public -> 200"    "$(code $B/metrics)" "200"
chk "/metrics has mock gauge"   "$(curl -s $B/metrics | grep -c "mcpsonar_up{server_id=\"$MID\"}")" "1"

echo "=== WEBHOOK ==="
chk "generic webhook delivered" "$([ -f "$HOOK" ] && grep -q 'POST /hook' "$HOOK" && echo ok)" "ok"

echo "=== EXPORT / EDIT / DELETE ==="
chk "export contains server"    "$(curl -s -b "$JAR" $B/api/export | grep -c 'Mock HTTP')" "1"
chk "rename -> 200"             "$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X PUT $B/api/servers/$MID \
      -H 'Content-Type: application/json' -d '{"name":"Mock Renamed","url":"http://127.0.0.1:'"$MOCK_PORT"'/mcp","transport":"http","check_interval_seconds":2,"tools_to_test":["ping"],"thresholds":{"latency_degraded_ms":2000,"latency_down_ms":10000}}')" "200"
chk "rename persisted"          "$(curl -s -b "$JAR" $B/api/servers/$MID | "$PY" -c "import sys,json;print(json.load(sys.stdin)['name'])")" "Mock Renamed"
chk "delete -> 204"             "$(code -b "$JAR" -X DELETE $B/api/servers/$DID)" "204"
chk "deleted gone -> 404"       "$(code -b "$JAR" $B/api/servers/$DID)" "404"

echo "=== LOGOUT ==="
curl -s -b "$JAR" -c "$JAR" -X POST $B/api/auth/logout >/dev/null
chk "after logout -> 401"       "$(code -b "$JAR" $B/api/servers)" "401"

echo ""
echo "================ RESULT: $P passed, $F failed ================"
[ "$F" -eq 0 ]

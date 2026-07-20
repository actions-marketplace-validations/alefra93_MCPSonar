"""In-process management dashboard.

A single self-contained page (inlined CSS + vanilla JS, no external assets, no build step)
that lets a user **add, edit, pause, delete and re-check** MCP servers from the browser and
watch their live status — the Uptime-Kuma-style experience, but MCP-aware. It talks to the
CRUD API (see :mod:`mcpsonar.api`); adding a server starts checks immediately, no restart.

Also serves ``/api/status`` (live state for polling) and Prometheus ``/metrics``.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .adapters import CONTENT_TYPE, render_metrics
from .api import register_api
from .auth import register_auth
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage


def create_app(
    storage: Storage, store: StateStore, scheduler: Scheduler, require_auth: bool = True
) -> FastAPI:
    app = FastAPI(title="mcpsonar", docs_url=None, redoc_url=None)
    register_auth(app, storage, require_auth)
    register_api(app, storage, store, scheduler)

    @app.get("/api/status")
    async def api_status() -> JSONResponse:
        snap = store.snapshot()
        servers = await storage.list_servers()
        return JSONResponse(
            {
                s.id: {
                    "name": s.name,
                    "enabled": s.enabled,
                    "event": snap[s.id].model_dump(mode="json") if s.id in snap else None,
                }
                for s in servers
            }
        )

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        servers = await storage.list_servers()
        return PlainTextResponse(render_metrics(servers, store), media_type=CONTENT_TYPE)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(_PAGE)

    return app


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcpsonar</title>
<style>
  :root { --bg:#f6f8fa; --card:#fff; --border:#d0d7de; --muted:#57606a; --text:#1f2328; }
  * { box-sizing: border-box; }
  body { font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         margin:0; background:var(--bg); color:var(--text); }
  header { display:flex; align-items:center; justify-content:space-between;
           padding:16px 28px; background:#24292f; color:#fff; }
  header h1 { margin:0; font-size:18px; }
  header .sub { opacity:.7; font-size:12px; margin-top:2px; }
  main { padding:22px 28px; max-width:1100px; margin:0 auto; }
  button { font:inherit; cursor:pointer; border:1px solid var(--border);
           background:#fff; border-radius:6px; padding:6px 12px; }
  button.primary { background:#1f6feb; border-color:#1f6feb; color:#fff; font-weight:600; }
  button.danger { color:#cf222e; }
  button.link { border:none; background:none; padding:4px 6px; color:#1f6feb; }
  table { border-collapse:collapse; width:100%; background:var(--card);
          border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th { text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); padding:10px 14px; background:#f6f8fa; border-bottom:1px solid var(--border); }
  td { padding:12px 14px; border-bottom:1px solid #eaeef2; font-size:14px; vertical-align:middle; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; padding:2px 10px; border-radius:12px; color:#fff;
           font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.03em; }
  .muted { color:var(--muted); }
  .detail { color:#cf222e; font-size:13px; }
  .actions { white-space:nowrap; text-align:right; }
  /* modal */
  .overlay { position:fixed; inset:0; background:rgba(0,0,0,.4); display:none;
             align-items:flex-start; justify-content:center; padding-top:6vh; }
  .overlay.open { display:flex; }
  .modal { background:#fff; border-radius:10px; width:min(560px,92vw); padding:22px 24px;
           box-shadow:0 10px 40px rgba(0,0,0,.25); }
  .modal h2 { margin:0 0 14px; font-size:17px; }
  .field { margin-bottom:12px; }
  .field label { display:block; font-size:13px; font-weight:600; margin-bottom:4px; }
  .field input, .field select, .field textarea { width:100%; padding:8px 10px;
           border:1px solid var(--border); border-radius:6px; font:inherit; }
  .field textarea { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px;
           resize:vertical; }
  .row2 { display:flex; gap:12px; } .row2 > * { flex:1; }
  .modal .buttons { display:flex; justify-content:flex-end; gap:10px; margin-top:8px; }
  .err { color:#cf222e; font-size:13px; min-height:18px; margin-top:4px; }
  .empty { color:var(--muted); }
</style>
</head>
<body>
<header>
  <div><h1>🛰️ mcpsonar</h1><div class="sub" id="sub">MCP server health</div></div>
  <div style="display:flex;gap:8px;align-items:center">
    <span id="whoami" class="muted" style="color:#c9d1d9;font-size:12.5px"></span>
    <button onclick="location.href='/api/export'">Export</button>
    <button onclick="openImport()">Import</button>
    <button class="primary" onclick="openForm()">+ Add server</button>
    <button id="logoutBtn" style="display:none" onclick="logout()">Logout</button>
  </div>
</header>
<main>
  <table>
    <thead><tr>
      <th>Server</th><th>Status</th><th>Latency</th><th>Spec version</th>
      <th style="text-align:center">Tools</th><th>Last check</th><th></th>
    </tr></thead>
    <tbody id="rows"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
  </table>
</main>

<div class="overlay" id="overlay">
  <div class="modal">
    <h2 id="formTitle">Add server</h2>
    <input type="hidden" id="f_id">
    <div class="field"><label>Name</label><input id="f_name" placeholder="My MCP server"></div>
    <div class="row2">
      <div class="field"><label>Transport</label>
        <select id="f_transport" onchange="onTransport()">
          <option value="http">http (Streamable HTTP)</option>
          <option value="sse">sse (legacy)</option>
          <option value="stdio">stdio (local process)</option></select></div>
      <div class="field"><label>Interval (s)</label><input id="f_interval" type="number" value="60"></div>
    </div>
    <div id="grpHttp">
      <div class="field"><label>URL</label><input id="f_url" placeholder="https://example.com/mcp"></div>
      <div class="field"><label>Headers (optional — one per line: <code>Key: Value</code>)</label>
        <textarea id="f_headers" rows="2" placeholder="Authorization: Bearer &lt;token&gt;"></textarea></div>
    </div>
    <div id="grpStdio" style="display:none">
      <div class="field"><label>Command</label><input id="f_command" placeholder="npx"></div>
      <div class="field"><label>Arguments (space-separated)</label>
        <input id="f_args" placeholder="-y @modelcontextprotocol/server-everything"></div>
      <div class="field"><label>Environment (optional — one per line: <code>KEY=value</code>)</label>
        <textarea id="f_env" rows="2" placeholder="API_TOKEN=..."></textarea></div>
    </div>
    <div class="field"><label>Tools to test (comma-separated, optional)</label>
      <input id="f_tools" placeholder="ping, health"></div>
    <div class="row2">
      <div class="field"><label>Degraded latency (ms)</label><input id="f_deg" type="number" value="2000"></div>
      <div class="field"><label>Down latency (ms)</label><input id="f_down" type="number" value="10000"></div>
    </div>
    <div class="err" id="formErr"></div>
    <div class="buttons">
      <button onclick="closeForm()">Cancel</button>
      <button class="primary" onclick="saveForm()">Save</button>
    </div>
  </div>
</div>

<div class="overlay" id="histOverlay">
  <div class="modal" style="width:min(640px,94vw)">
    <h2 id="histTitle">History</h2>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <button class="link" onclick="loadHistory(60)">1h</button>
      <button class="link" onclick="loadHistory(360)">6h</button>
      <button class="link" onclick="loadHistory(1440)">24h</button>
      <button class="link" onclick="loadHistory(null)">All</button>
    </div>
    <div id="histBody"><p class="muted">Loading…</p></div>
    <div class="buttons"><button onclick="closeHistory()">Close</button></div>
  </div>
</div>

<div class="overlay" id="importOverlay">
  <div class="modal">
    <h2>Import servers (YAML)</h2>
    <div class="field">
      <label>Paste a YAML config, or choose a file</label>
      <input type="file" id="importFile" accept=".yaml,.yml" onchange="loadFile(event)">
    </div>
    <div class="field">
      <textarea id="importText" rows="10" style="width:100%;font-family:monospace;font-size:12.5px;
        padding:10px;border:1px solid var(--border);border-radius:6px"
        placeholder="servers:&#10;  my-server:&#10;    url: https://example.com/mcp"></textarea>
    </div>
    <div class="err" id="importErr"></div>
    <div class="buttons">
      <button onclick="closeImport()">Cancel</button>
      <button class="primary" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<script>
const COLORS = { up:"#1a7f37", degraded:"#9a6700", down:"#cf222e", pending:"#57606a" };
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"]="application/json"; opt.body=JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) { let d; try { d = await r.json(); } catch(e){}
    throw new Error(d && d.detail ? JSON.stringify(d.detail) : (r.status+" "+r.statusText)); }
  return r.status === 204 ? null : r.json();
}

function badge(status) {
  const s = status || "pending";
  return `<span class="badge" style="background:${COLORS[s]}">${s}</span>`;
}

async function refresh() {
  let data;
  try { data = await api("GET", "/api/status"); } catch(e) { return; }
  const ids = Object.keys(data);
  const tb = document.getElementById("rows");
  document.getElementById("sub").textContent =
    ids.length + " server" + (ids.length===1?"":"s") + " monitored";
  if (!ids.length) { tb.innerHTML = '<tr><td colspan="7" class="empty">No servers yet. Click “Add server”.</td></tr>'; return; }
  tb.innerHTML = ids.map(id => {
    const s = data[id], ev = s.event;
    const status = ev ? ev.status : "pending";
    const latency = ev ? Math.round(ev.latency_ms)+" ms" : "—";
    let spec = "—";
    if (ev && ev.spec_version) { spec = esc(ev.spec_version);
      if (!ev.spec_version_supported) spec += ' <span class="muted">(unrecognized)</span>'; }
    const tools = ev ? (ev.tools_failed+"/"+ev.tools_checked) : "—";
    const checked = ev ? new Date(ev.checked_at).toLocaleTimeString() : "—";
    const detail = ev && ev.detail ? `<div class="detail">${esc(ev.detail)}</div>` : "";
    const name = esc(s.name) + (s.enabled ? "" : ' <span class="muted">(paused)</span>');
    return `<tr>
      <td><b>${name}</b>${detail}</td>
      <td>${badge(status)}</td><td>${latency}</td><td>${spec}</td>
      <td style="text-align:center">${tools}</td>
      <td class="muted" style="white-space:nowrap">${checked}</td>
      <td class="actions">
        <button class="link" onclick="openHistory('${id}', ${JSON.stringify(s.name)})">History</button>
        <button class="link" onclick="checkNow('${id}')">Check</button>
        <button class="link" onclick="editServer('${id}')">Edit</button>
        <button class="link" onclick="togglePause('${id}', ${s.enabled})">${s.enabled?"Pause":"Resume"}</button>
        <button class="link danger" onclick="del('${id}')">Delete</button>
      </td></tr>`;
  }).join("");
}

const $ = id => document.getElementById(id);
function onTransport(){
  const stdio = $("f_transport").value === "stdio";
  $("grpStdio").style.display = stdio ? "" : "none";
  $("grpHttp").style.display  = stdio ? "none" : "";
}
function parseLines(text, sep){
  const out = {};
  text.split("\n").map(l=>l.trim()).filter(Boolean).forEach(l=>{
    const i = l.indexOf(sep); if(i<0) return;
    out[l.slice(0,i).trim()] = l.slice(i+sep.length).trim();
  });
  return out;
}
function dumpLines(obj, sep){ return Object.entries(obj||{}).map(([k,v])=>k+sep+v).join("\n"); }

function openForm() {
  $("formTitle").textContent = "Add server";
  ["f_id","f_name","f_url","f_headers","f_command","f_args","f_env","f_tools"].forEach(i=>$(i).value="");
  $("f_transport").value="http"; onTransport();
  $("f_interval").value=60; $("f_deg").value=2000; $("f_down").value=10000;
  $("formErr").textContent="";
  $("overlay").classList.add("open");
}
function closeForm(){ $("overlay").classList.remove("open"); }

async function editServer(id) {
  const s = await api("GET", "/api/servers/"+id);
  $("formTitle").textContent = "Edit server";
  $("f_id").value = s.id;
  $("f_name").value = s.name;
  $("f_transport").value = s.transport; onTransport();
  $("f_url").value = s.url || "";
  $("f_headers").value = dumpLines(s.headers, ": ");
  $("f_command").value = s.command || "";
  $("f_args").value = (s.args||[]).join(" ");
  $("f_env").value = dumpLines(s.env, "=");
  $("f_interval").value = s.check_interval_seconds;
  $("f_tools").value = (s.tools_to_test||[]).map(t=>t.name).join(", ");
  $("f_deg").value = s.thresholds.latency_degraded_ms;
  $("f_down").value = s.thresholds.latency_down_ms;
  $("formErr").textContent="";
  $("overlay").classList.add("open");
}

function formPayload(enabled) {
  const transport = $("f_transport").value;
  const tools = $("f_tools").value.split(",").map(t=>t.trim()).filter(Boolean);
  const p = {
    name: $("f_name").value.trim(),
    enabled: enabled,
    transport: transport,
    check_interval_seconds: parseInt($("f_interval").value,10),
    tools_to_test: tools,
    thresholds: {
      latency_degraded_ms: parseFloat($("f_deg").value),
      latency_down_ms: parseFloat($("f_down").value),
    },
  };
  if (transport === "stdio") {
    p.command = $("f_command").value.trim();
    p.args = $("f_args").value.trim() ? $("f_args").value.trim().split(/\s+/) : [];
    p.env = parseLines($("f_env").value, "=");
  } else {
    p.url = $("f_url").value.trim();
    p.headers = parseLines($("f_headers").value, ": ");
  }
  return p;
}

async function saveForm() {
  const id = $("f_id").value;
  try {
    let cur = null;
    if (id) cur = await api("GET","/api/servers/"+id);
    const payload = formPayload(cur ? cur.enabled : true);
    if (cur) payload.webhooks = cur.webhooks;  // the form has no webhook fields; keep existing
    if (id) await api("PUT", "/api/servers/"+id, payload);
    else await api("POST", "/api/servers", payload);
    closeForm(); refresh();
  } catch(e) { $("formErr").textContent = "Error: "+e.message; }
}

async function del(id) {
  if (!confirm("Delete this server and its history?")) return;
  await api("DELETE", "/api/servers/"+id); refresh();
}
async function checkNow(id) { try { await api("POST","/api/servers/"+id+"/check"); } catch(e){} refresh(); }

// ---- history + charts ----
let histId = null;
function closeHistory(){ document.getElementById("histOverlay").classList.remove("open"); }
function openHistory(id, name){
  histId = id;
  document.getElementById("histTitle").textContent = "History · " + name;
  document.getElementById("histOverlay").classList.add("open");
  loadHistory(360);
}
async function loadHistory(minutes){
  const q = minutes ? ("?minutes="+minutes) : "";
  let hist;
  try { hist = await api("GET", "/api/servers/"+histId+"/history"+q); }
  catch(e){ document.getElementById("histBody").innerHTML = '<p class="detail">'+esc(e.message)+'</p>'; return; }
  document.getElementById("histBody").innerHTML = renderCharts(hist);
}
function renderCharts(hist){
  if(!hist.length) return '<p class="muted">No checks recorded in this window yet.</p>';
  const col = s => COLORS[s] || COLORS.pending;
  const n = hist.length;
  const ups = hist.filter(e=>e.status==="up").length;
  const uptime = (100*ups/n).toFixed(1);
  const oks = hist.filter(e=>e.status!=="down");
  const avg = oks.length ? Math.round(oks.reduce((a,e)=>a+e.latency_ms,0)/oks.length) : 0;
  const last = hist[hist.length-1];

  const W=592, H=140, pad=26;
  const lat = hist.map(e=>e.latency_ms);
  const maxL = Math.max(50, ...lat);
  const X = i => pad + (n===1 ? (W-2*pad)/2 : i*(W-2*pad)/(n-1));
  const Y = v => H-pad - (v/maxL)*(H-2*pad);
  const line = lat.map((v,i)=> (i?"L":"M")+X(i).toFixed(1)+" "+Y(v).toFixed(1)).join(" ");
  const area = line + ` L ${X(n-1).toFixed(1)} ${H-pad} L ${X(0).toFixed(1)} ${H-pad} Z`;
  const dots = hist.map((e,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(e.latency_ms).toFixed(1)}" r="2.4" fill="${col(e.status)}"/>`).join("");
  const gy = v => `<line x1="${pad}" y1="${Y(v).toFixed(1)}" x2="${W-pad}" y2="${Y(v).toFixed(1)}" stroke="#8884" stroke-dasharray="3 3"/>`
    + `<text x="4" y="${(Y(v)+3).toFixed(1)}" font-size="9" fill="#8b949e">${Math.round(v)}</text>`;
  const grid = gy(maxL) + gy(maxL/2);

  const sw=(W-2*pad)/n;
  const strip = hist.map((e,i)=>`<rect x="${(pad+i*sw).toFixed(1)}" y="0" width="${Math.max(1.2,sw-1).toFixed(1)}" height="14" rx="1" fill="${col(e.status)}"/>`).join("");

  return `
    <div style="display:flex;gap:22px;margin-bottom:12px;font-size:13px">
      <div><div class="muted" style="font-size:11px;text-transform:uppercase">Uptime</div><b style="font-size:17px">${uptime}%</b></div>
      <div><div class="muted" style="font-size:11px;text-transform:uppercase">Avg latency</div><b style="font-size:17px">${avg} ms</b></div>
      <div><div class="muted" style="font-size:11px;text-transform:uppercase">Checks</div><b style="font-size:17px">${n}</b></div>
      <div><div class="muted" style="font-size:11px;text-transform:uppercase">Now</div>${badge(last.status)}</div>
    </div>
    <div class="muted" style="font-size:11px;margin-bottom:3px">Latency (ms)</div>
    <svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block">
      ${grid}
      <path d="${area}" fill="${col(last.status)}22"/>
      <path d="${line}" fill="none" stroke="${col(last.status)}" stroke-width="1.6"/>
      ${dots}
    </svg>
    <div class="muted" style="font-size:11px;margin:8px 0 3px">Status timeline (oldest → newest)</div>
    <svg viewBox="0 0 ${W} 14" width="100%" style="display:block">${strip}</svg>`;
}

// ---- import / export ----
function closeImport(){ document.getElementById("importOverlay").classList.remove("open"); }
function openImport(){
  document.getElementById("importText").value="";
  document.getElementById("importErr").textContent="";
  document.getElementById("importOverlay").classList.add("open");
}
function loadFile(ev){
  const f = ev.target.files[0]; if(!f) return;
  const r = new FileReader();
  r.onload = () => { document.getElementById("importText").value = r.result; };
  r.readAsText(f);
}
async function doImport(){
  const text = document.getElementById("importText").value;
  try {
    const r = await fetch("/api/import", {method:"POST", headers:{"Content-Type":"application/x-yaml"}, body:text});
    if(!r.ok){ const d=await r.json().catch(()=>({})); throw new Error(d.detail||r.status); }
    const res = await r.json();
    closeImport(); refresh();
    alert("Imported "+res.imported+" server(s).");
  } catch(e){ document.getElementById("importErr").textContent = "Error: "+e.message; }
}
async function togglePause(id, enabled) {
  const s = await api("GET","/api/servers/"+id);
  const payload = Object.assign({}, s, {enabled: !enabled});
  delete payload.id;  // ServerInput forbids unknown fields; everything else is preserved
  await api("PUT","/api/servers/"+id, payload); refresh();
}

async function logout(){ await fetch("/api/auth/logout",{method:"POST"}); location.href="/login"; }
async function initAuth(){
  try {
    const s = await (await fetch("/api/auth/status")).json();
    if (s.auth_enabled){
      document.getElementById("logoutBtn").style.display="";
      if (s.username) document.getElementById("whoami").textContent = s.username;
    }
  } catch(e){}
}

initAuth();
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""

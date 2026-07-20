"""In-process management dashboard.

A single self-contained page (inlined CSS + vanilla JS, no external assets, no build step)
that lets a user add, edit, pause, delete and re-check MCP servers from the browser and watch
their live status, heartbeat and history — the Uptime-Kuma experience, but MCP-aware. It talks
to the CRUD API (see :mod:`mcpsonar.api`); adding a server starts checks immediately.

Also serves ``/api/status`` (live state + recent heartbeat for polling) and Prometheus
``/metrics``.
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

_HEARTBEAT_POINTS = 40


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
        out: dict = {}
        for s in servers:
            recent = await storage.get_history(s.id, limit=_HEARTBEAT_POINTS)
            out[s.id] = {
                "name": s.name,
                "enabled": s.enabled,
                "transport": s.transport.value,
                "target": s.url or s.command or "",
                "event": snap[s.id].model_dump(mode="json") if s.id in snap else None,
                "recent": [
                    {"status": e.status.value, "latency_ms": e.latency_ms} for e in recent
                ],
            }
        return JSONResponse(out)

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
  :root{
    --bg:#f1f4f9; --surface:#ffffff; --surface-2:#f6f9fc; --elev:#ffffff;
    --border:#e4e9f2; --border-strong:#d2dbe8;
    --text:#0e1a2b; --muted:#5b6b83; --faint:#93a1b6;
    --accent:#0d9488; --accent-strong:#0f766e; --accent-ink:#ffffff; --accent-soft:rgba(13,148,136,.10);
    --up:#15a34a; --degraded:#d97706; --down:#dc2626; --pending:#6b7a92;
    --shadow:0 1px 2px rgba(14,26,43,.05), 0 10px 26px rgba(14,26,43,.06);
    --shadow-lg:0 24px 70px rgba(14,26,43,.24);
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --r:12px;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#070c15; --surface:#0f1826; --surface-2:#131f30; --elev:#14202f;
      --border:#1f2b3e; --border-strong:#2c3c54;
      --text:#e7eefb; --muted:#93a3bd; --faint:#5f708a;
      --accent:#2dd4bf; --accent-strong:#5eead4; --accent-ink:#04120f; --accent-soft:rgba(45,212,191,.12);
      --up:#34d399; --degraded:#fbbf24; --down:#f87171; --pending:#7c8aa5;
      --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 32px rgba(0,0,0,.38);
      --shadow-lg:0 28px 80px rgba(0,0,0,.62);
    }
  }
  :root[data-theme="light"]{
    --bg:#f1f4f9; --surface:#ffffff; --surface-2:#f6f9fc; --elev:#ffffff;
    --border:#e4e9f2; --border-strong:#d2dbe8; --text:#0e1a2b; --muted:#5b6b83; --faint:#93a1b6;
    --accent:#0d9488; --accent-strong:#0f766e; --accent-ink:#ffffff; --accent-soft:rgba(13,148,136,.10);
    --up:#15a34a; --degraded:#d97706; --down:#dc2626; --pending:#6b7a92;
    --shadow:0 1px 2px rgba(14,26,43,.05), 0 10px 26px rgba(14,26,43,.06);
    --shadow-lg:0 24px 70px rgba(14,26,43,.24);
  }
  :root[data-theme="dark"]{
    --bg:#070c15; --surface:#0f1826; --surface-2:#131f30; --elev:#14202f;
    --border:#1f2b3e; --border-strong:#2c3c54; --text:#e7eefb; --muted:#93a3bd; --faint:#5f708a;
    --accent:#2dd4bf; --accent-strong:#5eead4; --accent-ink:#04120f; --accent-soft:rgba(45,212,191,.12);
    --up:#34d399; --degraded:#fbbf24; --down:#f87171; --pending:#7c8aa5;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 32px rgba(0,0,0,.38);
    --shadow-lg:0 28px 80px rgba(0,0,0,.62);
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.45;
       -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
  .num{font-variant-numeric:tabular-nums;}
  ::selection{background:var(--accent-soft);}

  /* top bar */
  .topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:14px;
       padding:14px 26px;background:color-mix(in srgb,var(--surface) 88%,transparent);
       backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--border);}
  .brand{display:flex;align-items:center;gap:12px;margin-right:auto;}
  .logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:20px;
       background:linear-gradient(150deg,var(--accent),var(--accent-strong));
       box-shadow:0 6px 18px var(--accent-soft), inset 0 1px 0 rgba(255,255,255,.25);}
  .brand h1{margin:0;font-size:17px;font-weight:700;letter-spacing:-.02em;}
  .brand .live{display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);margin-top:1px;}
  .ping{width:7px;height:7px;border-radius:50%;background:var(--accent);position:relative;}
  .ping::after{content:"";position:absolute;inset:-4px;border-radius:50%;border:1px solid var(--accent);
       animation:ping 1.9s ease-out infinite;}
  @keyframes ping{0%{transform:scale(.6);opacity:.8}100%{transform:scale(1.9);opacity:0}}
  @media (prefers-reduced-motion:reduce){.ping::after{animation:none;}}

  .btn{font:inherit;font-size:13.5px;font-weight:550;cursor:pointer;border:1px solid var(--border-strong);
       background:var(--surface);color:var(--text);border-radius:9px;padding:8px 13px;
       display:inline-flex;align-items:center;gap:7px;transition:all .14s ease;}
  .btn:hover{border-color:var(--accent);color:var(--accent-strong);transform:translateY(-1px);}
  .btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
  .btn.primary{background:linear-gradient(150deg,var(--accent),var(--accent-strong));
       border-color:transparent;color:var(--accent-ink);box-shadow:0 6px 16px var(--accent-soft);}
  .btn.primary:hover{color:var(--accent-ink);filter:brightness(1.06);}
  .btn.icon{padding:8px 10px;}
  .whoami{font-size:12.5px;color:var(--muted);display:inline-flex;align-items:center;gap:6px;}
  .whoami .av{width:22px;height:22px;border-radius:50%;background:var(--accent-soft);color:var(--accent-strong);
       display:grid;place-items:center;font-weight:700;font-size:11px;text-transform:uppercase;}

  main{max-width:1120px;margin:0 auto;padding:26px 26px 70px;}

  /* summary tiles */
  .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px;}
  .tile{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:15px 17px;
       box-shadow:var(--shadow);position:relative;overflow:hidden;}
  .tile .k{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:600;}
  .tile .v{font-size:27px;font-weight:750;letter-spacing:-.02em;margin-top:4px;}
  .tile .rail{position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--faint);}
  .tile.up .rail{background:var(--up);} .tile.degraded .rail{background:var(--degraded);}
  .tile.down .rail{background:var(--down);} .tile.accent .rail{background:var(--accent);}

  .board-head{display:flex;align-items:baseline;justify-content:space-between;margin:0 2px 12px;}
  .board-head h2{margin:0;font-size:15px;font-weight:650;letter-spacing:-.01em;}
  .board-head .hint{font-size:12px;color:var(--faint);}

  /* server cards */
  .cards{display:flex;flex-direction:column;gap:12px;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
       padding:15px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden;
       transition:border-color .15s,transform .15s,box-shadow .15s;}
  .card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--pending);opacity:.9;}
  .card.up::before{background:var(--up);} .card.degraded::before{background:var(--degraded);}
  .card.down::before{background:var(--down);} .card.pending::before{background:var(--faint);}
  .card:hover{border-color:var(--border-strong);transform:translateY(-1px);box-shadow:var(--shadow-lg);}
  /* card = 3 stacked rows: header (name/status), heartbeat, footer (meta/actions) */
  .chead{display:flex;align-items:center;gap:10px;}
  .sdot{width:10px;height:10px;border-radius:50%;flex:none;}
  .sdot.up{background:var(--up);box-shadow:0 0 0 4px color-mix(in srgb,var(--up) 22%,transparent);}
  .sdot.degraded{background:var(--degraded);box-shadow:0 0 0 4px color-mix(in srgb,var(--degraded) 22%,transparent);}
  .sdot.down{background:var(--down);box-shadow:0 0 0 4px color-mix(in srgb,var(--down) 22%,transparent);}
  .sdot.pending{background:var(--faint);}
  .cname{font-weight:650;font-size:14.5px;flex:1 1 auto;min-width:0;white-space:nowrap;
       overflow:hidden;text-overflow:ellipsis;}
  .cname .paused{color:var(--faint);font-weight:500;font-size:12px;margin-left:6px;}
  .tport{font-family:var(--mono);font-size:10px;color:var(--accent-strong);background:var(--accent-soft);
       padding:2px 7px;border-radius:5px;text-transform:uppercase;letter-spacing:.03em;flex:none;}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 11px 4px 9px;border-radius:999px;
       font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex:none;}
  .pill .d{width:6px;height:6px;border-radius:50%;background:currentColor;}
  .pill.up{color:var(--up);background:color-mix(in srgb,var(--up) 13%,transparent);}
  .pill.degraded{color:var(--degraded);background:color-mix(in srgb,var(--degraded) 15%,transparent);}
  .pill.down{color:var(--down);background:color-mix(in srgb,var(--down) 13%,transparent);}
  .pill.pending{color:var(--pending);background:color-mix(in srgb,var(--pending) 14%,transparent);}
  .lat{font-weight:700;font-size:14px;flex:none;min-width:56px;text-align:right;}

  .heartbeat{display:flex;gap:2px;align-items:center;height:30px;width:100%;margin-top:12px;overflow:hidden;}
  .hb{flex:1 1 0;min-width:2px;height:26px;border-radius:2px;}
  .hb.empty{background:var(--border);opacity:.55;height:13px;}

  .cfoot{display:flex;align-items:center;justify-content:space-between;gap:8px 16px;flex-wrap:wrap;
       margin-top:12px;padding-top:11px;border-top:1px dashed var(--border);}
  .meta{display:flex;flex-wrap:wrap;gap:4px 15px;font-size:12px;color:var(--muted);min-width:0;}
  .meta b{color:var(--text);font-weight:600;}
  .target,.spec{font-family:var(--mono);}
  .spec .unk{font-family:var(--sans);color:var(--degraded);}
  .detail{color:var(--down);}
  .acts{display:flex;gap:2px;flex:none;}
  .act{border:none;background:none;font:inherit;font-size:12.5px;cursor:pointer;color:var(--muted);
       padding:5px 9px;border-radius:7px;transition:all .12s;}
  .act:hover{background:var(--surface-2);color:var(--accent-strong);}
  .act.danger{color:var(--down);opacity:.8;}
  .act.danger:hover{background:color-mix(in srgb,var(--down) 12%,transparent);opacity:1;}
  .act:focus-visible{outline:2px solid var(--accent);outline-offset:1px;}
  .empty{background:var(--surface);border:1px dashed var(--border-strong);border-radius:var(--r);
       padding:44px 20px;text-align:center;color:var(--muted);}
  .empty .big{font-size:34px;margin-bottom:8px;}

  /* modal */
  .overlay{position:fixed;inset:0;background:color-mix(in srgb,#04070d 55%,transparent);
       backdrop-filter:blur(3px);display:none;align-items:flex-start;justify-content:center;
       padding:7vh 16px 16px;z-index:50;}
  .overlay.open{display:flex;animation:fade .16s ease;}
  @keyframes fade{from{opacity:0}to{opacity:1}}
  .modal{background:var(--elev);border:1px solid var(--border);border-radius:16px;width:min(560px,96vw);
       padding:24px 26px;box-shadow:var(--shadow-lg);max-height:86vh;overflow:auto;}
  .modal.wide{width:min(680px,96vw);}
  .modal h2{margin:0 0 3px;font-size:18px;letter-spacing:-.01em;}
  .modal .lead{color:var(--muted);font-size:13px;margin:0 0 18px;}
  .field{margin-bottom:13px;}
  .field label{display:block;font-size:12.5px;font-weight:600;margin-bottom:5px;}
  .field label code{font-family:var(--mono);font-size:11px;background:var(--surface-2);padding:1px 5px;border-radius:4px;}
  .field input,.field select,.field textarea{width:100%;padding:9px 12px;border:1px solid var(--border-strong);
       border-radius:9px;font:inherit;font-size:13.5px;background:var(--surface-2);color:var(--text);
       transition:border-color .12s,box-shadow .12s;}
  .field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:var(--accent);
       box-shadow:0 0 0 3px var(--accent-soft);}
  .field textarea{font-family:var(--mono);font-size:12.5px;resize:vertical;}
  .row2{display:flex;gap:12px;} .row2>*{flex:1;}
  .buttons{display:flex;justify-content:flex-end;gap:10px;margin-top:10px;}
  .err{color:var(--down);font-size:13px;min-height:18px;margin-top:6px;}
  .ranges{display:flex;gap:4px;margin-bottom:14px;background:var(--surface-2);padding:3px;border-radius:9px;width:max-content;}
  .ranges .rbtn{border:none;background:none;font:inherit;font-size:12.5px;font-weight:600;color:var(--muted);
       padding:5px 12px;border-radius:7px;cursor:pointer;}
  .ranges .rbtn.on,.ranges .rbtn:hover{background:var(--surface);color:var(--accent-strong);box-shadow:var(--shadow);}
  .stats{display:flex;gap:24px;margin-bottom:16px;flex-wrap:wrap;}
  .stats .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;}
  .stats .v{font-size:20px;font-weight:750;letter-spacing:-.02em;}
  .clabel{font-size:11px;color:var(--muted);margin:12px 0 4px;text-transform:uppercase;letter-spacing:.04em;}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="logo">🛰️</div>
    <div><h1>mcpsonar</h1><div class="live"><span class="ping"></span><span id="sub">connecting…</span></div></div>
  </div>
  <span class="whoami" id="whoami"></span>
  <button class="btn icon" id="themeBtn" title="Toggle theme" onclick="toggleTheme()">🌙</button>
  <button class="btn" onclick="location.href='/api/export'">Export</button>
  <button class="btn" onclick="openImport()">Import</button>
  <button class="btn primary" onclick="openForm()">＋ Add server</button>
  <button class="btn" id="logoutBtn" style="display:none" onclick="logout()">Logout</button>
</div>

<main>
  <div class="summary" id="summary"></div>
  <div class="board-head"><h2>Monitored servers</h2><span class="hint">auto-refresh · 5s</span></div>
  <div class="cards" id="rows"><div class="empty">Loading…</div></div>
</main>

<div class="overlay" id="overlay">
  <div class="modal">
    <h2 id="formTitle">Add server</h2>
    <p class="lead">Adding a server starts checking it immediately — no restart.</p>
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
      <button class="btn" onclick="closeForm()">Cancel</button>
      <button class="btn primary" onclick="saveForm()">Save server</button>
    </div>
  </div>
</div>

<div class="overlay" id="histOverlay">
  <div class="modal wide">
    <h2 id="histTitle">History</h2>
    <div class="ranges" style="margin-top:14px">
      <button class="rbtn" onclick="loadHistory(60,this)">1h</button>
      <button class="rbtn on" onclick="loadHistory(360,this)">6h</button>
      <button class="rbtn" onclick="loadHistory(1440,this)">24h</button>
      <button class="rbtn" onclick="loadHistory(null,this)">All</button>
    </div>
    <div id="histBody"><p class="muted">Loading…</p></div>
    <div class="buttons"><button class="btn" onclick="closeHistory()">Close</button></div>
  </div>
</div>

<div class="overlay" id="importOverlay">
  <div class="modal">
    <h2>Import servers</h2>
    <p class="lead">Paste a YAML config or choose a file — each server is created and started.</p>
    <div class="field">
      <input type="file" id="importFile" accept=".yaml,.yml" onchange="loadFile(event)">
    </div>
    <div class="field">
      <textarea id="importText" rows="10"
        placeholder="servers:&#10;  my-server:&#10;    url: https://example.com/mcp"></textarea>
    </div>
    <div class="err" id="importErr"></div>
    <div class="buttons">
      <button class="btn" onclick="closeImport()">Cancel</button>
      <button class="btn primary" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const sc = s => css(s==="up"?"--up":s==="degraded"?"--degraded":s==="down"?"--down":"--pending");

/* theme */
function applyTheme(t){ if(t){document.documentElement.setAttribute("data-theme",t);}
  else{document.documentElement.removeAttribute("data-theme");}
  const dark = (t||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light"))==="dark";
  $("themeBtn").textContent = dark ? "☀️" : "🌙"; }
function toggleTheme(){ const cur=localStorage.getItem("mcpsonar-theme");
  const dark=(cur||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light"))==="dark";
  const next=dark?"light":"dark"; localStorage.setItem("mcpsonar-theme",next); applyTheme(next); }
applyTheme(localStorage.getItem("mcpsonar-theme"));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"]="application/json"; opt.body=JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) { let d; try { d = await r.json(); } catch(e){}
    throw new Error(d && d.detail ? JSON.stringify(d.detail) : (r.status+" "+r.statusText)); }
  return r.status === 204 ? null : r.json();
}

function relTime(iso){
  const d=(Date.now()-new Date(iso).getTime())/1000;
  if(d<5) return "just now"; if(d<60) return Math.floor(d)+"s ago";
  if(d<3600) return Math.floor(d/60)+"m ago"; if(d<86400) return Math.floor(d/3600)+"h ago";
  return Math.floor(d/86400)+"d ago";
}
function heartbeat(recent){
  const N=40, arr=(recent||[]).slice(-N), pad=N-arr.length;
  let bars="";
  for(let i=0;i<pad;i++) bars+='<span class="hb empty"></span>';
  arr.forEach(e=>{ bars+=`<span class="hb" style="background:${sc(e.status)}" `+
    `title="${e.status} · ${Math.round(e.latency_ms)}ms"></span>`; });
  return `<div class="heartbeat">${bars}</div>`;
}
function pill(status){ return `<span class="pill ${status}"><span class="d"></span>${status}</span>`; }

function renderSummary(list){
  const n=list.length, c={up:0,degraded:0,down:0};
  let latSum=0, latN=0;
  list.forEach(s=>{ const ev=s.event; if(ev){ if(c[ev.status]!=null)c[ev.status]++;
    if(ev.status!=="down"){latSum+=ev.latency_ms;latN++;} }});
  const avg = latN?Math.round(latSum/latN)+" ms":"—";
  const tile=(cls,k,v)=>`<div class="tile ${cls}"><span class="rail"></span><div class="k">${k}</div><div class="v num">${v}</div></div>`;
  $("summary").innerHTML =
    tile("accent","Servers",n)+tile("up","Up",c.up)+tile("degraded","Degraded",c.degraded)+
    tile("down","Down",c.down)+tile("accent","Avg latency",avg);
}

let SERVERS = {};
async function refresh() {
  let data;
  try { data = await api("GET", "/api/status"); } catch(e) { return; }
  const ids = Object.keys(data);
  const list = ids.map(id=>({id, ...data[id]}));
  SERVERS = {}; list.forEach(s=>SERVERS[s.id]=s.name);
  $("sub").textContent = ids.length ? (ids.length+" server"+(ids.length===1?"":"s")+" · Live") : "No servers yet";
  renderSummary(list);
  const tb = $("rows");
  if (!ids.length) {
    tb.innerHTML = '<div class="empty"><div class="big">🛰️</div>No servers yet.<br>Click <b>＋ Add server</b> to start monitoring an MCP.</div>';
    return;
  }
  tb.innerHTML = list.map(s => {
    const ev=s.event, status=ev?ev.status:"pending";
    const latency = ev ? Math.round(ev.latency_ms)+" ms" : "—";
    let spec = "—";
    if (ev && ev.spec_version){ spec=esc(ev.spec_version);
      if(!ev.spec_version_supported) spec+=' <span class="unk">unrecognized</span>'; }
    const tools = ev ? (ev.tools_failed+"/"+ev.tools_checked) : "—";
    const when = ev ? relTime(ev.checked_at) : "never";
    const detail = ev && ev.detail ? ` · <span class="detail">${esc(ev.detail)}</span>` : "";
    const paused = s.enabled ? "" : '<span class="paused">paused</span>';
    return `<div class="card ${status}">
      <div class="chead">
        <span class="sdot ${status}"></span>
        <span class="cname">${esc(s.name)}${paused}</span>
        <span class="tport">${esc(s.transport)}</span>
        ${pill(status)}
        <span class="lat num">${latency}</span>
      </div>
      ${heartbeat(s.recent)}
      <div class="cfoot">
        <div class="meta">
          <span class="target">${esc(s.target)}</span>
          <span class="spec">spec ${spec}</span>
          <span>tools <b>${tools}</b></span>
          <span>checked <b>${when}</b>${detail}</span>
        </div>
        <div class="acts">
          <button class="act" onclick="openHistory('${s.id}')">History</button>
          <button class="act" onclick="checkNow('${s.id}')">Check</button>
          <button class="act" onclick="editServer('${s.id}')">Edit</button>
          <button class="act" onclick="togglePause('${s.id}',${s.enabled})">${s.enabled?"Pause":"Resume"}</button>
          <button class="act danger" onclick="del('${s.id}')">Delete</button>
        </div>
      </div>
    </div>`;
  }).join("");
}

/* form */
function onTransport(){
  const stdio = $("f_transport").value === "stdio";
  $("grpStdio").style.display = stdio ? "" : "none";
  $("grpHttp").style.display  = stdio ? "none" : "";
}
function parseLines(text, sep){
  const out={};
  text.split("\n").map(l=>l.trim()).filter(Boolean).forEach(l=>{
    const i=l.indexOf(sep); if(i<0) return;
    out[l.slice(0,i).trim()]=l.slice(i+sep.length).trim();
  });
  return out;
}
function dumpLines(obj, sep){ return Object.entries(obj||{}).map(([k,v])=>k+sep+v).join("\n"); }

function openForm() {
  $("formTitle").textContent = "Add server";
  ["f_id","f_name","f_url","f_headers","f_command","f_args","f_env","f_tools"].forEach(i=>$(i).value="");
  $("f_transport").value="http"; onTransport();
  $("f_interval").value=60; $("f_deg").value=2000; $("f_down").value=10000;
  $("formErr").textContent=""; $("overlay").classList.add("open");
}
function closeForm(){ $("overlay").classList.remove("open"); }

async function editServer(id) {
  const s = await api("GET", "/api/servers/"+id);
  $("formTitle").textContent = "Edit server";
  $("f_id").value=s.id; $("f_name").value=s.name;
  $("f_transport").value=s.transport; onTransport();
  $("f_url").value=s.url||""; $("f_headers").value=dumpLines(s.headers, ": ");
  $("f_command").value=s.command||""; $("f_args").value=(s.args||[]).join(" ");
  $("f_env").value=dumpLines(s.env, "=");
  $("f_interval").value=s.check_interval_seconds;
  $("f_tools").value=(s.tools_to_test||[]).map(t=>t.name).join(", ");
  $("f_deg").value=s.thresholds.latency_degraded_ms; $("f_down").value=s.thresholds.latency_down_ms;
  $("formErr").textContent=""; $("overlay").classList.add("open");
}

function formPayload(enabled) {
  const transport = $("f_transport").value;
  const tools = $("f_tools").value.split(",").map(t=>t.trim()).filter(Boolean);
  const p = { name:$("f_name").value.trim(), enabled, transport,
    check_interval_seconds:parseInt($("f_interval").value,10), tools_to_test:tools,
    thresholds:{ latency_degraded_ms:parseFloat($("f_deg").value), latency_down_ms:parseFloat($("f_down").value) } };
  if (transport==="stdio") {
    p.command=$("f_command").value.trim();
    p.args=$("f_args").value.trim()?$("f_args").value.trim().split(/\s+/):[];
    p.env=parseLines($("f_env").value,"=");
  } else { p.url=$("f_url").value.trim(); p.headers=parseLines($("f_headers").value,": "); }
  return p;
}
async function saveForm() {
  const id=$("f_id").value;
  try {
    let cur=null; if(id) cur=await api("GET","/api/servers/"+id);
    const payload=formPayload(cur?cur.enabled:true);
    if(cur) payload.webhooks=cur.webhooks;
    if(id) await api("PUT","/api/servers/"+id,payload); else await api("POST","/api/servers",payload);
    closeForm(); refresh();
  } catch(e){ $("formErr").textContent="Error: "+e.message; }
}
async function del(id) {
  if(!confirm("Delete this server and its history?")) return;
  await api("DELETE","/api/servers/"+id); refresh();
}
async function checkNow(id){ try{ await api("POST","/api/servers/"+id+"/check"); }catch(e){} refresh(); }
async function togglePause(id, enabled) {
  const s=await api("GET","/api/servers/"+id);
  const payload=Object.assign({},s,{enabled:!enabled}); delete payload.id;
  await api("PUT","/api/servers/"+id,payload); refresh();
}

/* history */
let histId=null;
function closeHistory(){ $("histOverlay").classList.remove("open"); }
function openHistory(id){
  histId=id; $("histTitle").textContent="History · "+(SERVERS[id]||id);
  $("histOverlay").classList.add("open"); loadHistory(360);
}
async function loadHistory(minutes, btn){
  if(btn){ document.querySelectorAll("#histOverlay .rbtn").forEach(b=>b.classList.remove("on")); btn.classList.add("on"); }
  const q=minutes?("?minutes="+minutes):"";
  let hist;
  try{ hist=await api("GET","/api/servers/"+histId+"/history"+q); }
  catch(e){ $("histBody").innerHTML='<p class="detail">'+esc(e.message)+'</p>'; return; }
  $("histBody").innerHTML=renderCharts(hist);
}
function renderCharts(hist){
  if(!hist.length) return '<p class="muted">No checks recorded in this window yet.</p>';
  const n=hist.length, ups=hist.filter(e=>e.status==="up").length;
  const uptime=(100*ups/n).toFixed(1);
  const oks=hist.filter(e=>e.status!=="down");
  const avg=oks.length?Math.round(oks.reduce((a,e)=>a+e.latency_ms,0)/oks.length):0;
  const last=hist[n-1], accent=sc(last.status), grid=css("--border-strong"), muted=css("--muted");
  const W=620,H=150,pad=28;
  const lat=hist.map(e=>e.latency_ms), maxL=Math.max(50,...lat);
  const X=i=>pad+(n===1?(W-2*pad)/2:i*(W-2*pad)/(n-1));
  const Y=v=>H-pad-(v/maxL)*(H-2*pad);
  const line=lat.map((v,i)=>(i?"L":"M")+X(i).toFixed(1)+" "+Y(v).toFixed(1)).join(" ");
  const area=line+` L ${X(n-1).toFixed(1)} ${H-pad} L ${X(0).toFixed(1)} ${H-pad} Z`;
  const dots=hist.map((e,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(e.latency_ms).toFixed(1)}" r="2.4" fill="${sc(e.status)}"/>`).join("");
  const gy=v=>`<line x1="${pad}" y1="${Y(v).toFixed(1)}" x2="${W-pad}" y2="${Y(v).toFixed(1)}" stroke="${grid}" stroke-dasharray="3 4"/>`+
    `<text x="4" y="${(Y(v)+3).toFixed(1)}" font-size="9" fill="${muted}">${Math.round(v)}</text>`;
  const sw=(W-2*pad)/n;
  const strip=hist.map((e,i)=>`<rect x="${(pad+i*sw).toFixed(1)}" y="0" width="${Math.max(1.2,sw-1).toFixed(1)}" height="14" rx="1.5" fill="${sc(e.status)}"/>`).join("");
  return `
    <div class="stats">
      <div><div class="k">Uptime</div><div class="v num">${uptime}%</div></div>
      <div><div class="k">Avg latency</div><div class="v num">${avg} ms</div></div>
      <div><div class="k">Checks</div><div class="v num">${n}</div></div>
      <div><div class="k">Now</div><div style="margin-top:4px">${pill(last.status)}</div></div>
    </div>
    <div class="clabel">Latency (ms)</div>
    <svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block">
      ${gy(maxL)}${gy(maxL/2)}
      <path d="${area}" fill="${accent}" fill-opacity="0.13"/>
      <path d="${line}" fill="none" stroke="${accent}" stroke-width="1.8"/>
      ${dots}
    </svg>
    <div class="clabel">Status timeline (oldest → newest)</div>
    <svg viewBox="0 0 ${W} 14" width="100%" style="display:block">${strip}</svg>`;
}

/* import / export */
function closeImport(){ $("importOverlay").classList.remove("open"); }
function openImport(){ $("importText").value=""; $("importErr").textContent=""; $("importOverlay").classList.add("open"); }
function loadFile(ev){
  const f=ev.target.files[0]; if(!f) return;
  const r=new FileReader(); r.onload=()=>{ $("importText").value=r.result; }; r.readAsText(f);
}
async function doImport(){
  const text=$("importText").value;
  try{
    const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/x-yaml"},body:text});
    if(!r.ok){ const d=await r.json().catch(()=>({})); throw new Error(d.detail||r.status); }
    const res=await r.json(); closeImport(); refresh();
    alert("Imported "+res.imported+" server(s).");
  }catch(e){ $("importErr").textContent="Error: "+e.message; }
}

/* auth */
async function logout(){ await fetch("/api/auth/logout",{method:"POST"}); location.href="/login"; }
async function initAuth(){
  try{
    const s=await (await fetch("/api/auth/status")).json();
    if(s.auth_enabled){
      $("logoutBtn").style.display="";
      if(s.username){ $("whoami").innerHTML='<span class="av">'+esc(s.username[0])+'</span>'+esc(s.username); }
    }
  }catch(e){}
}

/* close modals on overlay click / Escape */
document.querySelectorAll(".overlay").forEach(o=>o.addEventListener("mousedown",e=>{ if(e.target===o) o.classList.remove("open"); }));
document.addEventListener("keydown",e=>{ if(e.key==="Escape") document.querySelectorAll(".overlay.open").forEach(o=>o.classList.remove("open")); });

initAuth();
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""

"""The MCPSonar Trust Report: what was observed about one MCP server, or a fleet, over a
window of time, in one self-contained file to share.

It answers the questions someone asks before relying on a server:

* **Was it available?** Share of checks it answered, incidents, the longest one, latency.
* **Did its tools change?** The pinned definitions with their fingerprints, every change in
  the window, and whether a person reviewed it: who approved it and when (audit log).
* **Do its tools look suspicious?** Findings of the lint rules on the current definitions,
  labeled as what they are: heuristics.

It is a record of observations, **not a certification**: no score, no "safe" verdict.

``build`` gathers the data (also served as JSON); ``render_html`` writes a page with no
script and no external resource, styled for printing ("Save as PDF" in any browser).
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any

from . import __version__
from .incidents import incidents
from .lint import RULES, SEVERITY_ORDER, lint_tool
from .models import MonitoredServer, TransportType
from .notify import clean
from .redact import redact_url
from .storage import Storage
from .tooldefs import fingerprint

DISCLAIMER = (
    "This report summarizes what MCPSonar observed. It is not a security certification: "
    "findings are heuristic matches on tool-definition text, reasons for a person to look, "
    "not proof of malicious behavior."
)


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]


def _parse(ts: str) -> datetime:
    value = datetime.fromisoformat(ts)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _target(server: MonitoredServer) -> str:
    if server.transport == TransportType.STDIO:
        return f"stdio: {server.command}"  # never the arguments: they may carry keys
    return redact_url(server.url) or ""


async def _server_section(storage: Storage, server: MonitoredServer, since: datetime,
                          now: datetime) -> dict[str, Any]:
    rows = await storage.status_rows(server.id, since)
    checks = len(rows)
    up = [r["latency_ms"] for r in rows if r["status"] != "down"]
    incs = incidents(rows)
    for inc in incs:
        end = _parse(inc["recovered"]) if inc["recovered"] else now
        inc["duration_s"] = round((end - _parse(inc["started"])).total_seconds())
    anomalies = Counter(a["kind"] for r in rows for a in r["anomalies"] if not a.get("ongoing"))
    anomalies.pop("tool_change", None)  # reported with the changes, below

    snapshot = await storage.get_tool_snapshot(server.id) or {}
    tools = []
    for name, definition in sorted(snapshot.items()):
        findings = lint_tool(definition)
        tools.append({
            "name": name,
            "sha256": fingerprint(definition),
            "findings": [{"rule": f.rule, "severity": f.severity, "message": f.message,
                          "location": f.location,
                          "confidence": RULES[f.rule].confidence if f.rule in RULES else None}
                         for f in findings],
        })

    approvals = await storage.list_audit_for(server.id, "tool_changes.approved")
    changes = []
    for change in await storage.list_tool_changes(server.id, include_reviewed=True, limit=10_000):
        if _parse(change["detected_at"]) < since:
            continue
        approval = next(
            (a for a in approvals if _parse(a["at"]) >= _parse(change["detected_at"])
             and any(c.get("tool") == change["tool"] and c.get("kind") == change["kind"]
                     for c in (a["detail"] or {}).get("changes", []))),
            None)
        changes.append({
            "detected_at": change["detected_at"], "kind": change["kind"],
            "tool": change["tool"], "fields": change["fields"],
            "reviewed": change["reviewed"],
            "approved_by": approval["actor"] if approval else None,
            "approved_at": approval["at"] if approval else None,
        })
    changes.reverse()  # oldest first, like the rest of the report

    severities = Counter(f["severity"] for t in tools for f in t["findings"])
    pending = sum(1 for c in changes if not c["reviewed"])
    return {
        "id": server.id,
        "name": server.name,
        "transport": server.transport.value,
        "target": _target(server),
        "enabled": server.enabled,
        "status": rows[-1]["status"] if rows else None,
        "last_check": rows[-1]["checked_at"] if rows else None,
        "data_from": rows[0]["checked_at"] if rows else None,
        "availability": {
            "checks": checks,
            "answered_pct": round(100 * len(up) / checks, 2) if checks else None,
            "incidents": len(incs),
            "time_not_up_s": sum(i["duration_s"] for i in incs),
            "longest_incident_s": max((i["duration_s"] for i in incs), default=0),
            "latency_p50_ms": round(median(up), 1) if up else None,
            "latency_p95_ms": round(_percentile(up, 0.95), 1) if up else None,
        },
        "incidents": incs,
        "anomalies": dict(sorted(anomalies.items())),
        "tools": {"pinned_since": await storage.tool_baseline_since(server.id),
                  "count": len(tools), "definitions": tools},
        "changes": changes,
        "summary": {"pending_changes": pending,
                    "findings": {k: severities.get(k, 0) for k in SEVERITY_ORDER}},
    }


async def build(storage: Storage, server_ids: list[str] | None = None, days: float = 30,
                now: datetime | None = None) -> dict[str, Any]:
    """The report's data, for every server or the given ones (KeyError for an unknown id)."""
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days)
    servers = await storage.list_servers()
    if server_ids:
        known = {s.id: s for s in servers}
        missing = [i for i in server_ids if i not in known]
        if missing:
            raise KeyError(", ".join(missing))
        servers = [known[i] for i in server_ids]
    return {
        "kind": "trust_report",
        "generated_at": now.isoformat(),
        "mcpsonar_version": __version__,
        "window": {"days": days, "from": since.isoformat(), "to": now.isoformat()},
        "disclaimer": DISCLAIMER,
        "servers": [await _server_section(storage, s, since, now) for s in servers],
    }


# ---- HTML ---------------------------------------------------------------------------- #
def _e(text: Any) -> str:
    """Escaped, and for server-supplied text cleaned of invisible characters."""
    return html.escape(clean(str(text), 400) if text is not None else "")


def _when(ts: str | None) -> str:
    return _parse(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else "—"


def _dur(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} s"
    minutes = round(seconds / 60)
    if minutes < 90:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if hours < 48 else f"{hours // 24} d {hours % 24} h"


def _signals(s: dict) -> list[tuple[str, str]]:
    """(class, text) observations for the top of a server's section; never a verdict."""
    out = []
    a = s["availability"]
    if a["checks"]:
        out.append(("ok" if a["answered_pct"] >= 99 else "warn",
                    f"Answered {a['answered_pct']}% of {a['checks']} checks"))
    else:
        out.append(("warn", "No checks in this window"))
    pending = s["summary"]["pending_changes"]
    out.append(("ok", "Every tool change in the window was reviewed") if not pending else
                ("bad", f"{pending} tool change(s) not reviewed yet"))
    high = s["summary"]["findings"].get("high", 0)
    out.append(("ok", "No high-severity findings on the current tools") if not high else
                ("bad", f"{high} high-severity finding(s) on the current tools (heuristic)"))
    return out


def _server_html(s: dict) -> str:
    a = s["availability"]
    parts = [f'<section class="server"><h2>{_e(s["name"])}</h2>',
             f'<p class="meta">{_e(s["target"])} · {_e(s["transport"])} · current status '
             f'<b>{_e(s["status"] or "unknown")}</b> · last check {_when(s["last_check"])}'
             + ("" if s["enabled"] else " · <b>paused</b>") + "</p>",
             '<ul class="signals">' + "".join(
                 f'<li class="{c}">{html.escape(t)}</li>' for c, t in _signals(s)) + "</ul>"]
    if s["data_from"]:
        parts.append(f'<p class="meta">Data in this window starts {_when(s["data_from"])} '
                     "(history older than the retention period is not kept).</p>")

    parts.append("<h3>Availability</h3><table><tr><th>Checks</th><th>Answered</th>"
                 "<th>Incidents</th><th>Time not up</th><th>Longest incident</th>"
                 "<th>Latency p50</th><th>Latency p95</th></tr><tr>"
                 f'<td>{a["checks"]}</td><td>{a["answered_pct"] if a["answered_pct"] is not None else "—"}%</td>'
                 f'<td>{a["incidents"]}</td><td>{_dur(a["time_not_up_s"])}</td>'
                 f'<td>{_dur(a["longest_incident_s"])}</td>'
                 f'<td>{a["latency_p50_ms"] if a["latency_p50_ms"] is not None else "—"} ms</td>'
                 f'<td>{a["latency_p95_ms"] if a["latency_p95_ms"] is not None else "—"} ms</td></tr></table>')
    if s["incidents"]:
        rows = "".join(
            f'<tr><td>{_when(i["started"])}</td><td>{_e(i["worst"])}</td>'
            f'<td>{_dur(i["duration_s"])}{"" if i["recovered"] else " (ongoing)"}</td>'
            f'<td>{_e(i["detail"] or "")}</td></tr>' for i in s["incidents"][-20:])
        more = len(s["incidents"]) - 20
        parts.append("<h3>Incidents</h3><table><tr><th>Started</th><th>Worst</th>"
                     f"<th>Duration</th><th>Reason</th></tr>{rows}</table>"
                     + (f'<p class="meta">… and {more} earlier.</p>' if more > 0 else ""))
    if s["anomalies"]:
        parts.append("<h3>Anomalies</h3><p>" + " · ".join(
            f"{_e(k.replace('_', ' '))}: {v}" for k, v in s["anomalies"].items()) + "</p>")

    t = s["tools"]
    parts.append(f'<h3>Tool definitions</h3><p class="meta">{t["count"]} tool(s) pinned'
                 + (f' since {_when(t["pinned_since"])}' if t["pinned_since"] else "")
                 + ". The fingerprint is the SHA-256 of the normalized definition; any change "
                 "to it is recorded below.</p>")
    if t["definitions"]:
        rows = "".join(
            f'<tr><td>{_e(d["name"])}</td><td class="mono">{d["sha256"][:16]}…</td><td>'
            + ("<br>".join(f'<span class="sev {f["severity"]}">{f["severity"]}</span> '
                           f'{_e(f["rule"])}' for f in d["findings"]) or "none")
            + "</td></tr>" for d in t["definitions"])
        parts.append("<table><tr><th>Tool</th><th>Fingerprint</th>"
                     f"<th>Findings (heuristic)</th></tr>{rows}</table>")

    parts.append("<h3>Tool changes in this window</h3>")
    if s["changes"]:
        rows = "".join(
            f'<tr><td>{_when(c["detected_at"])}</td><td>{_e(c["kind"])} '
            f'<b>{_e(c["tool"])}</b>' + (f' ({_e(", ".join(c["fields"]))})' if c["fields"] else "")
            + "</td><td>"
            + (f'approved by {_e(c["approved_by"])} · {_when(c["approved_at"])}'
               if c["approved_by"] else
               "reviewed (before the audit log existed)" if c["reviewed"] else
               '<b class="bad">not reviewed</b>')
            + "</td></tr>" for c in s["changes"])
        parts.append("<table><tr><th>Detected</th><th>Change</th><th>Review</th></tr>"
                     f"{rows}</table>")
    else:
        parts.append("<p>None: the tools matched their pinned definitions throughout.</p>")
    parts.append("</section>")
    return "".join(parts)


def render_html(report: dict) -> str:
    servers = report["servers"]
    title = (f"Trust report · {servers[0]['name']}" if len(servers) == 1
             else f"Trust report · {len(servers)} servers")
    fleet = ""
    if len(servers) > 1:
        rows = "".join(
            f'<tr><td>{_e(s["name"])}</td><td>{_e(s["status"] or "unknown")}</td>'
            f'<td>{s["availability"]["answered_pct"] if s["availability"]["answered_pct"] is not None else "—"}%</td>'
            f'<td>{s["availability"]["incidents"]}</td><td>{s["summary"]["pending_changes"]}</td>'
            f'<td>{s["summary"]["findings"]["high"]} / {s["summary"]["findings"]["medium"]}</td></tr>'
            for s in servers)
        fleet = ("<h2>Fleet</h2><table><tr><th>Server</th><th>Status</th><th>Answered</th>"
                 "<th>Incidents</th><th>Unreviewed changes</th><th>Findings high / medium</th>"
                 f"</tr>{rows}</table>")
    w = report["window"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root{{--text:#0e1a2b;--muted:#5b6b83;--border:#d2dbe8;--ok:#15803d;--warn:#b45309;--bad:#c81e1e;}}
  body{{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--text);
    background:#fff;max-width:900px;margin:32px auto;padding:0 20px;}}
  h1{{font-size:24px;margin:0 0 4px;}} h2{{font-size:19px;margin:28px 0 4px;}}
  h3{{font-size:14px;margin:18px 0 6px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);}}
  .meta{{color:var(--muted);font-size:12.5px;margin:2px 0;overflow-wrap:anywhere;}}
  table{{border-collapse:collapse;width:100%;font-size:12.5px;margin:4px 0;}}
  th,td{{border-bottom:1px solid var(--border);padding:5px 8px;text-align:left;vertical-align:top;
    overflow-wrap:anywhere;}}
  th{{font-weight:600;color:var(--muted);}}
  .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;}}
  .signals{{list-style:none;padding:0;margin:10px 0;}}
  .signals li{{padding:3px 0 3px 22px;position:relative;}}
  .signals li::before{{position:absolute;left:0;font-weight:700;}}
  .signals .ok::before{{content:"✓";color:var(--ok);}} .signals .warn::before{{content:"!";color:var(--warn);}}
  .signals .bad::before{{content:"✗";color:var(--bad);}}
  .bad{{color:var(--bad);}}
  .sev{{font-size:11px;font-weight:700;text-transform:uppercase;}}
  .sev.high{{color:var(--bad);}} .sev.medium{{color:var(--warn);}} .sev.low{{color:var(--muted);}}
  .note{{border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--muted);
    font-size:12.5px;margin:16px 0;}}
  section.server{{border-top:2px solid var(--text);margin-top:28px;}}
  @media print{{ body{{margin:0;max-width:none;}} section.server{{break-before:page;}}
    section.server:first-of-type{{break-before:auto;}} a{{color:inherit;}} }}
</style></head><body>
<h1>{_e(title)}</h1>
<p class="meta">From {_when(w["from"])} to {_when(w["to"])} ({_e(w["days"])} days) · generated
 {_when(report["generated_at"])} by MCPSonar {_e(report["mcpsonar_version"])}</p>
<p class="note">{html.escape(report["disclaimer"])} The rules, their limits and measured false
 positives are documented in MCPSonar's detection-rules.md.</p>
{fleet}
{"".join(_server_html(s) for s in servers) or "<p>No servers.</p>"}
</body></html>
"""

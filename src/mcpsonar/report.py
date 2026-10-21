"""Reports: one document from one or more scan results, as JSON, Markdown or SARIF 2.1.0.

The data comes from :class:`mcpsonar.scan.ScanResult` — the same inspection, lint and
lockfile comparison as ``mcpsonar scan`` — so a report never disagrees with a scan.

SARIF notes (for GitHub code scanning and other SARIF consumers):

* every lint rule is a SARIF rule with its stable ID, help text, severity
  (``security-severity`` and the default ``level``), ``precision`` (the rule's confidence)
  and its OWASP MCP Top 10 categories as tags; lockfile drift is the extra rule
  ``tool-definition-changed``;
* results carry ``partialFingerprints`` so a consumer can follow the same alert across runs;
* tool definitions are not files: a result points at the tool's entry in the **lockfile**
  when one is given (``--lock``), which is what GitHub needs to show the alert on a line.
  Without a lockfile, results only carry a logical location (``server/tool/field``).

Reports contain rule IDs, short evidence excerpts and tool names — never credentials (target
labels are already redacted) and never tool responses.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .lint import OWASP_MCP, RULES, SEVERITY_ORDER, Finding
from .scan import ScanResult

REPO_URL = "https://github.com/alefra93/MCPSonar"
RULES_DOC = f"{REPO_URL}/blob/main/docs/detection-rules.md"
DISCLAIMER = (
    "Findings are heuristic matches on tool-definition text: reasons for a human to review "
    "a tool, not proof of malicious behavior."
)
DRIFT_RULE = "tool-definition-changed"
_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}  # GitHub's scale


def finding_details(f: Finding) -> dict[str, Any]:
    """A finding plus its rule's documentation: what ``risks --json`` and reports emit."""
    info = RULES.get(f.rule)
    return {
        **f.to_dict(),
        "evidence": f.excerpt,
        "title": info.title if info else f.rule,
        "confidence": info.confidence if info else None,
        "owasp": list(info.owasp) if info else [],
        "explanation": info.explanation if info else f.message,
        "remediation": info.remediation if info else None,
    }


def build(results: list[tuple[ScanResult, str | None]]) -> dict[str, Any]:
    """The JSON report. ``results`` pairs each scan result with its lockfile path, if any."""
    targets = []
    for r, lock in results:
        targets.append({
            "target": r.target,
            "server": {"name": r.server_name, "version": r.server_version},
            "spec_version": r.spec_version,
            "error": r.error,
            "tools": sorted(r.tools),
            "findings": [finding_details(f) for f in r.findings],
            "lockfile": lock,
            "changes": None if r.changes is None else [
                {"kind": c.kind, "tool": c.tool, "fields": c.fields} for c in r.changes
            ],
        })
    findings = [f for r, _ in results for f in r.findings]
    return {
        "kind": "report",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "mcpsonar": __version__,
        "disclaimer": DISCLAIMER,
        "summary": {
            "targets": len(results),
            "unreachable": sum(1 for r, _ in results if r.error),
            "tools": sum(len(r.tools) for r, _ in results),
            "findings": {sev: sum(1 for f in findings if f.severity == sev)
                         for sev in SEVERITY_ORDER},
            "tool_changes": sum(len(r.changes or []) for r, _ in results),
        },
        "targets": targets,
    }


# ---- Markdown ---------------------------------------------------------------- #
def _md_escape(text: str) -> str:
    # "<IMPORTANT>" must stay visible: GitHub strips unknown HTML tags from Markdown.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    f = s["findings"]
    out = [
        "# MCPSonar report",
        "",
        f"Generated {report['generated_at']} by MCPSonar {report['mcpsonar']}.",
        "",
        (f"**{s['targets']}** server(s) · **{s['tools']}** tools · findings: "
        f"**{f['high']}** high, **{f['medium']}** medium, **{f['low']}** low · "
        f"**{s['tool_changes']}** tool change(s) vs lockfile · "
        f"**{s['unreachable']}** unreachable"),
        "",
        f"> {report['disclaimer']} Rule reference: <{RULES_DOC}>.",
        "",
    ]
    for t in report["targets"]:
        name = " ".join(filter(None, [t["server"]["name"], t["server"]["version"]])) or "?"
        out += [f"## {t['target']}", ""]
        if t["error"]:
            out += [f"**Could not be read:** {t['error']}", ""]
            continue
        out += [f"Server `{name}` · spec {t['spec_version']} · {len(t['tools'])} tools", ""]
        if t["changes"]:
            out += ["### Tool definitions changed since the lockfile", "",
                    "| Change | Tool | Fields |", "|---|---|---|"]
            out += [f"| {c['kind']} | `{_md_escape(c['tool'])}` | {', '.join(c['fields'])} |"
                    for c in t["changes"]]
            out.append("")
        elif t["changes"] == []:
            out += ["Tool definitions match the lockfile.", ""]
        if not t["findings"]:
            out += ["No findings.", ""]
            continue
        out += ["| Severity | Rule | Tool | Where | Evidence |", "|---|---|---|---|---|"]
        for x in sorted(t["findings"], key=lambda x: SEVERITY_ORDER[x["severity"]]):
            out.append(
                f"| {x['severity'].upper()} | `{x['rule']}` ({_md_escape(x['title'])}) | "
                f"`{_md_escape(x['tool'])}` | {_md_escape(x['location'])} | "
                f"{_md_escape(x['evidence'])} |"
            )
        out.append("")
        out += ["<details><summary>What to review</summary>", ""]
        for rule in dict.fromkeys(x["rule"] for x in t["findings"]):
            info = RULES.get(rule)
            if info:
                out.append(f"- **{rule}** — {_md_escape(info.explanation)} "
                           f"*Review:* {_md_escape(info.remediation)}")
        out += ["", "</details>", ""]
    return "\n".join(out).rstrip() + "\n"


# ---- SARIF ------------------------------------------------------------------- #
def _sarif_rules() -> list[dict[str, Any]]:
    rules = []
    for rule_id, info in RULES.items():
        owasp = [f"{code} {OWASP_MCP.get(code, '')}".strip() for code in info.owasp]
        rules.append({
            "id": rule_id,
            "name": "".join(w.capitalize() for w in rule_id.split("-")),
            "shortDescription": {"text": info.title},
            "fullDescription": {"text": info.explanation},
            "help": {
                "text": f"{info.remediation} {DISCLAIMER}",
                "markdown": f"{info.explanation}\n\n**Review:** {info.remediation}\n\n"
                            f"_{DISCLAIMER}_\n\nOWASP MCP Top 10: {', '.join(owasp)}.",
            },
            "helpUri": f"{RULES_DOC}#{rule_id}--"
                       + "-".join(info.title.lower().replace("/", "").split()),
            "defaultConfiguration": {"level": _LEVEL[info.severity]},
            "properties": {
                "tags": ["security", "mcp", "tool-poisoning", *info.owasp],
                "precision": info.confidence,
                "security-severity": _SECURITY_SEVERITY[info.severity],
            },
        })
    rules.append({
        "id": DRIFT_RULE,
        "name": "ToolDefinitionChanged",
        "shortDescription": {"text": "Tool definition changed since it was pinned"},
        "fullDescription": {"text": "A tool was added, removed or changed compared with the "
                                    "lockfile (possible rug pull)."},
        "help": {"text": "Review the change. If it is expected, update the lockfile with "
                         "`mcpsonar scan --update-lock`."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "mcp", "rug-pull", "MCP03", "MCP04"],
                       "precision": "very-high", "security-severity": "7.0"},
    })
    return rules


def _lock_lines(lock: str | None) -> dict[str, int]:
    """Line (1-based) of each tool's entry in a lockfile written by ``scan --lock``."""
    if not lock or not Path(lock).exists():
        return {}
    lines = Path(lock).read_text(encoding="utf-8").splitlines()
    out: dict[str, int] = {}
    in_tools = False
    for n, line in enumerate(lines, 1):
        if line.startswith('  "tools": {'):
            in_tools = True
        elif in_tools and line.startswith('    "') and line.rstrip().endswith("{"):
            out[json.loads(line.strip()[:-1].rstrip(" :"))] = n
    return out


def _repo_uri(path: str) -> str:
    """SARIF consumers (GitHub) resolve locations against the repository root, i.e. the
    working directory of a CI run: make the lockfile path relative to it when possible."""
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            pass
    return p.as_posix()


def _location(target: str, tool: str, where: str, lock: str | None,
              lines: dict[str, int]) -> dict[str, Any]:
    loc: dict[str, Any] = {"logicalLocations": [{
        "name": tool, "fullyQualifiedName": f"{target}/{tool}/{where}", "kind": "function",
    }]}
    if lock and tool in lines:
        loc["physicalLocation"] = {
            "artifactLocation": {"uri": _repo_uri(lock)},
            "region": {"startLine": lines[tool]},
        }
    return loc


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def to_sarif(results: list[tuple[ScanResult, str | None]]) -> dict[str, Any]:
    rules = _sarif_rules()
    index = {r["id"]: i for i, r in enumerate(rules)}
    sarif_results = []
    notifications = []
    for r, lock in results:
        lines = _lock_lines(lock)
        if r.error:
            notifications.append({"level": "error",
                                  "message": {"text": f"{r.target}: {r.error}"}})
            continue
        for f in r.findings:
            sarif_results.append({
                "ruleId": f.rule,
                "ruleIndex": index[f.rule],
                "level": _LEVEL[f.severity],
                "message": {"text": f"Tool '{f.tool}' ({f.location}): {f.message}. "
                                    f"Evidence: {f.excerpt}"},
                "locations": [_location(r.target, f.tool, f.location, lock, lines)],
                "partialFingerprints": {
                    "mcpsonarFinding/v1": _fingerprint(r.target, f.tool, f.rule, f.location)
                },
                "properties": {"server": r.server_name, "target": r.target,
                               "evidence": f.excerpt},
            })
        for c in r.changes or []:
            what = f"{', '.join(c.fields)} changed" if c.kind == "changed" else c.kind
            sarif_results.append({
                "ruleId": DRIFT_RULE,
                "ruleIndex": index[DRIFT_RULE],
                "level": "error",
                "message": {"text": f"Tool '{c.tool}' {what} since it was pinned in "
                                    f"{lock}. Review it before trusting the new definition."},
                "locations": [_location(r.target, c.tool, "definition", lock, lines)],
                "partialFingerprints": {
                    "mcpsonarDrift/v1": _fingerprint(r.target, c.tool, c.kind, *c.fields)
                },
            })
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "MCPSonar",
            "semanticVersion": __version__,
            "informationUri": REPO_URL,
            "rules": rules,
        }},
        "results": sarif_results,
        "invocations": [{
            "executionSuccessful": not notifications,
            "toolExecutionNotifications": notifications,
        }],
        "properties": {"disclaimer": DISCLAIMER},
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

"""``mcpsonar report``: one document for one server or every server of a config file.

Markdown for people (an issue, a PR comment, an e-mail to whoever owns the servers), JSON for
scripts, SARIF 2.1.0 for GitHub code scanning and other SARIF tools. Built on the same scan as
``mcpsonar scan`` (see :mod:`mcpsonar.report`). Read-only: it never writes a lockfile.

Exit codes: 0 · 1 findings at/above ``--fail-on`` or lockfile drift · 2 a server could not be
read (the report is still written, with the error in it).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .. import report as rep
from ..lint import SEVERITY_ORDER
from ..loader import ConfigError, load_config
from ..output import EXIT_ERROR, EXIT_FAILED, EXIT_OK, Output
from ..scan import ScanResult, read_lock, scan
from ..tooldefs import diff_tools
from ._target import TargetError, add_target_args, resolve_target


def register(sub: Any) -> None:
    p = sub.add_parser(
        "report",
        help="Security report of one server, or every server in --config (md/json/sarif).",
        description="Inspect the server(s), lint every tool and (with --lock) compare with a "
        "lockfile, then write one report. With --config and no TARGET, every server in the "
        "file is included. " + rep.DISCLAIMER,
    )
    add_target_args(p)
    p.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown",
                   help="Report format (default: markdown).")
    p.add_argument("-o", "--output", metavar="FILE", help="Write the report here (default: "
                   "stdout).")
    p.add_argument("--lock", metavar="FILE",
                   help="Compare with this lockfile (single server only; never written). "
                   "SARIF results then point at the tool's line in it.")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never",
                   help="Exit 1 on a finding at or above this severity (default: never).")
    p.set_defaults(handler=run)


def _targets(args: Any) -> list[tuple[Any, str]]:
    if args.config and not args.target:
        try:
            config = load_config(args.config)
        except (ConfigError, ValidationError, OSError) as exc:
            raise TargetError(f"cannot use {args.config}: {exc}") from exc
        if not config.servers:
            raise TargetError(f"no servers in {args.config}")
        return [(cfg, name) for name, cfg in config.servers.items()]
    return [resolve_target(args)]


async def run(args: Any) -> int:
    out = Output()
    try:
        targets = _targets(args)
    except TargetError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if args.lock and len(targets) > 1:
        out.error("--lock compares one server; give a TARGET together with --config")
        return EXIT_ERROR
    if args.lock and not Path(args.lock).exists():
        out.error(f"lockfile {args.lock} not found (create it with `mcpsonar scan --lock`)")
        return EXIT_ERROR

    results: list[tuple[ScanResult, str | None]] = []
    for cfg, label in targets:
        result = await scan(cfg, label, timeout_s=args.timeout)
        if result.error is None and args.lock:
            result.changes = diff_tools(read_lock(Path(args.lock)), result.tools)
        results.append((result, args.lock))

    if args.format == "sarif":
        text = json.dumps(rep.to_sarif(results), indent=2, ensure_ascii=False)
    else:
        doc = rep.build(results)
        text = (json.dumps(doc, indent=2, ensure_ascii=False) if args.format == "json"
                else rep.to_markdown(doc))
    if args.output:
        Path(args.output).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
        print(f"wrote {args.output}", file=out.stderr)
    else:
        out.print(text.rstrip("\n"))

    for r, _ in results:
        if r.error:
            out.warn(f"{r.target}: {r.error}")
    if any(r.error for r, _ in results):
        return EXIT_ERROR
    drift = any(r.changes for r, _ in results)
    limit = SEVERITY_ORDER.get(args.fail_on)
    findings = limit is not None and any(
        SEVERITY_ORDER[f.severity] <= limit for r, _ in results for f in r.findings
    )
    return EXIT_FAILED if drift or findings else EXIT_OK

"""Command-line entry point.

* ``mcpsonar run``  — the monitor: opens the SQLite store, optionally seeds it from a YAML
  config on first run (when the DB has no servers yet), starts the dynamic scheduler, and
  serves the dashboard + CRUD API under uvicorn.
* ``mcpsonar scan`` — one-shot security scan of a server (tool-poisoning lint + lockfile).
* ``mcpsonar demo`` — the monitor against four scripted demo servers, no setup.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import tempfile
import webbrowser

import uvicorn

from .dashboard import create_app
from .loader import ConfigError, load_config
from .scheduler import Scheduler
from .state import StateStore
from .storage import Storage

logger = logging.getLogger("mcpsonar")


async def _seed_from_yaml_if_empty(storage: Storage, config_path: str) -> None:
    if await storage.list_servers():
        return  # DB already has servers; never overwrite from YAML
    config = load_config(config_path)
    for name, cfg in config.servers.items():
        await storage.create_server(name=name, config=cfg)
    logger.info("seeded %d server(s) from %s", len(config.servers), config_path)


async def _seed_demo(storage: Storage, servers, interval: int) -> None:
    from .models import ServerConfig

    for d in servers:
        await storage.create_server(
            name=d.name,
            config=ServerConfig(
                url=d.url,
                check_interval_seconds=interval,
                tools_to_test=[d.probe],
                thresholds={"latency_degraded_ms": 1500, "latency_down_ms": 5000},
            ),
        )


async def _serve(
    config_path: str | None,
    host: str,
    port: int,
    db_path: str,
    retention_days: float,
    require_auth: bool,
    demo_interval: int | None = None,
    open_browser: bool = False,
) -> None:
    storage = await Storage.open(db_path)
    if config_path:
        await _seed_from_yaml_if_empty(storage, config_path)

    demo_proc = None
    if demo_interval is not None:
        from .demo import demo_servers, spawn

        base = port + 26
        demo_proc = await asyncio.to_thread(spawn, base, demo_interval)
        await _seed_demo(storage, demo_servers(base, demo_interval), demo_interval)

    store = StateStore()
    scheduler = Scheduler(storage, store, retention_days=retention_days)
    await scheduler.start()

    app = create_app(storage, store, scheduler, require_auth=require_auth)
    if require_auth and not await storage.has_admin():
        logger.info("no admin yet — open the dashboard to create one (first-run setup)")

    uv_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uv_config)
    logger.info("dashboard at http://%s:%d  (db: %s)", host, port, db_path)
    if demo_proc is not None:
        url = f"http://{host}:{port}"
        logger.info("demo running at %s — watch the story unfold over ~5 minutes:", url)
        logger.info("  • calculator performs a rug pull (poisoned tool) after ~%ds",
                    25 * demo_interval)
        logger.info("  • docs-search gets permanently slower after ~%ds", 45 * demo_interval)
        logger.info("  • payments-gateway flaps; weather-api spikes now and then")
        if open_browser:
            asyncio.get_running_loop().call_later(1.5, webbrowser.open, url)
    try:
        await server.serve()
    finally:
        if demo_proc is not None:
            demo_proc.terminate()
        await scheduler.stop()
        await storage.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcpsonar")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Serve the dashboard/API and run checks.")
    run.add_argument(
        "--config",
        default=None,
        help="Optional YAML to seed the DB on first run (when it has no servers yet).",
    )
    run.add_argument(
        "--db",
        default=os.environ.get("MCPSONAR_DB", "mcpsonar.db"),
        help="SQLite database path (env MCPSONAR_DB; default ./mcpsonar.db).",
    )
    run.add_argument(
        "--retention-days",
        type=float,
        default=float(os.environ.get("MCPSONAR_RETENTION_DAYS", "7")),
        help="Delete check history older than this many days (0 disables pruning).",
    )
    run.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable the dashboard login (only behind a trusted proxy / on localhost).",
    )
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8675)

    scan = sub.add_parser(
        "scan",
        help="One-shot security scan of an MCP server (tool poisoning + lockfile drift).",
        description="Connect once, lint every tool definition for tool-poisoning patterns "
        "and optionally compare them with a lockfile. Exit code 1 on findings/drift.",
    )
    scan.add_argument("target", nargs="?", help="Server URL (http/sse).")
    scan.add_argument("--stdio", metavar="CMD",
                      help='Launch a stdio server instead, e.g. --stdio "npx -y @scope/server"')
    scan.add_argument("--transport", choices=["http", "sse"],
                      help="Force the transport for a URL (default: sse if it ends in /sse).")
    scan.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                      help="HTTP header, repeatable (e.g. -H 'Authorization: Bearer ...').")
    scan.add_argument("-e", "--env", action="append", default=[], metavar="K=V",
                      help="Environment variable for --stdio, repeatable.")
    scan.add_argument("--lock", metavar="FILE",
                      help="Lockfile: written if missing, otherwise compared (drift = exit 1).")
    scan.add_argument("--update-lock", action="store_true",
                      help="Rewrite the lockfile with the current definitions.")
    scan.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                      help="Lowest finding severity that fails the scan (default: high).")
    scan.add_argument("--json", action="store_true", help="Machine-readable output.")
    scan.add_argument("--timeout", type=float, default=20.0, help="Seconds (default 20).")

    demo = sub.add_parser(
        "demo",
        help="Run the dashboard against four scripted demo MCP servers (no setup).",
    )
    demo.add_argument("--port", type=int, default=8675)
    demo.add_argument("--interval", type=int, default=3,
                      help="Check interval in seconds (default 3: the story takes ~5 min).")
    demo.add_argument("--db", default=None, help="Keep the demo DB here (default: temp file).")
    demo.add_argument("--no-browser", action="store_true", help="Don't open the dashboard.")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)  # per-session chatter from the SDK
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        from .scan import run_scan

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        return asyncio.run(run_scan(args))

    if args.command == "demo":
        db = args.db or os.path.join(tempfile.mkdtemp(prefix="mcpsonar-demo-"), "demo.db")
        try:
            asyncio.run(
                _serve(None, "127.0.0.1", args.port, db, 1.0, require_auth=False,
                       demo_interval=args.interval, open_browser=not args.no_browser)
            )
        except KeyboardInterrupt:
            pass
        return 0

    if args.command == "run":
        try:
            asyncio.run(
                _serve(
                    args.config, args.host, args.port, args.db,
                    args.retention_days, require_auth=not args.no_auth,
                )
            )
        except KeyboardInterrupt:
            return 0
        except ConfigError as exc:
            logger.error("%s", exc)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Command-line entry point: ``mcpsonar run [--config seed.yaml] [--db path]``.

Opens the SQLite store, optionally seeds it from a YAML config on first run (when the DB has
no servers yet), starts the dynamic scheduler, and serves the dashboard + CRUD API under
uvicorn. Servers are managed at runtime via the API — no restart needed to add one.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

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


async def _serve(
    config_path: str | None,
    host: str,
    port: int,
    db_path: str,
    retention_days: float,
    require_auth: bool,
) -> None:
    storage = await Storage.open(db_path)
    if config_path:
        await _seed_from_yaml_if_empty(storage, config_path)

    store = StateStore()
    scheduler = Scheduler(storage, store, retention_days=retention_days)
    await scheduler.start()

    app = create_app(storage, store, scheduler, require_auth=require_auth)
    if require_auth and not await storage.has_admin():
        logger.info("no admin yet — open the dashboard to create one (first-run setup)")

    uv_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uv_config)
    logger.info("dashboard at http://%s:%d  (db: %s)", host, port, db_path)
    try:
        await server.serve()
    finally:
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
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    args = _build_parser().parse_args(argv)

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

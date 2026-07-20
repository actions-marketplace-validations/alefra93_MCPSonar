"""Manually run the check engine against one MCP server and print the CheckEvent.

Against the bundled mock (start it first in another shell):
    python scripts/mock_mcp_server.py
    python scripts/manual_check.py                          # -> up (no tools probed)
    python scripts/manual_check.py --tools ping             # -> up  (ping responds)
    python scripts/manual_check.py --tools ping boom        # -> degraded (boom fails)
    python scripts/manual_check.py --tools boom             # -> down (only tool fails)
    python scripts/manual_check.py --tools ping echo \
        --args '{"echo": {"text": "hi"}}'                   # -> up (echo called with args)

Against any real server:
    python scripts/manual_check.py --url https://example.com/mcp --transport http
"""

from __future__ import annotations

import argparse
import asyncio
import json

from mcpsonar.check_engine import check_server
from mcpsonar.models import ServerConfig, Thresholds, ToolProbe, TransportType


async def run(args: argparse.Namespace) -> None:
    args_map: dict[str, dict] = json.loads(args.args) if args.args else {}
    probes = [ToolProbe(name=name, arguments=args_map.get(name)) for name in args.tools]
    cfg = ServerConfig(
        url=args.url,
        transport=TransportType(args.transport),
        tools_to_test=probes,
        thresholds=Thresholds(
            latency_degraded_ms=args.degraded_ms,
            latency_down_ms=args.down_ms,
        ),
    )
    event = await check_server(args.server_id, cfg)
    print(event.model_dump_json(indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Manual mcpsonar check.")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--transport", choices=["http", "sse"], default="http")
    parser.add_argument("--server-id", default="manual-test")
    parser.add_argument("--tools", nargs="*", default=[], help="tool names to test-call")
    parser.add_argument(
        "--args",
        default=None,
        help='JSON map of tool name -> arguments, e.g. \'{"echo": {"text": "hi"}}\'',
    )
    parser.add_argument("--degraded-ms", type=float, default=2000)
    parser.add_argument("--down-ms", type=float, default=10000)
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

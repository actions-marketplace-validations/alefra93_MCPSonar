"""``mcpsonar servers``: the servers a running instance monitors (remote mode).

Credentials are masked by the instance itself (the API never returns them), so nothing
printed here can leak a token.
"""

from __future__ import annotations

from typing import Any

import yaml

from ..output import EXIT_ERROR, EXIT_OK, add_format_args, output_for, table
from ._remote import Remote, RemoteError, add_remote_args


def register(sub: Any) -> None:
    servers = sub.add_parser("servers", help="List and inspect monitored servers (remote).")
    actions = servers.add_subparsers(dest="servers_action", required=True, metavar="ACTION")

    lst = actions.add_parser("list", help="Every monitored server.")
    add_remote_args(lst)
    add_format_args(lst)
    lst.set_defaults(handler=run_list)

    show = actions.add_parser("show", help="One server's configuration (credentials masked).")
    show.add_argument("server", help="Server name or id.")
    add_remote_args(show)
    add_format_args(show, formats=("yaml", "json"))
    show.set_defaults(handler=run_show, format="yaml")


async def run_list(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            servers = await remote.get("/api/servers")
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if out.json_mode:
        out.emit_json("servers", {"servers": servers})
        return EXIT_OK
    if not servers:
        out.print("No servers monitored yet.")
        return EXIT_OK
    st = out.style
    rows = [[s["name"], s["id"], s["transport"], s["url"] or s["command"] or "",
             "yes" if s["enabled"] else st.dim("paused"), f"{s['check_interval_seconds']}s",
             str(len(s["tools_to_test"]))]
            for s in sorted(servers, key=lambda s: s["name"].lower())]
    out.print(table(["NAME", "ID", "TRANSPORT", "TARGET", "ENABLED", "INTERVAL", "PROBES"],
                    rows, st))
    return EXIT_OK


async def run_show(args: Any) -> int:
    out = output_for(args)
    try:
        async with Remote(args.url, out) as remote:
            server = await remote.resolve_server(args.server)
    except RemoteError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    if args.format == "json":
        out.emit_json("server", {"server": server})
    else:
        out.print(yaml.safe_dump(server, sort_keys=False, allow_unicode=True).rstrip())
    return EXIT_OK

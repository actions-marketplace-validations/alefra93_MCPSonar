"""Application services: the one place each MCPSonar operation is implemented.

The dashboard/REST API, the CLI and the CI scanner are three *interfaces* over the same
operations. An operation that two interfaces need lives here, once, so that a server never
looks different depending on where you ask (same timeouts, same pagination, same lint, same
redaction). Interfaces only translate inputs and render outputs.

Layering::

    cli / api / scan        interfaces (argparse, FastAPI, CI exit codes)
            │
        services            operations (this module)
            │
    check_engine · monitor · lint · tooldefs · redact · netpolicy     engine
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from .check_engine import (
    _find_http_error,
    _format_exc,
    _open_session,
    check_budget_s,
    list_all_tools,
    raise_if_cancelling,
    request_timeout_s,
)
from .lint import Finding, lint_tools
from .models import ServerConfig
from .redact import scrub, secret_values
from .tooldefs import index_tools, normalize_tool


@dataclass
class Inspection:
    """What a server exposes right now: identity, protocol version and its tools, with
    tool-poisoning findings. ``error`` is set (and the rest empty) if it could not be read."""

    target: str
    server_name: str | None = None
    server_version: str | None = None
    spec_version: str | None = None
    latency_ms: float = 0.0
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    auth_required: bool = False

    def tool_findings(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.tool == name]


async def inspect_server(
    cfg: ServerConfig, label: str, timeout_s: float | None = None
) -> Inspection:
    """Connect once, run ``initialize``, list *every* tool (all pages) and lint them.

    ``timeout_s`` bounds each request (default: the server's own request timeout); the whole
    inspection is bounded too, so a hung server can never hang a caller. Never raises for a
    server-side problem: the reason is in ``error``, already scrubbed of credentials.
    """
    result = Inspection(target=label)
    per_request = timeout_s if timeout_s is not None else request_timeout_s(cfg)
    budget = 3 * per_request if timeout_s is not None else check_budget_s(cfg)
    try:
        async with asyncio.timeout(budget), _open_session(cfg, per_request) as session:
            start = perf_counter()
            init = await session.initialize()
            result.latency_ms = (perf_counter() - start) * 1000
            result.spec_version = init.protocolVersion
            if init.serverInfo:
                result.server_name = init.serverInfo.name
                result.server_version = init.serverInfo.version
            tools = await list_all_tools(session)
    except TimeoutError:
        result.error = f"no complete answer within {budget:.0f}s"
        return result
    except Exception as exc:
        raise_if_cancelling(exc)
        http_err = _find_http_error(exc)
        if http_err is not None and http_err.response.status_code in (401, 403):
            result.auth_required = True
            result.error = f"authentication required ({http_err.response.status_code})"
        else:
            result.error = scrub(_format_exc(exc), secret_values(cfg))
        return result
    definitions = [normalize_tool(t) for t in tools]
    result.tools = index_tools(definitions)
    result.findings = lint_tools(definitions)
    return result

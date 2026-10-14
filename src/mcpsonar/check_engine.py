"""Core check engine: health-check a single MCP server and produce a :class:`CheckEvent`.

The engine is the only place that speaks MCP. It connects via the official SDK, runs the
``initialize`` handshake, lists tools, optionally test-calls configured tools, applies the
version-aware validators, and classifies the result. It **never raises**: any connection or
protocol failure becomes a ``down`` event, so the scheduler can treat every server uniformly.
"""

from __future__ import annotations

import contextlib
import functools
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from time import perf_counter
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import InitializeResult, Tool

from .models import CheckEvent, CheckStatus, ServerConfig, Thresholds, ToolProbe, TransportType
from .tooldefs import normalize_tool
from .validators import get_validator, run_minimal_common_validation


@functools.cache
def _ssl_context() -> ssl.SSLContext:
    """One TLS context for every check. Building one loads the CA bundle (~200 ms of blocking
    CPU); doing that per check stalls the event loop and inflates the latency measured for
    every *other* server being checked at the same time."""
    return httpx.create_ssl_context()


def _http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """Same defaults as the SDK's ``create_mcp_http_client``, with the shared TLS context."""
    return httpx.AsyncClient(
        follow_redirects=True,
        headers=headers,
        timeout=timeout if timeout is not None else httpx.Timeout(30.0, read=300.0),
        auth=auth,
        verify=_ssl_context(),
    )


@contextlib.asynccontextmanager
async def _open_session(cfg: ServerConfig, timeout_s: float) -> AsyncIterator[ClientSession]:
    """Open an initialized-capable MCP ClientSession over the configured transport.

    * http  — Streamable HTTP (3-tuple client), with optional auth ``headers``.
    * sse   — legacy HTTP+SSE (2-tuple client), with optional auth ``headers``.
    * stdio — mcpsonar launches ``command``/``args`` and speaks over the process's stdio.

    The timeout bounds connect/read so a hung server surfaces as ``down`` rather than
    blocking forever.
    """
    headers = cfg.headers or None
    if cfg.transport == TransportType.SSE:
        async with sse_client(
            cfg.url, headers=headers, timeout=timeout_s, httpx_client_factory=_http_client
        ) as (read, write), ClientSession(read, write) as session:
            yield session
    elif cfg.transport == TransportType.STDIO:
        params = StdioServerParameters(
            command=cfg.command, args=cfg.args, env=(cfg.env or None)
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            yield session
    else:  # TransportType.HTTP -> Streamable HTTP
        timeout = httpx.Timeout(timeout_s)
        async with (
            _http_client(headers=headers, timeout=timeout) as http_client,
            streamable_http_client(cfg.url, http_client=http_client) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            yield session


async def _probe_tools(
    session: ClientSession, probes: list[ToolProbe], timeout_s: float
) -> tuple[int, int, list[str]]:
    """Test-call each configured tool with its configured arguments to prove it responds.
    Returns (tools_checked, tools_failed, failure_notes).

    A tool counts as failed if the call raises (transport/protocol error, unknown tool) or
    returns ``isError``. Configure representative ``arguments`` per tool so an error is a
    real malfunction signal rather than a "you called it wrong" artifact.
    """
    checked = 0
    failed = 0
    notes: list[str] = []
    for probe in probes:
        checked += 1
        try:
            result = await session.call_tool(
                probe.name,
                arguments=probe.arguments,
                read_timeout_seconds=timedelta(seconds=timeout_s),
            )
            if result.isError:
                failed += 1
                notes.append(f"{probe.name}: tool returned an error result")
        except Exception as exc:  # unknown tool, bad args, transport error, timeout
            failed += 1
            notes.append(f"{probe.name}: {type(exc).__name__}")
    return checked, failed, notes


def _classify(
    latency_ms: float,
    thresholds: Thresholds,
    tools_checked: int,
    tools_failed: int,
    tool_notes: list[str],
    validation_issues: list[str],
) -> tuple[CheckStatus, str | None]:
    """Map raw signals to a status + human-readable detail.

    down     : latency >= latency_down_ms, OR every tested tool failed.
    degraded : latency >= latency_degraded_ms, OR some (not all) tested tools failed,
               OR the server violates known-spec validation rules.
    up       : none of the above.

    (An unrecognized spec version is *not* a factor here — it only sets
    spec_version_supported=False on the event; it never changes status.)
    """
    reasons: list[str] = []
    is_down = False
    is_degraded = False

    if latency_ms >= thresholds.latency_down_ms:
        is_down = True
        reasons.append(
            f"latency {latency_ms:.0f}ms >= down threshold {thresholds.latency_down_ms:.0f}ms"
        )
    if tools_checked > 0 and tools_failed == tools_checked:
        is_down = True
        reasons.append(f"all {tools_checked} tested tool(s) failed")

    if not is_down:
        if latency_ms >= thresholds.latency_degraded_ms:
            is_degraded = True
            reasons.append(
                f"latency {latency_ms:.0f}ms >= degraded threshold "
                f"{thresholds.latency_degraded_ms:.0f}ms"
            )
        if 0 < tools_failed < tools_checked:
            is_degraded = True
            reasons.append(f"{tools_failed}/{tools_checked} tested tool(s) failed")
        if validation_issues:
            is_degraded = True
            reasons.append("validation: " + "; ".join(validation_issues))

    # Always surface tool-level errors in detail, even when they drove the classification.
    if tool_notes:
        reasons.append("tool errors: " + "; ".join(tool_notes))

    if is_down:
        status = CheckStatus.DOWN
    elif is_degraded:
        status = CheckStatus.DEGRADED
    else:
        status = CheckStatus.UP

    detail = "; ".join(reasons) if reasons else None
    return status, detail


def _format_exc(exc: BaseException) -> str:
    """Render an exception for the event detail, unwrapping the anyio ExceptionGroup that
    wraps transport errors so the real cause (e.g. ConnectError) is what's reported."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_format_exc(sub) for sub in exc.exceptions)
    return f"{type(exc).__name__}: {exc}"


def _find_http_error(exc: BaseException) -> httpx.HTTPStatusError | None:
    """The HTTP status error buried in a (possibly nested) anyio ExceptionGroup, if any."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _find_http_error(sub)
            if found is not None:
                return found
    return None


def _has_auth_header(cfg: ServerConfig) -> bool:
    return any(k.lower() in ("authorization", "x-api-key") for k in cfg.headers)


def _auth_outcome(
    server_id: str, cfg: ServerConfig, err: httpx.HTTPStatusError, latency_ms: float
) -> CheckOutcome:
    """Classify a 401/403 answer.

    Without credentials configured, a 401/403 means the server is alive and protected (most
    hosted MCP servers use OAuth): that's **up**, flagged ``auth_required`` — we just can't
    see its tools. With credentials configured it means they were rejected: **down**.
    """
    code = err.response.status_code
    challenge = err.response.headers.get("www-authenticate", "")
    if _has_auth_header(cfg):
        return CheckOutcome(
            CheckEvent(
                server_id=server_id,
                status=CheckStatus.DOWN,
                latency_ms=latency_ms,
                auth_required=True,
                detail=f"credentials rejected ({code}) — check the configured token",
            )
        )
    kind = "MCP OAuth" if "resource_metadata" in challenge else (
        challenge.split(" ", 1)[0] or "authentication")
    status, detail = _classify(latency_ms, cfg.thresholds, 0, 0, [], [])
    note = f"reachable — {kind} required ({code}); add an Authorization header to check tools"
    return CheckOutcome(
        CheckEvent(
            server_id=server_id,
            status=status,
            latency_ms=latency_ms,
            auth_required=True,
            detail="; ".join(filter(None, [note, detail])),
        )
    )


@dataclass
class CheckOutcome:
    """A check's event plus the raw material later analysis needs.

    ``tools`` holds the normalized tool definitions from ``tools/list`` (see
    :func:`mcpsonar.tooldefs.normalize_tool`), or None when the handshake never completed.
    """

    event: CheckEvent
    tools: list[dict[str, Any]] | None = None


async def check_server(server_id: str, cfg: ServerConfig) -> CheckEvent:
    """Run one health check against ``cfg`` and return a standardized :class:`CheckEvent`.

    Never raises: connection/handshake failures are caught and returned as a ``down`` event.
    """
    return (await run_check(server_id, cfg)).event


async def run_check(server_id: str, cfg: ServerConfig) -> CheckOutcome:
    """Like :func:`check_server`, but also returns the tool definitions that were listed."""
    thresholds = cfg.thresholds
    # Give the transport enough headroom to actually observe a "down due to latency" result
    # rather than aborting a slow-but-alive server early.
    timeout_s = thresholds.latency_down_ms / 1000.0 + 5.0
    t0 = perf_counter()

    try:
        async with _open_session(cfg, timeout_s) as session:
            start = perf_counter()
            init: InitializeResult = await session.initialize()
            latency_ms = (perf_counter() - start) * 1000.0

            spec_version = init.protocolVersion or None
            tools: list[Tool] = (await session.list_tools()).tools

            tools_checked, tools_failed, tool_notes = await _probe_tools(
                session, cfg.tools_to_test, timeout_s
            )

            # Version-aware validation: common rules always, version rules only if known.
            issues = run_minimal_common_validation(init, tools)
            validator = get_validator(spec_version)
            if validator is not None:
                spec_version_supported = True
                issues = issues + validator.validate(init, tools)
            else:
                spec_version_supported = False  # informational only; never changes status

            status, detail = _classify(
                latency_ms, thresholds, tools_checked, tools_failed, tool_notes, issues
            )

            event = CheckEvent(
                server_id=server_id,
                status=status,
                latency_ms=latency_ms,
                tools_checked=tools_checked,
                tools_failed=tools_failed,
                tools_available=len(tools),
                spec_version=spec_version,
                spec_version_supported=spec_version_supported,
                detail=detail,
            )
            return CheckOutcome(event, [normalize_tool(t) for t in tools])

    except Exception as exc:  # connect failure, handshake failure, timeout, etc.
        http_err = _find_http_error(exc)
        if http_err is not None and http_err.response.status_code in (401, 403):
            return _auth_outcome(server_id, cfg, http_err, (perf_counter() - t0) * 1000.0)
        if http_err is not None and http_err.response.status_code == 429:
            # Alive, but throttling us: a problem worth seeing, not an outage.
            retry = http_err.response.headers.get("retry-after")
            return CheckOutcome(
                CheckEvent(
                    server_id=server_id,
                    status=CheckStatus.DEGRADED,
                    latency_ms=(perf_counter() - t0) * 1000.0,
                    detail="rate limited (429)" + (f", retry after {retry}s" if retry else ""),
                )
            )
        return CheckOutcome(
            CheckEvent(
                server_id=server_id,
                status=CheckStatus.DOWN,
                latency_ms=0.0,
                spec_version=None,
                spec_version_supported=False,
                detail=f"connection/handshake failed: {_format_exc(exc)}",
            )
        )

"""Prometheus exporter.

Not a push adapter: it renders the current StateStore contents as Prometheus text-format
metrics for a ``GET /metrics`` scrape. Only servers that have been checked at least once are
emitted (Prometheus prefers absent series over fabricated ones).
"""

from __future__ import annotations

from ..models import CheckEvent, CheckStatus, MonitoredServer
from ..state import StateStore

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_STATUS_CODE = {CheckStatus.UP: 2, CheckStatus.DEGRADED: 1, CheckStatus.DOWN: 0}


def _escape(value: str) -> str:
    """Escape a Prometheus label value."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, help_text: str, samples: list[str]) -> list[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", *samples]


def render_metrics(servers: list[MonitoredServer], store: StateStore) -> str:
    snap = store.snapshot()
    names = {s.id: s.name for s in servers}
    events: list[CheckEvent] = [snap[s.id] for s in servers if s.id in snap]

    lines: list[str] = []

    def label(event: CheckEvent) -> str:
        return f'server_id="{_escape(event.server_id)}"'

    lines += _metric(
        "mcpsonar_up",
        "Whether the server's last check was 'up' (1) or not (0).",
        [f"mcpsonar_up{{{label(e)}}} {1 if e.status == CheckStatus.UP else 0}" for e in events],
    )
    lines += _metric(
        "mcpsonar_status_code",
        "Status of the last check: 2=up, 1=degraded, 0=down.",
        [f"mcpsonar_status_code{{{label(e)}}} {_STATUS_CODE[e.status]}" for e in events],
    )
    lines += _metric(
        "mcpsonar_latency_ms",
        "Latency of the last check's initialize handshake, in milliseconds.",
        [f"mcpsonar_latency_ms{{{label(e)}}} {e.latency_ms:.3f}" for e in events],
    )
    lines += _metric(
        "mcpsonar_tools_checked",
        "Number of tools test-called in the last check.",
        [f"mcpsonar_tools_checked{{{label(e)}}} {e.tools_checked}" for e in events],
    )
    lines += _metric(
        "mcpsonar_tools_failed",
        "Number of test-called tools that failed in the last check.",
        [f"mcpsonar_tools_failed{{{label(e)}}} {e.tools_failed}" for e in events],
    )
    lines += _metric(
        "mcpsonar_spec_version_supported",
        "1 if mcpsonar has a version-specific validator for the declared spec version, else 0.",
        [
            f"mcpsonar_spec_version_supported{{{label(e)}}} "
            f"{1 if e.spec_version_supported else 0}"
            for e in events
        ],
    )
    lines += _metric(
        "mcpsonar_last_check_timestamp_seconds",
        "Unix timestamp of the last check.",
        [
            f"mcpsonar_last_check_timestamp_seconds{{{label(e)}}} {e.checked_at.timestamp():.0f}"
            for e in events
        ],
    )
    lines += _metric(
        "mcpsonar_server_info",
        "Informational labels for the server (value is always 1).",
        [
            f'mcpsonar_server_info{{{label(e)},'
            f'name="{_escape(names.get(e.server_id, ""))}",'
            f'spec_version="{_escape(e.spec_version or "")}",'
            f'spec_version_supported="{str(e.spec_version_supported).lower()}"}} 1'
            for e in events
        ],
    )

    return "\n".join(lines) + "\n"

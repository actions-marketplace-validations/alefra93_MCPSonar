"""Pydantic models for mcpsonar.

This module is the **source of truth** for the project:

* :class:`CheckEvent` is the standardized, transport/adapter-independent result of a
  single health check. Everything downstream (dashboard, Prometheus, webhooks) consumes
  this and nothing else.
* The ``*Config`` models describe the YAML configuration file.

Both are intentionally decoupled: the check engine produces a ``CheckEvent`` without
knowing where it will go, and the config describes intent without knowing how a check
is performed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class CheckStatus(str, Enum):
    """Outcome of a single health check."""

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


class TransportType(str, Enum):
    """MCP transport used to reach a server."""

    HTTP = "http"  # Streamable HTTP (>= 2025-03-26)
    SSE = "sse"  # legacy HTTP+SSE (2024-11-05), deprecated but still around
    STDIO = "stdio"  # local process launched by mcpsonar, spoken to over stdio


# --------------------------------------------------------------------------- #
# The event — the stable contract every downstream consumer depends on
# --------------------------------------------------------------------------- #
def _utcnow() -> datetime:
    return datetime.now(UTC)


class Anomaly(BaseModel):
    """Something unusual detected by a check, beyond plain up/degraded/down."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["latency_spike", "latency_shift", "flapping", "tool_change", "response_drift"]
    detail: str
    score: float | None = Field(
        default=None, description="Strength of the signal (z-score / t-statistic), if any."
    )


class CheckEvent(BaseModel):
    """The standardized result of checking one MCP server, at one point in time.

    This is deliberately flat and boring: it is serialized as-is to webhooks and read
    field-by-field by the dashboard and the Prometheus exporter. Adding a field is a
    contract change — do it consciously.
    """

    model_config = ConfigDict(extra="forbid")

    server_id: str = Field(description="Logical id of the server (the YAML section key).")
    status: CheckStatus
    checked_at: datetime = Field(
        default_factory=_utcnow,
        description="Timezone-aware timestamp of when the check completed.",
    )
    latency_ms: float = Field(
        ge=0,
        description="Round-trip time of the initialize handshake, in milliseconds. "
        "0 when the connection never succeeded.",
    )
    tools_checked: int = Field(
        default=0, ge=0, description="How many configured tools were test-called."
    )
    tools_failed: int = Field(
        default=0, ge=0, description="How many of the test-called tools failed."
    )
    tools_available: int = Field(
        default=0, ge=0, description="How many tools the server exposes (from tools/list)."
    )
    spec_version: str | None = Field(
        default=None,
        description="MCP spec version the server declared during initialize "
        "(None if the handshake never completed).",
    )
    spec_version_supported: bool = Field(
        default=False,
        description="True if mcpsonar has a version-specific validator for the declared "
        "spec_version. When False, only minimal common validation was applied.",
    )
    detail: str | None = Field(
        default=None,
        description="Human-readable note: error message when down, or the reason for a "
        "degraded classification. None when everything is nominal.",
    )
    auth_required: bool = Field(
        default=False,
        description="The server answered 401/403 to an anonymous client: it is alive but needs "
        "credentials (e.g. MCP OAuth). Counted as 'up' when no Authorization header is "
        "configured — tools can't be listed, so tool checks are skipped.",
    )
    tool_changes: int = Field(
        default=0,
        ge=0,
        description="Tool-definition changes (added/removed/changed tools) detected since the "
        "baseline and not yet reviewed. Non-zero means the server's tools changed under you.",
    )
    tool_risks: int = Field(
        default=0,
        ge=0,
        description="High/medium tool-poisoning findings in the current tool definitions.",
    )
    anomalies: list[Anomaly] = Field(
        default_factory=list,
        description="Things newly detected by *this* check (latency spike/shift, flapping, "
        "tool changes). Empty on a nominal check.",
    )
    latency_baseline_ms: float | None = Field(
        default=None,
        description="Median latency of recent healthy checks (None until enough history).",
    )
    latency_score: float | None = Field(
        default=None,
        description="Robust z-score of this check's latency vs. the baseline "
        "((latency - median) / scaled MAD). None until enough history.",
    )
    timings_ms: dict[str, float] | None = Field(
        default=None,
        description="How long each phase of the check took, in ms: 'handshake' (the "
        "negotiation RPC that succeeded — the same value as latency_ms), 'discovery' (every "
        "tools/list page), 'probes' (all configured tool calls) and 'total' (the whole check, "
        "connection set-up included). None when the server was not reached.",
    )
    tool_latency_ms: dict[str, float] = Field(
        default_factory=dict,
        description="Latency of each probed tool call, by tool name (only tools that were "
        "actually called).",
    )


# --------------------------------------------------------------------------- #
# Configuration models
# --------------------------------------------------------------------------- #
def _check_http_url(value: str) -> str:
    """Only http(s) URLs with a host: no file://, no scheme-less strings, no bare paths."""
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http:// or https:// URL with a host")
    return value.strip()


HttpUrlStr = Annotated[str, AfterValidator(_check_http_url)]


class Thresholds(BaseModel):
    """Latency thresholds that drive up/degraded/down classification.

    A check at or above ``latency_degraded_ms`` is at best ``degraded``; at or above
    ``latency_down_ms`` it is ``down`` even if it technically answered.
    """

    model_config = ConfigDict(extra="forbid")

    latency_degraded_ms: float = Field(default=2000, gt=0)
    latency_down_ms: float = Field(default=10000, gt=0)


class AnomalyConfig(BaseModel):
    """Statistical anomaly detection on the latency/status history of a server."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    sensitivity: float = Field(
        default=4.0,
        gt=0,
        description="Robust z-score above which a latency is a spike (lower = more alerts).",
    )
    degrade: bool = Field(
        default=False,
        description="Also mark the server 'degraded' when a latency anomaly is detected.",
    )


class UptimeKumaWebhook(BaseModel):
    """Push-monitor target for Uptime Kuma (has no notion of 'degraded')."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["uptime_kuma"] = "uptime_kuma"
    push_url: HttpUrlStr = Field(description="Uptime Kuma push URL, e.g. .../api/push/<token>.")


class GenericWebhook(BaseModel):
    """POST the raw CheckEvent JSON to an arbitrary URL."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["generic"] = "generic"
    url: HttpUrlStr
    on: list[CheckStatus] = Field(
        default_factory=lambda: [CheckStatus.DOWN, CheckStatus.DEGRADED],
        description="Only fire this webhook when the event status is in this list.",
    )
    on_anomaly: bool = Field(
        default=True,
        description="Also fire when a check detects something new (anomaly or tool change), "
        "whatever its status.",
    )


# Discriminated union so the YAML `type:` picks the right model with clear errors.
WebhookConfig = Annotated[
    UptimeKumaWebhook | GenericWebhook,
    Field(discriminator="type"),
]


class ToolProbe(BaseModel):
    """A tool to test-call to prove it responds, with the arguments to call it with.

    Accepts a bare string in YAML as shorthand for a no-argument probe, e.g.::

        tools_to_test:
          - ping                              # -> ToolProbe(name="ping")
          - name: echo
            arguments: { text: "healthcheck" }
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] | None = Field(
        default=None,
        description="Arguments passed to call_tool. None calls the tool with no arguments.",
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        description="Timeout for this call (default: the server's request timeout).",
    )
    allow_destructive: bool = Field(
        default=False,
        description="Probe the tool even if its annotations declare it destructive. "
        "Annotations are the server's own claims, not guarantees: only probe tools that are "
        "safe to call repeatedly.",
    )
    drift: Literal["shape", "hash", "off"] = Field(
        default="shape",
        description="Response drift detection for this probe. 'shape' (default) compares "
        "error/no-error, content types, the structure of structured content and the order "
        "of magnitude of the size — never values. 'hash' also compares the content, minus "
        "drift_ignore fields: for deterministic probes. 'off' disables it.",
    )
    drift_ignore: list[str] = Field(
        default_factory=list,
        description="Field names left out of the 'hash' comparison wherever they appear "
        "(timestamps, request ids, ...).",
    )


class ServerConfig(BaseModel):
    """Everything mcpsonar needs to monitor one MCP server.

    For ``http``/``sse`` transports, ``url`` is required (and ``headers`` may carry auth).
    For ``stdio``, ``command`` is required (with optional ``args``/``env``) and mcpsonar
    launches the process for each check.
    """

    model_config = ConfigDict(extra="forbid")

    transport: TransportType = TransportType.HTTP

    # http / sse
    url: HttpUrlStr | None = Field(
        default=None, description="Endpoint of the MCP server (http/sse)."
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers for http/sse, e.g. Authorization for a protected server.",
    )

    # stdio
    command: str | None = Field(
        default=None, description="Executable to launch for a stdio server (e.g. 'npx')."
    )
    args: list[str] = Field(default_factory=list, description="Arguments for the stdio command.")
    env: dict[str, str] = Field(
        default_factory=dict, description="Extra environment variables for the stdio process."
    )

    check_interval_seconds: int = Field(default=60, gt=0)
    tools_to_test: list[ToolProbe] = Field(
        default_factory=list,
        description="Tools to actually call to prove they respond (not just listed). "
        "Each item is a tool name or a {name, arguments} mapping.",
    )
    thresholds: Thresholds = Field(default_factory=Thresholds)
    webhooks: list[WebhookConfig] = Field(default_factory=list)
    on_tool_change: Literal["degrade", "alert", "ignore"] = Field(
        default="degrade",
        description="What to do when tool definitions change vs. the pinned baseline: "
        "'degrade' keeps the server degraded until the change is reviewed, 'alert' only "
        "records it and notifies, 'ignore' disables tool pinning.",
    )
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)

    @field_validator("tools_to_test", mode="before")
    @classmethod
    def _coerce_tool_probes(cls, value: Any) -> Any:
        """Allow bare strings as shorthand for a no-argument probe."""
        if isinstance(value, list):
            return [{"name": item} if isinstance(item, str) else item for item in value]
        return value

    @model_validator(mode="after")
    def _check_transport_fields(self) -> ServerConfig:
        if self.transport == TransportType.STDIO:
            if not self.command:
                raise ValueError("stdio transport requires 'command'")
        elif not self.url:
            raise ValueError(f"{self.transport.value} transport requires 'url'")
        return self


class Config(BaseModel):
    """Top-level configuration: one entry per monitored server."""

    model_config = ConfigDict(extra="forbid")

    servers: dict[str, ServerConfig] = Field(default_factory=dict)


class MonitoredServer(ServerConfig):
    """A server as stored/managed at runtime: a :class:`ServerConfig` plus identity and an
    enabled flag. This is what the CRUD API and the persistence layer work with; because it
    *is* a ServerConfig, ``check_server`` accepts it unchanged.
    """

    id: str = Field(description="Stable server id (generated, used in URLs and history).")
    name: str = Field(description="Human-friendly display name.")
    enabled: bool = Field(default=True, description="Whether the scheduler checks it.")

    def to_server_config(self) -> ServerConfig:
        """The plain check-config view (drops id/name/enabled)."""
        return ServerConfig.model_validate(
            {k: getattr(self, k) for k in ServerConfig.model_fields}
        )


class ServerInput(ServerConfig):
    """Request body for creating/updating a server via the API: check config + name/enabled
    (no id — the server assigns it)."""

    name: str
    enabled: bool = True

    def to_server_config(self) -> ServerConfig:
        return ServerConfig.model_validate(
            {k: getattr(self, k) for k in ServerConfig.model_fields}
        )

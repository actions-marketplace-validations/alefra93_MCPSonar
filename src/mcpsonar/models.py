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

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    return datetime.now(timezone.utc)


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


# --------------------------------------------------------------------------- #
# Configuration models
# --------------------------------------------------------------------------- #
class Thresholds(BaseModel):
    """Latency thresholds that drive up/degraded/down classification.

    A check at or above ``latency_degraded_ms`` is at best ``degraded``; at or above
    ``latency_down_ms`` it is ``down`` even if it technically answered.
    """

    model_config = ConfigDict(extra="forbid")

    latency_degraded_ms: float = Field(default=2000, gt=0)
    latency_down_ms: float = Field(default=10000, gt=0)


class UptimeKumaWebhook(BaseModel):
    """Push-monitor target for Uptime Kuma (has no notion of 'degraded')."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["uptime_kuma"] = "uptime_kuma"
    push_url: str = Field(description="Uptime Kuma push URL, e.g. .../api/push/<token>.")


class GenericWebhook(BaseModel):
    """POST the raw CheckEvent JSON to an arbitrary URL."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["generic"] = "generic"
    url: str
    on: list[CheckStatus] = Field(
        default_factory=lambda: [CheckStatus.DOWN, CheckStatus.DEGRADED],
        description="Only fire this webhook when the event status is in this list.",
    )


# Discriminated union so the YAML `type:` picks the right model with clear errors.
WebhookConfig = Annotated[
    Union[UptimeKumaWebhook, GenericWebhook],
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


class ServerConfig(BaseModel):
    """Everything mcpsonar needs to monitor one MCP server.

    For ``http``/``sse`` transports, ``url`` is required (and ``headers`` may carry auth).
    For ``stdio``, ``command`` is required (with optional ``args``/``env``) and mcpsonar
    launches the process for each check.
    """

    model_config = ConfigDict(extra="forbid")

    transport: TransportType = TransportType.HTTP

    # http / sse
    url: str | None = Field(default=None, description="Endpoint of the MCP server (http/sse).")
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

    @field_validator("tools_to_test", mode="before")
    @classmethod
    def _coerce_tool_probes(cls, value: Any) -> Any:
        """Allow bare strings as shorthand for a no-argument probe."""
        if isinstance(value, list):
            return [{"name": item} if isinstance(item, str) else item for item in value]
        return value

    @model_validator(mode="after")
    def _check_transport_fields(self) -> "ServerConfig":
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

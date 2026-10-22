"""Output adapters and the dispatcher that fans check events out to them.

Push adapters (Uptime Kuma, generic webhook) implement :class:`BaseAdapter` and share one
``httpx2.AsyncClient`` owned by :class:`AdapterDispatcher`. The Prometheus exporter is not a
push adapter — it is scraped via ``/metrics`` and reads the StateStore directly.
"""

from __future__ import annotations

import httpx2

from ..models import DiscordWebhook, GenericWebhook, ServerConfig, SlackWebhook, UptimeKumaWebhook
from .base import BaseAdapter
from .chat import DiscordAdapter, SlackAdapter
from .generic_webhook import GenericWebhookAdapter
from .prometheus import CONTENT_TYPE, render_metrics
from .uptime_kuma import UptimeKumaAdapter

__all__ = [
    "CONTENT_TYPE",
    "BaseAdapter",
    "DiscordAdapter",
    "GenericWebhookAdapter",
    "SlackAdapter",
    "UptimeKumaAdapter",
    "build_push_adapters",
    "render_metrics",
]


def build_push_adapters(
    cfg: ServerConfig, client: httpx2.AsyncClient, name: str = ""
) -> list[BaseAdapter]:
    """Construct the push adapters declared in a server's webhook config. The scheduler owns
    the shared client and dispatches events to these per server. ``name``: the server's
    display name, for chat messages."""
    adapters: list[BaseAdapter] = []
    for webhook in cfg.webhooks:
        if isinstance(webhook, UptimeKumaWebhook):
            adapters.append(UptimeKumaAdapter(webhook.push_url, client))
        elif isinstance(webhook, GenericWebhook):
            adapters.append(
                GenericWebhookAdapter(
                    webhook.url, webhook.on, client, on_anomaly=webhook.on_anomaly,
                    on_recovery=webhook.on_recovery,
                )
            )
        elif isinstance(webhook, SlackWebhook | DiscordWebhook):
            cls = SlackAdapter if isinstance(webhook, SlackWebhook) else DiscordAdapter
            adapters.append(cls(webhook.url, name, webhook.on, client,
                                on_anomaly=webhook.on_anomaly,
                                on_recovery=webhook.on_recovery))
    return adapters

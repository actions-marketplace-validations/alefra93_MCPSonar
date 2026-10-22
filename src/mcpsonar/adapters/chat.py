"""Slack and Discord notifications: one message per change (see :mod:`mcpsonar.notify`).

Both POST JSON to an incoming-webhook URL through the shared client, so deliveries obey the
outbound connection policy like every other request. The URL is a secret: it never appears
in logs (``redact_url(..., whole_path=True)``) and is masked by the API.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx2

from ..models import CheckEvent, CheckStatus
from ..notify import Notification, discord_payload, notification_for, slack_payload
from ..redact import redact_url
from .base import BaseAdapter

logger = logging.getLogger("mcpsonar.adapters.chat")


class _ChatAdapter(BaseAdapter):
    def __init__(
        self,
        url: str,
        server_name: str,
        on: list[CheckStatus],
        client: httpx2.AsyncClient,
        on_anomaly: bool = True,
        on_recovery: bool = True,
        max_retries: int = 3,
        backoff: float = 0.5,
    ) -> None:
        super().__init__(client)
        self._url = url
        self._server_name = server_name
        self._on = list(on)
        self._on_anomaly = on_anomaly
        self._on_recovery = on_recovery
        self._max_retries = max_retries
        self._backoff = backoff

    def payload(self, note: Notification) -> dict[str, Any]:
        raise NotImplementedError

    async def send(self, event: CheckEvent) -> None:
        note = notification_for(event, self._server_name or event.server_id, self._on,
                                self._on_anomaly, self._on_recovery)
        if note is None:
            return
        body = self.payload(note)
        delay = self._backoff
        for attempt in range(1, self._max_retries + 1):
            try:
                response = await self._client.post(self._url, json=body)
                response.raise_for_status()
                logger.debug("%s notification for %s sent to %s", self.name, event.server_id,
                             redact_url(self._url, whole_path=True))
                return
            except Exception:
                if attempt == self._max_retries:
                    raise
                await asyncio.sleep(delay)
                delay *= 2


class SlackAdapter(_ChatAdapter):
    name = "slack"

    def payload(self, note: Notification) -> dict[str, Any]:
        return slack_payload(note)


class DiscordAdapter(_ChatAdapter):
    name = "discord"

    def payload(self, note: Notification) -> dict[str, Any]:
        return discord_payload(note)

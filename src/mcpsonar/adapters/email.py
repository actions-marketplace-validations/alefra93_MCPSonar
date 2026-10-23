"""Email notifications through SMTP: one message per change (see :mod:`mcpsonar.notify`).

* **TLS is required**: STARTTLS must succeed (it is not opportunistic), or implicit TLS on
  port 465. Plain SMTP is accepted only for a relay on localhost (validated by the model).
* **The outbound policy applies**: the SMTP host is resolved and every address is checked
  against it before connecting, like an HTTP check; the connection then goes to a vetted
  address while TLS still verifies the certificate against the host *name*.
* **The password** can be a secret reference (``${env:...}`` / ``${file:...}``), resolved for
  each message under the same allowlist as header references.

smtplib is blocking, so a delivery runs in a worker thread with a timeout.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import httpx2

from ..models import CheckEvent, EmailWebhook
from ..netpolicy import get_policy, resolve
from ..notify import notification_for, plain_text
from ..secretref import resolve_value
from .base import BaseAdapter

logger = logging.getLogger("mcpsonar.adapters.email")

TIMEOUT_S = 20.0
CONNECT_TIMEOUT_S = 5.0  # per address: one that drops packets must not eat the whole budget


class SMTPDeliveryError(Exception):
    """The message could not be delivered; the text names the step, never a credential."""


def _connect(addresses: list[str], port: int, timeout: float) -> socket.socket:
    """The first vetted address that accepts the connection. Each attempt is short (a host
    name often resolves to IPv6 and IPv4; a broken path must not stall the delivery), then
    the connected socket gets the full ``timeout`` for the conversation."""
    last: OSError | None = None
    for address in addresses:
        try:
            sock = socket.create_connection((address, port), min(timeout, CONNECT_TIMEOUT_S))
        except OSError as exc:
            last = exc
            continue
        sock.settimeout(timeout)
        return sock
    raise last or OSError("no address to connect to")


class _SMTP(smtplib.SMTP):
    """Connects only to vetted IP addresses; smtplib keeps the host name (``_host``) for
    the certificate check of STARTTLS."""

    def __init__(self, addresses: list[str], host: str, port: int, timeout: float) -> None:
        self.addresses = addresses
        super().__init__(host, port, timeout=timeout)

    def _get_socket(self, host, port, timeout):  # smtplib hook
        return _connect(self.addresses, port, timeout)


class _SMTPS(smtplib.SMTP_SSL):
    """Implicit TLS to vetted IP addresses, verified against the host name."""

    def __init__(self, addresses: list[str], host: str, port: int, timeout: float,
                 context: ssl.SSLContext) -> None:
        self.addresses = addresses
        super().__init__(host, port, timeout=timeout, context=context)

    def _get_socket(self, host, port, timeout):
        sock = _connect(self.addresses, port, timeout)
        return self.context.wrap_socket(sock, server_hostname=self._host)


class EmailAdapter(BaseAdapter):
    name = "email"

    def __init__(
        self,
        config: EmailWebhook,
        server_name: str,
        client: httpx2.AsyncClient,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(client)
        self._cfg = config
        self._server_name = server_name
        self._ssl_context = ssl_context

    async def send(self, event: CheckEvent) -> None:
        cfg = self._cfg
        note = notification_for(event, self._server_name or event.server_id, cfg.on,
                                cfg.on_anomaly, cfg.on_recovery)
        if note is None:
            return
        message = EmailMessage()
        message["Subject"] = f"{cfg.subject_prefix} {note.icon} {note.title}".strip()
        message["From"] = cfg.sender
        message["To"] = ", ".join(cfg.to)
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(domain=cfg.sender.rsplit("@", 1)[1])
        message.set_content(plain_text(note))
        addresses = await self._vetted_addresses()
        password = resolve_value(cfg.password) if cfg.password else None
        await asyncio.wait_for(
            asyncio.to_thread(self._deliver, addresses, message, password), TIMEOUT_S + 5)
        logger.debug("email notification for %s sent to %d recipient(s)", event.server_id,
                     len(cfg.to))

    async def _vetted_addresses(self) -> list[str]:
        cfg = self._cfg
        try:
            addresses = await asyncio.wait_for(resolve(cfg.host, cfg.port), TIMEOUT_S)
        except (OSError, TimeoutError) as exc:
            raise SMTPDeliveryError(f"could not resolve {cfg.host}: {exc}") from None
        policy = get_policy()
        allowed, reasons = [], []
        for ip in addresses:
            if reason := policy.check_ip(ip):
                reasons.append(reason)
            else:
                allowed.append(str(ip))
        if not allowed:
            raise SMTPDeliveryError(f"outbound policy blocked {cfg.host}: "
                                    + "; ".join(dict.fromkeys(reasons)))
        return allowed

    def _context(self) -> ssl.SSLContext:
        return self._ssl_context or httpx2.create_ssl_context()

    def _deliver(self, addresses: list[str], message: EmailMessage,
                 password: str | None) -> None:
        cfg = self._cfg
        step = "connect"
        try:
            if cfg.security == "tls":
                smtp: smtplib.SMTP = _SMTPS(addresses, cfg.host, cfg.port, TIMEOUT_S,
                                            self._context())
            else:
                smtp = _SMTP(addresses, cfg.host, cfg.port, TIMEOUT_S)
            with smtp:
                if cfg.security == "starttls":
                    step = "STARTTLS"
                    smtp.starttls(context=self._context())  # raises if not offered
                if cfg.username:
                    step = "login"
                    smtp.login(cfg.username, password or "")
                step = "send"
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            # Exception texts can quote the server's reply, never our password.
            raise SMTPDeliveryError(f"SMTP {step} with {cfg.host}:{cfg.port} failed: "
                                    f"{type(exc).__name__}: {exc}") from None

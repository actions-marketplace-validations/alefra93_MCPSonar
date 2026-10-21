"""Keep credentials out of API responses, exports, check details, webhooks and logs.

mcpsonar must *hold* secrets to do its job (``Authorization`` headers, stdio ``env``, API
keys in server URLs, webhook URLs that embed a token), but it never needs to *show* them.
Everything that leaves the process goes through here:

* :func:`redact_config` — the API/export view of a server: every header and env value,
  URL userinfo, credential-looking query parameters and token-looking path segments become
  :data:`REDACTED`.
* :func:`restore_secrets` — the inverse on update: a value sent back still redacted means
  "unchanged", so editing a server in the dashboard never wipes (or leaks) its credentials.
* :func:`scrub` — removes known secret values (from the server's config) and anything that
  looks like a bearer token or a credentialed URL from free text: error details, logs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import ServerConfig, UptimeKumaWebhook
from .secretref import showable

REDACTED = "********"

# Query-parameter names that carry credentials (substring match, case-insensitive).
_SENSITIVE_PARAM = re.compile(
    r"key|token|secret|passw|pwd|auth|sig|credential|session|bearer|jwt", re.IGNORECASE
)
# A path segment that looks like a credential rather than a route: long, and mixes letters
# with digits (e.g. Uptime Kuma push tokens, Zapier/Composio-style keyed MCP URLs).
_TOKENISH = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_\-.~]{16,}$")
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{8,}")
_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>]+")
_MIN_SECRET_LEN = 6  # shorter "secrets" would scrub ordinary words out of messages


def redact_url(url: str | None, *, whole_path: bool = False) -> str | None:
    """``url`` with userinfo, credential query values and token-like path segments masked.
    ``whole_path`` masks the entire path and query (for webhook URLs: Slack, Discord, ...
    put the secret anywhere in the path)."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return REDACTED
    if not parts.scheme or not parts.netloc:
        return url
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    if parts.username or parts.password:
        netloc = f"{REDACTED}@{netloc}"
    if whole_path:
        path = "/" + REDACTED if parts.path not in ("", "/") or parts.query else parts.path
        return urlunsplit((parts.scheme, netloc, path, "", ""))
    path = "/".join(REDACTED if _TOKENISH.match(seg) else seg for seg in parts.path.split("/"))
    query = urlencode(
        [(k, REDACTED if _SENSITIVE_PARAM.search(k) else v)
         for k, v in parse_qsl(parts.query, keep_blank_values=True)],
        safe="*",
    )
    return urlunsplit((parts.scheme, netloc, path, query, parts.fragment))


def _webhook_url(webhook: Any) -> str:
    return webhook.push_url if isinstance(webhook, UptimeKumaWebhook) else webhook.url


def redact_config(cfg: ServerConfig) -> dict[str, Any]:
    """JSON-ready dump of a server config (or a MonitoredServer) with secrets masked."""
    data = cfg.model_dump(mode="json")
    data["url"] = redact_url(cfg.url)
    # A pure reference (``${env:X}``, ``Bearer ${file:...}``) names a secret without holding
    # it: shown as-is, so it survives an export and can be edited.
    data["headers"] = {k: v if showable(v) else REDACTED for k, v in cfg.headers.items()}
    data["env"] = {k: v if showable(v) else REDACTED for k, v in cfg.env.items()}
    for out, webhook in zip(data["webhooks"], cfg.webhooks, strict=True):
        key = "push_url" if isinstance(webhook, UptimeKumaWebhook) else "url"
        out[key] = redact_url(_webhook_url(webhook), whole_path=True)
    return data


class RedactedValueError(ValueError):
    """A redacted placeholder was submitted where no stored secret can replace it."""


def _restore_map(new: dict[str, str], old: dict[str, str], what: str) -> dict[str, str]:
    old_ci = {k.lower(): v for k, v in old.items()}
    out = {}
    for key, value in new.items():
        if value == REDACTED:
            if key.lower() not in old_ci:
                raise RedactedValueError(f"{what} '{key}' is a redacted placeholder; "
                                         "enter the real value")
            value = old_ci[key.lower()]
        out[key] = value
    return out


def restore_secrets(new: ServerConfig, old: ServerConfig | None) -> ServerConfig:
    """Put stored secrets back where ``new`` still carries the redacted placeholders that
    :func:`redact_config` produced. Raises :class:`RedactedValueError` for a placeholder
    with nothing to restore it from (e.g. a redacted export imported elsewhere)."""
    old_headers = old.headers if old else {}
    old_env = old.env if old else {}
    update: dict[str, Any] = {
        "headers": _restore_map(new.headers, old_headers, "header"),
        "env": _restore_map(new.env, old_env, "environment variable"),
    }
    if old is not None and old.url and new.url == redact_url(old.url) and new.url != old.url:
        update["url"] = old.url
    webhooks = []
    for wh in new.webhooks:
        url = _webhook_url(wh)
        if REDACTED in url and old is not None:
            match = next(
                (o for o in old.webhooks if type(o) is type(wh)
                 and redact_url(_webhook_url(o), whole_path=True) == url),
                None,
            )
            if match is not None:
                wh = wh.model_copy(update={
                    "push_url" if isinstance(wh, UptimeKumaWebhook) else "url":
                        _webhook_url(match)
                })
        webhooks.append(wh)
    update["webhooks"] = webhooks
    restored = new.model_copy(update=update)
    check_no_placeholders(restored)
    return restored


def check_no_placeholders(cfg: ServerConfig) -> None:
    """Refuse configs that would store a placeholder instead of a credential."""
    fields = [cfg.url or "", *cfg.headers.values(), *cfg.env.values(),
              *(_webhook_url(w) for w in cfg.webhooks)]
    if any(REDACTED in f for f in fields):
        raise RedactedValueError(
            "the configuration contains redacted placeholders (********) — it came from a "
            "redacted export; fill in the real credentials (or export with secrets)"
        )


def secret_values(cfg: ServerConfig) -> list[str]:
    """Every credential string the config holds, longest first (for :func:`scrub`)."""
    found: set[str] = set()
    for value in [*cfg.headers.values(), *cfg.env.values()]:
        found.add(value)
        found.update(m.group(0).split(None, 1)[1] for m in _BEARER.finditer(value))
    urls = [cfg.url] if cfg.url else []
    urls += [_webhook_url(w) for w in cfg.webhooks]
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        found.update(filter(None, [parts.username, parts.password]))
        found.update(v for k, v in parse_qsl(parts.query) if _SENSITIVE_PARAM.search(k))
        found.update(seg for seg in parts.path.split("/") if _TOKENISH.match(seg))
    return sorted((s for s in found if len(s) >= _MIN_SECRET_LEN), key=len, reverse=True)


def scrub(text: str | None, secrets: Iterable[str] = ()) -> str | None:
    """Remove ``secrets`` and credential-looking fragments from free text."""
    if not text:
        return text
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)) or "", text)

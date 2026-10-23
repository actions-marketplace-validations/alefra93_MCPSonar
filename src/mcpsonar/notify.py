"""What a human should be told about a check, and how to say it safely in a chat.

Chat notifications (Slack, Discord, email) speak in **changes**, not checks:

* the server **entered** a watched status (``down``, ``degraded``): once, not every minute;
* it is **back up**, with how long it was out;
* something **new** was detected: a tool change, the first check of a latency episode, a
  shift, flapping, a response drift. Checks marked ``ongoing`` are never re-notified.

Text in a notification partly comes from the monitored server (tool names, error messages,
tool-change details) and must be treated as hostile: it is stripped of invisible
characters, truncated, and escaped for each destination so it cannot mention ``@everyone``,
ping a channel, or pass off a link (see :func:`slack_text` and :func:`discord_payload`).
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field
from datetime import timedelta

from .models import CheckEvent, CheckStatus

MAX_LINE = 300
MAX_LINES = 8
BS = chr(92)  # a backslash, spelled out

_ICON = {"down": "🔴", "degraded": "🟠", "up": "✅", "anomaly": "🔎"}
_COLOR = {"down": 0xE5484D, "degraded": 0xF5A524, "up": 0x30A46C, "anomaly": 0x8E4EC6}


@dataclass
class Notification:
    level: str  # down | degraded | up | anomaly
    title: str
    lines: list[str] = field(default_factory=list)
    link: str | None = None

    @property
    def icon(self) -> str:
        return _ICON[self.level]


def clean(text: str | None, limit: int = MAX_LINE) -> str:
    """Untrusted text, made safe to display: no invisible/bidi characters, no line breaks
    (one line cannot fake another), bounded length."""
    text = "".join(ch for ch in (text or "") if unicodedata.category(ch) != "Cf")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 90:
        return f"{seconds}s"
    minutes = round(seconds / 60)
    if minutes < 90:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def notification_for(
    event: CheckEvent,
    name: str,
    on: list[CheckStatus],
    on_anomaly: bool = True,
    on_recovery: bool = True,
) -> Notification | None:
    """The notification this check deserves, or None (nothing changed worth saying)."""
    previous, current = event.previous_status, event.status
    note: Notification | None = None
    if previous != current and current in on:
        note = Notification(current.value, f"{name} is {current.value.upper()}")
        if event.detail:
            note.lines.append(clean(event.detail))
    elif (on_recovery and previous in on and current == CheckStatus.UP
          and previous is not None):
        title = f"{name} is back up"
        if event.previous_status_since is not None:
            title += (f" after {_duration(event.checked_at - event.previous_status_since)} "
                      f"{previous.value}")
        note = Notification("up", title)

    new = [a for a in event.anomalies if not a.ongoing]
    if on_anomaly and new:
        if note is None:
            noun = "finding" if len(new) == 1 else "findings"
            note = Notification("anomaly", f"{name}: {len(new)} new {noun}")
        note.lines += [f"{a.kind.replace('_', ' ')}: {clean(a.detail)}" for a in new]
    if note is None:
        return None
    if len(note.lines) > MAX_LINES:
        extra = len(note.lines) - MAX_LINES + 1
        note.lines = note.lines[: MAX_LINES - 1] + [f"… and {extra} more"]
    base = os.environ.get("MCPSONAR_PUBLIC_URL", "").rstrip("/")
    if base.startswith(("https://", "http://")):
        note.link = base
    return note


# ---- Slack ------------------------------------------------------------------------------ #
def _slack_escape(text: str) -> str:
    # Slack control sequences all live in <...>: <!channel>, <@U123>, <https://x|label>.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_text(note: Notification) -> str:
    lines = [f"{note.icon} *{_slack_escape(clean(note.title))}*"]
    lines += [f"• {_slack_escape(line)}" for line in note.lines]
    if note.link:
        lines.append(f"<{note.link}|Open MCPSonar>")
    return "\n".join(lines)


def slack_payload(note: Notification) -> dict:
    return {"text": slack_text(note)}


# ---- Discord ---------------------------------------------------------------------------- #
_DISCORD_SPECIAL = set("*_~`|[]()<>#@:-")


def _discord_escape(text: str) -> str:
    # Escaped markdown: no masked links, no headings or spoilers; mentions are also
    # disabled by allowed_mentions, belt and braces.
    return "".join(BS + ch if ch in _DISCORD_SPECIAL else ch for ch in text)


def discord_payload(note: Notification) -> dict:
    description = "\n".join(f"• {_discord_escape(line)}" for line in note.lines)
    embed = {
        "title": f"{note.icon} {clean(note.title, 240)}",
        "description": description[:3800],
        "color": _COLOR[note.level],
    }
    if note.link:
        embed["url"] = note.link
    return {"embeds": [embed], "allowed_mentions": {"parse": []}}


# ---- plain text (email) --------------------------------------------------------------- #
def plain_text(note: Notification) -> str:
    lines = [clean(note.title), ""] + [f"- {line}" for line in note.lines]
    if note.link:
        lines += ["", f"Open MCPSonar: {note.link}"]
    return "\n".join(lines) + "\n"

"""Chat notifications: one message per change, safe against hostile text.

Values below are fixtures; the webhook URLs are fake.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx2
import pytest

from mcpsonar import monitor
from mcpsonar.adapters import DiscordAdapter, GenericWebhookAdapter, SlackAdapter
from mcpsonar.check_engine import CheckOutcome
from mcpsonar.models import Anomaly, CheckEvent, CheckStatus, ServerConfig
from mcpsonar.notify import clean, discord_payload, notification_for, slack_text
from mcpsonar.redact import REDACTED, redact_config
from mcpsonar.storage import Storage

ON = [CheckStatus.DOWN, CheckStatus.DEGRADED]
T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SLACK = "https://hooks.slack.com/services/T0FIXTURE/B0FIXTURE/fixturefixturefixture42"
DISCORD = "https://discord.com/api/webhooks/123456789/fixture-token-fixture-token-42"


def ev(status, prev=None, since=None, anomalies=(), detail=None, at=T0):
    return CheckEvent(server_id="s", status=status, latency_ms=10, checked_at=at,
                      previous_status=prev, previous_status_since=since,
                      anomalies=list(anomalies), detail=detail)


# ---- what deserves a message ----------------------------------------------------------- #
def test_entering_a_watched_status_is_notified_once():
    first = notification_for(ev("down", prev="up", detail="connection refused"), "calc", ON)
    assert first.level == "down" and first.title == "calc is DOWN"
    assert first.lines == ["connection refused"]
    assert notification_for(ev("down", prev="down"), "calc", ON) is None  # still down
    assert notification_for(ev("up", prev="up"), "calc", ON) is None


def test_first_check_already_down_is_notified():
    assert notification_for(ev("down", prev=None), "calc", ON).level == "down"
    assert notification_for(ev("up", prev=None), "calc", ON) is None


def test_recovery_says_how_long():
    note = notification_for(ev("up", prev="down", since=T0 - timedelta(minutes=12)), "calc", ON)
    assert note.level == "up" and note.title == "calc is back up after 12 min down"
    assert notification_for(ev("up", prev="down"), "calc", ON, on_recovery=False) is None
    # back up from a status nobody watches: nothing to recover from
    assert notification_for(ev("up", prev="degraded"), "calc", [CheckStatus.DOWN]) is None


def test_new_anomalies_only_not_ongoing_ones():
    spike = Anomaly(kind="latency_spike", detail="400ms vs 50ms")
    note = notification_for(ev("up", prev="up", anomalies=[spike]), "calc", ON)
    assert note.level == "anomaly" and note.lines == ["latency spike: 400ms vs 50ms"]
    ongoing = spike.model_copy(update={"ongoing": True})
    assert notification_for(ev("up", prev="up", anomalies=[ongoing]), "calc", ON) is None
    assert notification_for(ev("up", prev="up", anomalies=[spike]), "calc", ON,
                            on_anomaly=False) is None


def test_status_change_and_findings_share_one_message():
    change = Anomaly(kind="tool_change", detail="add: description changed")
    note = notification_for(ev("degraded", prev="up", anomalies=[change],
                               detail="1 unreviewed tool change(s)"), "calc", ON)
    assert note.title == "calc is DEGRADED"
    assert note.lines == ["1 unreviewed tool change(s)",
                          "tool change: add: description changed"]


# ---- hostile text --------------------------------------------------------------------- #
def test_untrusted_text_is_cleaned():
    hostile = "ok" + chr(0x202E) + "evil" + chr(0x200B) + "\nFAKE LINE"
    assert clean(hostile) == "okevil FAKE LINE"
    assert len(clean("x" * 1000)) == 300


def test_slack_cannot_ping_or_hide_links():
    change = Anomaly(kind="tool_change",
                     detail="<!channel> see <https://evil.example|docs> & more")
    text = slack_text(notification_for(ev("up", prev="up", anomalies=[change]), "a<b>", ON))
    assert "<!channel>" not in text and "<https://evil" not in text
    assert "&lt;!channel&gt;" in text and "a&lt;b&gt;" in text and "&amp; more" in text


def test_discord_cannot_mention_or_mask_links():
    change = Anomaly(kind="tool_change", detail="@everyone [click](https://evil.example)")
    payload = discord_payload(notification_for(ev("up", prev="up", anomalies=[change]),
                                               "calc", ON))
    assert payload["allowed_mentions"] == {"parse": []}
    description = payload["embeds"][0]["description"]
    bs = chr(92)  # escaped markdown: shown literally, never a mention or a link
    assert f"{bs}@everyone" in description
    assert f"{bs}[click{bs}]{bs}(https{bs}://evil.example{bs})" in description


# ---- delivery ------------------------------------------------------------------------- #
def _recorder():
    sent = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append((str(request.url), json.loads(request.content)))
        return httpx2.Response(200)

    return sent, httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


async def test_slack_and_discord_post_once_per_change():
    sent, client = _recorder()
    slack = SlackAdapter(SLACK, "calculator", ON, client)
    discord = DiscordAdapter(DISCORD, "calculator", ON, client)
    for event in (ev("down", prev="up"), ev("down", prev="down"), ev("down", prev="down"),
                  ev("up", prev="down", since=T0 - timedelta(minutes=3))):
        await slack.send(event)
        await discord.send(event)
    await client.aclose()
    slack_msgs = [body["text"] for url, body in sent if url == SLACK]
    discord_titles = [body["embeds"][0]["title"] for url, body in sent if url == DISCORD]
    assert len(slack_msgs) == 2 and "calculator is DOWN" in slack_msgs[0]
    assert "back up after 3 min down" in slack_msgs[1]
    assert len(discord_titles) == 2 and discord_titles[1].endswith("back up after 3 min down")


async def test_generic_webhook_also_reports_the_recovery():
    sent, client = _recorder()
    hook = GenericWebhookAdapter("http://hook.example/x", ON, client)
    await hook.send(ev("up", prev="down"))
    await hook.send(ev("up", prev="up"))
    hook_off = GenericWebhookAdapter("http://hook.example/y", ON, client, on_recovery=False)
    await hook_off.send(ev("up", prev="down"))
    await client.aclose()
    assert [body["previous_status"] for _, body in sent] == ["down"]


# ---- pipeline and configuration -------------------------------------------------------- #
@pytest.fixture
async def storage():
    s = await Storage.open(":memory:")
    yield s
    await s.close()


async def test_pipeline_sets_previous_status_and_since(storage, monkeypatch):
    script = iter([("up", 0), ("down", 1), ("down", 2), ("up", 3)])

    async def fake(server_id, cfg):
        status, minute = next(script)
        return CheckOutcome(CheckEvent(server_id=server_id, status=status, latency_ms=10,
                                       checked_at=T0 + timedelta(minutes=minute)), None)

    monkeypatch.setattr(monitor, "run_check", fake)
    cfg = ServerConfig(url="http://x", on_tool_change="ignore")
    events = [await monitor.process_check(storage, "s", cfg) for _ in range(4)]
    assert [e.previous_status for e in events] == [None, "up", "down", "down"]
    assert events[3].previous_status_since == T0 + timedelta(minutes=1)  # down began here


def test_chat_webhooks_need_https_and_are_masked():
    with pytest.raises(ValueError, match="https"):
        ServerConfig(url="http://x", webhooks=[{"type": "slack", "url": "http://hooks.x/y"}])
    cfg = ServerConfig(url="http://x", webhooks=[{"type": "slack", "url": SLACK},
                                                  {"type": "discord", "url": DISCORD}])
    shown = json.dumps(redact_config(cfg))
    assert "fixturefixture" not in shown and "fixture-token" not in shown
    assert REDACTED in shown

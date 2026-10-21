"""Secret references: syntax, the read allowlist, resolution at check time, and that the
resolved value never reaches storage, the API view or check details.

Values below are fake fixtures, not credentials.
"""

from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError

from mcpsonar.check_engine import run_check
from mcpsonar.loader import ConfigError, load_config
from mcpsonar.models import ServerConfig
from mcpsonar.redact import REDACTED, redact_config
from mcpsonar.secretref import (
    SecretRefError,
    check_config,
    check_syntax,
    resolve,
    resolve_value,
    showable,
)
from mcpsonar.services import inspect_server

FAKE = "fixture-not-a-secret-7c1d"
FIXTURE = Path(__file__).parent / "fixtures" / "scripted_server.py"


@pytest.fixture
def secrets_dir(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir()
    return d


def _env(secrets_dir: Path, **extra: str) -> dict[str, str]:
    return {"MCPSONAR_SECRETS_DIR": str(secrets_dir), **extra}


# ---- syntax ------------------------------------------------------------------- #
@pytest.mark.parametrize("value", [
    "${vault:x}", "${env:}", "${env:1BAD}", "${env:A-B}", "Bearer ${env:X", "${file:relative/p}",
    "${}",
])
def test_malformed_references_are_rejected_by_the_model(value):
    with pytest.raises(SecretRefError):
        check_syntax(value)
    with pytest.raises(ValidationError):
        ServerConfig(url="https://example.com/mcp", headers={"Authorization": value})


def test_plain_values_are_untouched():
    cfg = ServerConfig(url="https://example.com/mcp", headers={"X-Key": "literal$value"})
    assert resolve(cfg, {}) is cfg


# ---- the allowlist ------------------------------------------------------------------ #
def test_env_needs_the_prefix_or_an_explicit_listing():
    env = {"GITHUB_TOKEN": FAKE, "MCPSONAR_SECRET_GH": FAKE}
    assert resolve_value("Bearer ${env:MCPSONAR_SECRET_GH}", env) == f"Bearer {FAKE}"
    with pytest.raises(SecretRefError, match="not allowed"):
        resolve_value("${env:GITHUB_TOKEN}", env)
    listed = {**env, "MCPSONAR_SECRET_ENV": "OTHER, GITHUB_TOKEN"}
    assert resolve_value("${env:GITHUB_TOKEN}", listed) == FAKE


def test_internal_variables_are_not_readable_by_default():
    with pytest.raises(SecretRefError, match="not allowed"):
        resolve_value("${env:MCPSONAR_SETUP_TOKEN}", {"MCPSONAR_SETUP_TOKEN": FAKE})


def test_files_only_inside_the_secret_directories(secrets_dir, tmp_path):
    (secrets_dir / "key").write_text(FAKE + "\n", encoding="utf-8")
    outside = tmp_path / "id_rsa"
    outside.write_text("private", encoding="utf-8")
    env = _env(secrets_dir)
    assert resolve_value(f"${{file:{secrets_dir / 'key'}}}", env) == FAKE  # newline removed
    for path in (outside, secrets_dir / ".." / "id_rsa"):
        with pytest.raises(SecretRefError, match="outside the secret directories"):
            resolve_value(f"${{file:{path}}}", env)


def test_symlink_out_of_the_secret_directory_is_refused(secrets_dir, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("private", encoding="utf-8")
    link = secrets_dir / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks need extra privileges on this system")
    with pytest.raises(SecretRefError, match="outside"):
        resolve_value(f"${{file:{link}}}", _env(secrets_dir))


def test_unresolvable_references_name_the_problem_not_a_value(secrets_dir):
    env = _env(secrets_dir)
    big = secrets_dir / "big"
    big.write_bytes(b"x" * (64 * 1024 + 1))
    cases = {
        "${env:MCPSONAR_SECRET_MISSING}": "not set",
        f"${{file:{secrets_dir / 'missing'}}}": "file not found",
        f"${{file:{big}}}": "larger than",
    }
    for value, reason in cases.items():
        with pytest.raises(SecretRefError, match=reason):
            resolve_value(value, env)


def test_resolved_header_with_a_line_break_is_refused(secrets_dir):
    (secrets_dir / "two").write_text("a\nX-Injected: 1", encoding="utf-8")
    cfg = ServerConfig(url="https://example.com/mcp",
                       headers={"X-Key": f"${{file:{secrets_dir / 'two'}}}"})
    with pytest.raises(SecretRefError, match="line break"):
        resolve(cfg, _env(secrets_dir))


# ---- what is shown and stored ------------------------------------------------------- #
def test_api_view_shows_references_and_masks_literals():
    cfg = ServerConfig(
        url="https://example.com/mcp",
        headers={"Authorization": "Bearer ${env:MCPSONAR_SECRET_GH}",
                 "X-Mixed": "abc123${env:MCPSONAR_SECRET_GH}", "X-Literal": FAKE},
    )
    view = redact_config(cfg)["headers"]
    assert view == {"Authorization": "Bearer ${env:MCPSONAR_SECRET_GH}",
                    "X-Mixed": REDACTED, "X-Literal": REDACTED}
    assert showable("${file:/run/secrets/k}") and not showable(FAKE)


def test_config_file_with_a_forbidden_reference_fails_early(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text('servers:\n  s:\n    url: "https://example.com/mcp"\n'
                    '    headers: { Authorization: "Bearer ${env:AWS_SECRET_ACCESS_KEY}" }\n',
                    encoding="utf-8")
    with pytest.raises(ConfigError, match="server 's'.*not allowed"):
        load_config(path)


def test_check_config_names_the_field():
    cfg = ServerConfig(command="x", transport="stdio", env={"KEY": "${env:HOME}"})
    with pytest.raises(SecretRefError, match="env 'KEY'"):
        check_config(cfg, {})


# ---- end to end: resolved at check time, never echoed ------------------------------- #
class _Recorder(BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []

    def do_POST(self):
        type(self).seen.append(self.headers.get("Authorization", ""))
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_DELETE = do_POST

    def log_message(self, *args):
        pass


async def test_http_header_is_resolved_for_the_check_only(monkeypatch):
    monkeypatch.setenv("MCPSONAR_SECRET_DEMO", FAKE)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    handler = type("R", (_Recorder,), {"seen": []})
    server = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = ServerConfig(url=f"http://127.0.0.1:{port}/mcp",
                           headers={"Authorization": "Bearer ${env:MCPSONAR_SECRET_DEMO}"})
        event = (await run_check("s", cfg)).event
    finally:
        server.shutdown()
    assert handler.seen and set(handler.seen) == {f"Bearer {FAKE}"}
    assert cfg.headers["Authorization"] == "Bearer ${env:MCPSONAR_SECRET_DEMO}"  # unchanged
    assert FAKE not in event.model_dump_json()


async def test_unresolvable_reference_makes_the_check_down_with_a_reason(monkeypatch):
    monkeypatch.delenv("MCPSONAR_SECRET_ABSENT", raising=False)
    cfg = ServerConfig(url="http://127.0.0.1:1/mcp",
                       headers={"Authorization": "Bearer ${env:MCPSONAR_SECRET_ABSENT}"})
    event = (await run_check("s", cfg)).event
    assert event.status == "down"
    assert event.detail == ("header 'Authorization': '${env:MCPSONAR_SECRET_ABSENT}': "
                            "environment variable not set")


async def test_stdio_env_reference_reaches_the_child_process(monkeypatch):
    monkeypatch.setenv("MCPSONAR_SECRET_CHILD", FAKE)
    cfg = ServerConfig(transport="stdio", command=sys.executable,
                       args=[str(FIXTURE), "env", FAKE],
                       env={"FIXTURE_KEY": "${env:MCPSONAR_SECRET_CHILD}"})
    result = await inspect_server(cfg, "child")
    assert result.error is None and list(result.tools) == ["match"]

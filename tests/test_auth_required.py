"""Protected servers (401/403) and validators for every known spec version."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcpsonar.check_engine import run_check
from mcpsonar.models import CheckStatus, ServerConfig
from mcpsonar.scan import build_config, scan
from mcpsonar.validators import get_validator


class _Protected(BaseHTTPRequestHandler):
    """Answers every request like a hosted MCP server that requires OAuth."""

    code = 401

    def _deny(self):
        self.send_response(self.code)
        self.send_header("WWW-Authenticate", 'Bearer resource_metadata="https://x/.well-known/'
                                             'oauth-protected-resource"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_DELETE = _deny

    def log_message(self, *args):  # keep test output clean
        pass


def _serve(code):
    handler = type("H", (_Protected,), {"code": code})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}/mcp"


@pytest.fixture(params=[401, 403])
def protected_url(request):
    server, url = _serve(request.param)
    yield url
    server.shutdown()


async def test_rate_limited_is_degraded_not_down():
    server, url = _serve(429)
    try:
        ev = (await run_check("p", ServerConfig(url=url))).event
        assert ev.status == CheckStatus.DEGRADED and "rate limited" in ev.detail
    finally:
        server.shutdown()


async def test_anonymous_401_is_up_with_auth_required(protected_url):
    out = await run_check("p", ServerConfig(url=protected_url))
    ev = out.event
    assert ev.status == CheckStatus.UP and ev.auth_required
    assert "MCP OAuth required" in ev.detail and ev.latency_ms > 0
    assert out.tools is None  # nothing to pin


async def test_rejected_credentials_are_down(protected_url):
    cfg = ServerConfig(url=protected_url, headers={"Authorization": "Bearer expired"})
    ev = (await run_check("p", cfg)).event
    assert ev.status == CheckStatus.DOWN and ev.auth_required
    assert "credentials rejected" in ev.detail


async def test_scan_explains_how_to_authenticate(protected_url):
    cfg, label = build_config(protected_url, None, None, [], [])
    result = await scan(cfg, label, timeout_s=5)
    assert result.error.startswith("authentication required")


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_every_published_spec_version_has_a_validator(version):
    assert get_validator(version) is not None

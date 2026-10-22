"""Email notifications against a real (local, scripted) SMTP server: STARTTLS with a
certificate generated for the test, implicit TLS, authentication, the outbound policy and
the masking of the password. Values below are fixtures, not credentials."""

from __future__ import annotations

import base64
import datetime as dt
import socket
import ssl
import threading
from email import message_from_bytes
from email.policy import default as default_policy

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcpsonar.adapters.email import EmailAdapter, SMTPDeliveryError
from mcpsonar.models import CheckEvent, CheckStatus, EmailWebhook, ServerConfig
from mcpsonar.netpolicy import OutboundPolicy, set_policy
from mcpsonar.redact import REDACTED, RedactedValueError, redact_config, restore_secrets

PASSWORD = "fixture-smtp-password-1"


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    folder = tmp_path_factory.mktemp("tls")
    cert_file, key_file = folder / "cert.pem", folder / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_file, key_file


class FakeSMTP:
    """Just enough ESMTP: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, QUIT."""

    def __init__(self, cert, mode: str = "starttls") -> None:
        self.mode = mode  # starttls | tls | plain-only (no STARTTLS offered)
        self.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ctx.load_cert_chain(*cert)
        self.messages: list[bytes] = []
        self.auth: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                self._session(conn)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    def _session(self, conn) -> None:
        tls = False
        if self.mode == "tls":
            conn = self.server_ctx.wrap_socket(conn, server_side=True)
            tls = True
        f = conn.makefile("rb")

        def say(line: str) -> None:
            conn.sendall(line.encode() + b"\r\n")

        say("220 fake ESMTP")
        while line := f.readline():
            cmd = line.decode().strip()
            verb = cmd.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                caps = ["250-fake"]
                if self.mode == "starttls" and not tls:
                    caps.append("250-STARTTLS")
                caps.append("250 AUTH PLAIN")
                say("\r\n".join(caps))
            elif verb == "STARTTLS":
                say("220 go ahead")
                conn = self.server_ctx.wrap_socket(conn, server_side=True)
                f, tls = conn.makefile("rb"), True
            elif verb == "AUTH":
                self.auth.append(base64.b64decode(cmd.split()[2]).decode())
                say("235 ok")
            elif verb in ("MAIL", "RCPT"):
                say("250 ok")
            elif verb == "DATA":
                say("354 go")
                data = b""
                while (chunk := f.readline()) not in (b".\r\n", b""):
                    data += chunk
                self.messages.append(data)
                say("250 queued")
            elif verb == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")

    def close(self) -> None:
        self.sock.close()


def _cfg(port: int, **kw) -> EmailWebhook:
    base = {"host": "localhost", "port": port, "sender": "mcpsonar@example.com",
            "to": ["ops@example.com"], "username": "mcpsonar",
            "password": "${env:MCPSONAR_SECRET_SMTP}"}
    return EmailWebhook(**{**base, **kw})


def _client_ctx(cert) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert[0]))


DOWN = CheckEvent(server_id="s", status=CheckStatus.DOWN, latency_ms=0,
                  previous_status=CheckStatus.UP, detail="connection refused")


@pytest.fixture(autouse=True)
def _secret_and_policy(monkeypatch):
    monkeypatch.setenv("MCPSONAR_SECRET_SMTP", PASSWORD)
    set_policy(None)
    yield
    set_policy(None)


async def test_starttls_login_and_message(cert):
    server = FakeSMTP(cert)
    adapter = EmailAdapter(_cfg(server.port), "calculator", httpx2.AsyncClient(),
                           ssl_context=_client_ctx(cert))
    try:
        await adapter.send(DOWN)
        await adapter.send(DOWN.model_copy(update={"previous_status": CheckStatus.DOWN}))
    finally:
        server.close()
    assert len(server.messages) == 1  # staying down is not a new message
    assert server.auth == ["\0mcpsonar\0" + PASSWORD]  # the reference was resolved
    mail = message_from_bytes(server.messages[0], policy=default_policy)
    assert mail["Subject"].startswith("[MCPSonar]") and "calculator is DOWN" in mail["Subject"]
    assert mail["To"] == "ops@example.com"
    assert "connection refused" in mail.get_content()


async def test_implicit_tls(cert):
    server = FakeSMTP(cert, mode="tls")
    adapter = EmailAdapter(_cfg(server.port, security="tls"), "calc", httpx2.AsyncClient(),
                           ssl_context=_client_ctx(cert))
    try:
        await adapter.send(DOWN)
    finally:
        server.close()
    assert len(server.messages) == 1


async def test_starttls_is_required_not_opportunistic(cert):
    server = FakeSMTP(cert, mode="plain-only")
    adapter = EmailAdapter(_cfg(server.port), "calc", httpx2.AsyncClient(),
                           ssl_context=_client_ctx(cert))
    try:
        with pytest.raises(SMTPDeliveryError, match="STARTTLS") as err:
            await adapter.send(DOWN)
    finally:
        server.close()
    assert server.messages == [] and server.auth == []  # nothing sent, password kept
    assert PASSWORD not in str(err.value)


async def test_untrusted_certificate_is_refused(cert):
    server = FakeSMTP(cert)
    adapter = EmailAdapter(_cfg(server.port), "calc", httpx2.AsyncClient(),
                           ssl_context=ssl.create_default_context())  # doesn't trust it
    try:
        with pytest.raises(SMTPDeliveryError, match="STARTTLS"):
            await adapter.send(DOWN)
    finally:
        server.close()
    assert server.auth == []


async def test_outbound_policy_applies_to_smtp(cert):
    set_policy(OutboundPolicy.from_env({"MCPSONAR_OUTBOUND_DENY": "127.0.0.0/8,::1/128"}))
    adapter = EmailAdapter(_cfg(2525), "calc", httpx2.AsyncClient())
    with pytest.raises(SMTPDeliveryError, match="outbound policy blocked localhost"):
        await adapter.send(DOWN)


def test_password_is_masked_restored_and_policed():
    literal = _cfg(587, password=PASSWORD)
    cfg = ServerConfig(url="http://x", webhooks=[literal])
    shown = redact_config(cfg)["webhooks"][0]
    assert shown["password"] == REDACTED
    sent_back = ServerConfig.model_validate({**cfg.model_dump(), "webhooks": [shown]})
    assert restore_secrets(sent_back, cfg).webhooks[0].password == PASSWORD
    with pytest.raises(RedactedValueError):
        restore_secrets(sent_back, None)  # nothing to restore it from
    # a reference is not a secret: shown as-is
    ref = ServerConfig(url="http://x", webhooks=[_cfg(587)])
    assert redact_config(ref)["webhooks"][0]["password"] == "${env:MCPSONAR_SECRET_SMTP}"


def test_plaintext_only_to_localhost():
    with pytest.raises(ValueError, match="localhost"):
        _cfg(25, host="smtp.example.com", security="none")
    assert _cfg(1025, security="none").security == "none"

"""Dashboard login: first-run setup, session gating, login/logout, password hashing."""

from __future__ import annotations

import time

from httpx import ASGITransport, AsyncClient

from mcpsonar.auth import hash_password, sign_session, verify_password, verify_session
from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage


async def _client(require_auth=True):
    storage = await Storage.open(":memory:")
    store = StateStore()
    scheduler = Scheduler(storage, store)
    app = create_app(storage, store, scheduler, require_auth=require_auth)
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    return client, scheduler, storage


# ---- unit: hashing + session signing --------------------------------------- #
def test_password_hash_roundtrip():
    salt, h = hash_password("hunter2000")
    assert verify_password("hunter2000", salt, h)
    assert not verify_password("wrong", salt, h)


def test_session_signature_is_tamper_evident():
    tok = sign_session({"u": "admin", "iat": int(time.time())}, "secret")
    assert verify_session(tok, "secret")["u"] == "admin"
    assert verify_session(tok, "different-secret") is None  # wrong key
    assert verify_session(tok[:-1] + ("0" if tok[-1] != "0" else "1"), "secret") is None  # tampered
    # an old token is rejected by max-age
    old = sign_session({"u": "admin", "iat": 1}, "secret")
    assert verify_session(old, "secret") is None


# ---- full flow ------------------------------------------------------------- #
async def test_setup_then_protected_access_then_logout():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        # before setup: status says setup required, and the API is locked
        s = (await client.get("/api/auth/status")).json()
        assert s["auth_enabled"] and s["setup_required"] and not s["authenticated"]
        assert (await client.get("/api/servers")).status_code == 401

        # create the admin -> cookie set -> API now reachable
        r = await client.post("/api/auth/setup", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200
        assert (await client.get("/api/servers")).status_code == 200

        # a second setup is refused
        assert (await client.post(
            "/api/auth/setup", json={"username": "x", "password": "supersecret"}
        )).status_code == 400

        # logout clears the session -> locked again
        await client.post("/api/auth/logout")
        assert (await client.get("/api/servers")).status_code == 401
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_login_rejects_bad_credentials():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        await storage.create_admin("admin", "supersecret")
        assert (await client.post(
            "/api/auth/login", json={"username": "admin", "password": "nope"}
        )).status_code == 401
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert r.status_code == 200
        assert (await client.get("/api/servers")).status_code == 200
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_short_password_rejected_at_setup():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        assert (await client.post(
            "/api/auth/setup", json={"username": "admin", "password": "short"}
        )).status_code == 400
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_metrics_public_even_with_auth():
    client, scheduler, storage = await _client(require_auth=True)
    try:
        assert (await client.get("/metrics")).status_code == 200  # Prometheus can scrape
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()


async def test_no_auth_mode_leaves_everything_open():
    client, scheduler, storage = await _client(require_auth=False)
    try:
        assert (await client.get("/api/servers")).status_code == 200
        assert (await client.get("/api/auth/status")).json()["authenticated"] is True
    finally:
        await client.aclose()
        await scheduler.stop()
        await storage.close()

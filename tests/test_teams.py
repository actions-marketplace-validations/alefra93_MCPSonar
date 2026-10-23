"""Accounts, roles, sessions, tokens bound to their owner, and the append-only audit log.

Every request goes through the real app (ASGI): middleware, role checks and handlers.
Passwords below are fixtures for an in-memory instance.
"""

from __future__ import annotations

import sqlite3
import sys

import pytest
from httpx2 import ASGITransport, AsyncClient

from mcpsonar.dashboard import create_app
from mcpsonar.scheduler import Scheduler
from mcpsonar.state import StateStore
from mcpsonar.storage import Storage

PW = {"admin": "admin-fixture-pw", "olivia": "operator-fixture-pw", "vic": "viewer-fixture-pw"}
SECRET = "Bearer fixture-header-secret-123"
HTTP_SERVER = {"name": "remote", "url": "http://127.0.0.1:1/mcp", "enabled": False,
               "headers": {"Authorization": SECRET}}
STDIO_SERVER = {"name": "local", "transport": "stdio", "command": sys.executable,
                "args": ["-c", "pass", "--api-key=fixture-arg-secret"], "enabled": False}


@pytest.fixture
async def team():
    storage = await Storage.open(":memory:")
    scheduler = Scheduler(storage, store := StateStore())
    app = create_app(storage, store, scheduler, require_auth=True)
    clients = []

    def client():
        c = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        clients.append(c)
        return c

    async def login(name):
        c = client()
        r = await c.post("/api/auth/login", json={"username": name, "password": PW[name]})
        assert r.status_code == 200, r.text
        return c

    await storage.create_admin("admin", PW["admin"])
    admin = await login("admin")
    for name, role in (("olivia", "operator"), ("vic", "viewer")):
        r = await admin.post("/api/users", json={"username": name, "password": PW[name],
                                                 "role": role})
        assert r.status_code == 201, r.text
    yield {"storage": storage, "admin": admin, "login": login, "client": client}
    for c in clients:
        await c.aclose()
    await scheduler.stop()
    await storage.close()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


async def _token(c, scope):
    r = await c.post("/api/tokens", json={"name": f"t-{scope}", "scope": scope})
    assert r.status_code == 201, r.text
    return r.json()["token"]


# ---- the permission matrix ------------------------------------------------------------- #
async def test_viewer_reads_but_changes_nothing(team):
    vic = await team["login"]("vic")
    assert (await vic.get("/api/servers")).status_code == 200
    assert (await vic.post("/api/servers", json=HTTP_SERVER)).status_code == 403
    assert (await vic.get("/api/users")).status_code == 403
    assert (await vic.get("/api/audit")).status_code == 403
    # ... but may look after their own account
    assert (await vic.get("/api/auth/sessions")).status_code == 200
    assert (await vic.post("/api/tokens", json={"name": "r", "scope": "read"})).status_code == 201
    r = await vic.post("/api/tokens", json={"name": "w", "scope": "write"})
    assert r.status_code == 403 and "read tokens only" in r.text


async def test_operator_manages_http_servers_not_stdio_nor_accounts(team):
    olivia = await team["login"]("olivia")
    created = await olivia.post("/api/servers", json=HTTP_SERVER)
    assert created.status_code == 201
    sid = created.json()["id"]
    assert (await olivia.post(f"/api/servers/{sid}/tool-changes/ack")).status_code == 200
    r = await olivia.post("/api/servers", json=STDIO_SERVER)
    assert r.status_code == 403 and "admin role" in r.text
    assert (await olivia.get("/api/export?include_secrets=true")).status_code == 403
    assert (await olivia.get("/api/export")).status_code == 200  # masked export is fine
    assert (await olivia.get("/api/users")).status_code == 403
    assert (await olivia.delete(f"/api/servers/{sid}")).status_code == 204


async def test_operator_can_pause_but_not_change_a_stdio_process(team):
    admin = team["admin"]
    sid = (await admin.post("/api/servers", json=STDIO_SERVER)).json()["id"]
    olivia = await team["login"]("olivia")
    renamed = {**STDIO_SERVER, "name": "renamed"}
    assert (await olivia.put(f"/api/servers/{sid}", json=renamed)).status_code == 200
    sneaky = {**renamed, "env": {"NODE_OPTIONS": "--require /tmp/x.js"}}
    r = await olivia.put(f"/api/servers/{sid}", json=sneaky)
    assert r.status_code == 403 and "admin role" in r.text


# ---- tokens follow their owner ----------------------------------------------------------- #
async def test_tokens_never_exceed_their_owner_or_act_as_admin(team):
    admin, storage = team["admin"], team["storage"]
    anon = team["client"]()
    admin_write = await _token(admin, "write")
    r = await anon.post("/api/servers", json=STDIO_SERVER, headers=bearer(admin_write))
    assert r.status_code == 403  # a token never acts as an admin
    assert (await anon.get("/api/users", headers=bearer(admin_write))).status_code == 403

    olivia = await team["login"]("olivia")
    op_write = await _token(olivia, "write")
    ok = await anon.post("/api/servers", json=HTTP_SERVER, headers=bearer(op_write))
    assert ok.status_code == 201
    await admin.patch("/api/users/olivia", json={"role": "viewer"})
    r = await anon.post("/api/servers", json=HTTP_SERVER, headers=bearer(op_write))
    assert r.status_code == 403  # demoting the owner demotes the token
    assert (await anon.get("/api/servers", headers=bearer(op_write))).status_code == 200
    assert (await admin.delete("/api/users/olivia")).status_code == 204
    assert (await anon.get("/api/servers", headers=bearer(op_write))).status_code == 401
    assert await storage.list_api_tokens("olivia") == []


async def test_token_of_an_account_removed_outside_the_api_stops_working(team):
    # e.g. the documented forgotten-password procedure deletes rows with SQL: tokens whose
    # owner no longer exists must not keep working.
    olivia = await team["login"]("olivia")
    token = await _token(olivia, "write")
    await team["storage"]._conn.execute("DELETE FROM users WHERE username = 'olivia'")
    anon = team["client"]()
    assert (await anon.get("/api/servers", headers=bearer(token))).status_code == 401


async def test_status_reports_the_effective_role(team):
    olivia = await team["login"]("olivia")
    token = await _token(olivia, "read")
    anon = team["client"]()
    assert (await olivia.get("/api/auth/status")).json()["role"] == "operator"
    assert (await anon.get("/api/auth/status", headers=bearer(token))).json()["role"] == "viewer"


# ---- accounts ------------------------------------------------------------------------------ #
async def test_the_last_admin_stays(team):
    admin = team["admin"]
    r = await admin.patch("/api/users/admin", json={"role": "operator"})
    assert r.status_code == 409 and "last admin" in r.text
    assert (await admin.delete("/api/users/admin")).status_code == 409
    await admin.patch("/api/users/olivia", json={"role": "admin"})
    assert (await admin.patch("/api/users/admin", json={"role": "operator"})).status_code == 200


async def test_usernames_are_unique_and_passwords_long_enough(team):
    admin = team["admin"]
    r = await admin.post("/api/users", json={"username": "vic", "password": "x" * 12})
    assert r.status_code == 409
    r = await admin.post("/api/users", json={"username": "new", "password": "short"})
    assert r.status_code == 400


async def test_password_change_ends_other_sessions(team):
    first = await team["login"]("vic")
    second = await team["login"]("vic")
    r = await first.post("/api/auth/password",
                         json={"current_password": "wrong", "new_password": "x" * 12})
    assert r.status_code == 403
    r = await first.post("/api/auth/password",
                         json={"current_password": PW["vic"], "new_password": "vic-new-pw-123"})
    assert r.status_code == 200
    assert (await first.get("/api/servers")).status_code == 200  # this session stays
    assert (await second.get("/api/servers")).status_code == 401  # the other one ended
    login = await team["client"]().post("/api/auth/login",
                                        json={"username": "vic", "password": "vic-new-pw-123"})
    assert login.status_code == 200


async def test_admin_reset_ends_sessions_and_tokens(team):
    olivia = await team["login"]("olivia")
    token = await _token(olivia, "read")
    r = await team["admin"].post("/api/users/olivia/password", json={"password": "reset-pw-1234"})
    assert r.status_code == 200 and r.json()["tokens_revoked"] == 1
    assert (await olivia.get("/api/servers")).status_code == 401
    anon = team["client"]()
    assert (await anon.get("/api/servers", headers=bearer(token))).status_code == 401


async def test_sessions_can_be_listed_and_ended(team):
    laptop = await team["login"]("vic")
    phone = await team["login"]("vic")
    sessions = (await laptop.get("/api/auth/sessions")).json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])
    assert "token_hash" not in other
    assert (await laptop.delete(f"/api/auth/sessions/{other['id']}")).status_code == 204
    assert (await phone.get("/api/servers")).status_code == 401
    # nobody can end someone else's session by id
    olivia = await team["login"]("olivia")
    mine = (await laptop.get("/api/auth/sessions")).json()[0]["id"]
    assert (await olivia.delete(f"/api/auth/sessions/{mine}")).status_code == 404


async def test_tokens_are_private_to_their_owner(team):
    olivia = await team["login"]("olivia")
    vic = await team["login"]("vic")
    await _token(olivia, "read")
    vic_token_id = (await vic.post("/api/tokens", json={"name": "v", "scope": "read"})).json()["id"]
    assert [t["created_by"] for t in (await olivia.get("/api/tokens")).json()] == ["olivia"]
    assert (await olivia.delete(f"/api/tokens/{vic_token_id}")).status_code == 404
    everyone = {t["created_by"] for t in (await team["admin"].get("/api/tokens")).json()}
    assert everyone == {"olivia", "vic"}


# ---- the audit log ------------------------------------------------------------------------- #
async def test_audit_records_who_did_what_without_secrets(team):
    admin, storage = team["admin"], team["storage"]
    olivia = await team["login"]("olivia")
    sid = (await olivia.post("/api/servers", json=HTTP_SERVER)).json()["id"]
    await storage.add_tool_changes(sid, [])  # nothing pending: no approval entry
    await admin.post("/api/servers", json=STDIO_SERVER)
    await admin.patch("/api/users/vic", json={"role": "operator"})
    log = (await admin.get("/api/audit")).json()
    actions = [(e["actor"], e["action"]) for e in log]
    assert ("admin", "user.created") in actions and ("olivia", "account.login") in actions
    assert ("olivia", "server.created") in actions and ("admin", "user.role_changed") in actions
    role_change = next(e for e in log if e["action"] == "user.role_changed")
    assert role_change["detail"] == {"from": "viewer", "to": "operator"}
    dumped = str(log)
    assert "fixture-header-secret" not in dumped and "fixture-arg-secret" not in dumped
    assert all(pw not in dumped for pw in PW.values())


async def test_audit_log_is_append_only_in_the_database(team, tmp_path):
    storage = await Storage.open(tmp_path / "a.db")
    try:
        await storage.audit("someone", "test.action", "x")
    finally:
        await storage.close()
    with sqlite3.connect(tmp_path / "a.db") as conn:
        for sql in ("UPDATE audit_log SET actor = 'nobody'", "DELETE FROM audit_log"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(sql)
        assert conn.execute("SELECT actor FROM audit_log").fetchall() == [("someone",)]
    conn.close()


async def test_accounts_from_older_versions_are_admins(tmp_path):
    # Before v0.9 the one account was the admin: the migration keeps it that way.
    from pathlib import Path

    from mcpsonar.auth import hash_password

    db = tmp_path / "old.db"
    dump = Path(__file__).parent / "fixtures" / "db" / "v0.7.0.sql"
    salt, pw_hash = hash_password(PW["admin"])
    with sqlite3.connect(db) as conn:
        conn.executescript(dump.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO users (username, password_hash, salt, created_at) "
                     "VALUES ('owner', ?, ?, '2026-01-01T00:00:00+00:00')", (pw_hash, salt))
    conn.close()
    storage = await Storage.open(db)
    try:
        assert (await storage.get_user("owner"))["role"] == "admin"
        assert await storage.verify_credentials("owner", PW["admin"])
    finally:
        await storage.close()

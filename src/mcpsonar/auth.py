"""Accounts, roles and authentication for the dashboard and the API.

Self-contained, no extra dependencies:

* **Roles**: ``viewer`` (read everything), ``operator`` (also check, add / edit / delete HTTP
  servers, approve tool changes), ``admin`` (also stdio servers, exports with secrets,
  accounts and the audit log). The first account, created through setup, is an admin; the
  last admin can be neither demoted nor deleted.
* **Who did what** goes to an append-only audit log (database triggers refuse UPDATE and
  DELETE on it): logins, account and token changes, server changes, approvals.

* **Passwords** are hashed with PBKDF2-HMAC-SHA256 (stdlib) at 600k iterations, stored as
  ``pbkdf2_sha256$<iterations>$<hex>``. Hashes from v0.5 and earlier (bare hex, 200k
  iterations) still verify and are re-hashed transparently on the next successful login.
  Hashing runs in a worker thread so a login never stalls the event loop (and the checks).
* **Sessions** are random 256-bit tokens. Only their SHA-256 is stored (``sessions`` table),
  so logout really revokes a session and a leaked database does not leak live cookies.
* **Cookies** are ``HttpOnly`` + ``SameSite=Lax``; ``Secure`` is set when the request
  arrived over HTTPS (``cookie_secure="auto"``, the default — uvicorn derives the scheme from
  ``X-Forwarded-Proto`` only for proxies listed in ``FORWARDED_ALLOW_IPS``), or always/never.
* **First-admin bootstrap**: while no admin exists, ``/api/auth/setup`` creates one. When the
  app is given a ``setup_token`` (``mcpsonar run`` always gives one: random and printed in the
  log, or taken from ``MCPSONAR_SETUP_TOKEN``), setup requires it — so whoever reaches a
  freshly started, publicly exposed instance first cannot claim it. Creation is atomic: of
  two concurrent setup requests, exactly one wins.
* **Brute force**: repeated failed logins from one client address are throttled (429).
* **API tokens** (for the CLI and automation): ``Authorization: Bearer mcps_…``. Stored as
  SHA-256 only, shown once at creation, scoped ``read`` or ``write``, optionally expiring,
  revocable. A token acts with the *lower* of its scope (read = viewer, write = operator)
  and its owner's current role, and never as an admin: admin actions need a signed-in
  dashboard session. A token whose owner was deleted stops working. Tokens are created and
  revoked only from a dashboard session; a token can never mint or list tokens. Bearer
  requests carry no cookie, so they are not exposed to CSRF.

When ``require_auth`` is off (``--no-auth``, behind a trusted proxy / on localhost) the
middleware is not installed and everything is open. ``/metrics`` stays outside the login so
Prometheus can scrape it (protect it with ``MCPSONAR_METRICS_TOKEN`` if it must not be public).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import __version__

if TYPE_CHECKING:
    from .storage import Storage

COOKIE_NAME = "mcpsonar_session"
MAX_AGE = 7 * 24 * 3600  # 7 days
PBKDF2_ITERATIONS = 600_000  # OWASP Password Storage Cheat Sheet value for PBKDF2-HMAC-SHA256
LEGACY_ITERATIONS = 200_000  # bare-hex hashes written by v0.5 and earlier
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 1024  # PBKDF2 cost grows with input length; don't let a request pick it
MAX_USERNAME_LEN = 64
_HASH_PREFIX = "pbkdf2_sha256"
_PUBLIC_PATHS = {
    "/login",
    "/api/auth/status",
    "/api/auth/login",
    "/api/auth/setup",
    "/metrics",
    "/favicon.ico",
}

CookieSecure = Literal["auto", "always", "never"]
Role = Literal["viewer", "operator", "admin"]

ROLES: tuple[str, ...] = ("viewer", "operator", "admin")
_RANK = {role: i for i, role in enumerate(ROLES)}
TOKEN_CAP = {"read": "viewer", "write": "operator"}  # a token never acts as an admin
# Paths any signed-in user may POST/DELETE to, whatever their role (their own account).
_SELF_SERVICE = ("/api/auth/", "/api/tokens")


def lower_role(a: str, b: str) -> str:
    return a if _RANK[a] <= _RANK[b] else b


@dataclass(frozen=True)
class Principal:
    """Who is making a request, and with which effective role."""

    name: str
    role: str
    via: Literal["session", "token", "open"]
    token: str | None = None
    session_id: str | None = None

    @property
    def actor(self) -> str:
        """How the audit log names this principal."""
        return f"{self.name} (token {self.token})" if self.token else self.name


OPEN = Principal("anonymous (login disabled)", "admin", "open")


def principal(request: Request) -> Principal:
    """The request's principal; with the login disabled (``--no-auth``), everyone is OPEN."""
    return getattr(request.state, "principal", OPEN)


def require(request: Request, role: str, *, session: bool = False) -> Principal:
    """403 unless the request may act as ``role`` (and, with ``session``, comes from a
    signed-in dashboard session rather than an API token)."""
    who = principal(request)
    if session and who.via == "token":
        raise HTTPException(403, "this needs a signed-in dashboard session, not an API token")
    if _RANK[who.role] < _RANK[role]:
        raise HTTPException(403, f"this needs the {role} role (yours: {who.role})")
    return who


# ---- password hashing ------------------------------------------------------- #
def hash_password(
    password: str, salt: str | None = None, iterations: int = PBKDF2_ITERATIONS
) -> tuple[str, str]:
    """Return ``(salt_hex, encoded_hash)`` for a password (PBKDF2-HMAC-SHA256)."""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return salt, f"{_HASH_PREFIX}${iterations}${dk.hex()}"


def _parse_hash(encoded: str) -> tuple[int, str]:
    if encoded.startswith(_HASH_PREFIX + "$"):
        _, iterations, digest = encoded.split("$", 2)
        return int(iterations), digest
    return LEGACY_ITERATIONS, encoded  # v0.5: bare hex digest


def verify_password(password: str, salt: str, encoded: str) -> bool:
    iterations, digest = _parse_hash(encoded)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return hmac.compare_digest(dk.hex(), digest)


def needs_rehash(encoded: str) -> bool:
    """True for hashes weaker than the current policy (upgrade them on the next login)."""
    return _parse_hash(encoded)[0] < PBKDF2_ITERATIONS


# ---- session tokens --------------------------------------------------------- #
def new_session_token() -> str:
    return secrets.token_urlsafe(32)


API_TOKEN_PREFIX = "mcps_"  # recognizable by secret scanners and in logs


def new_api_token() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """What the database stores for a session token (never the token itself)."""
    return hashlib.sha256(token.encode()).hexdigest()


# ---- brute-force throttling ------------------------------------------------- #
class LoginThrottle:
    """Sliding-window limit on *failed* attempts per client address.

    Keyed by address only (not by username) so a stranger cannot lock the admin out by
    failing logins for "admin". The address is uvicorn's view of the client: it honours
    ``X-Forwarded-For`` only from proxies listed in ``FORWARDED_ALLOW_IPS``.
    """

    def __init__(
        self, max_failures: int = 10, window_s: float = 900.0, max_keys: int = 10_000
    ) -> None:
        self.max_failures = max_failures
        self.window_s = window_s
        self._max_keys = max_keys
        self._failures: dict[str, deque[float]] = {}

    def _recent(self, key: str, now: float) -> deque[float]:
        q = self._failures.get(key)
        if q is None:
            return deque()
        while q and now - q[0] > self.window_s:
            q.popleft()
        if not q:
            del self._failures[key]
        return q

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Seconds until ``key`` may try again (0 = allowed now)."""
        now = time.monotonic() if now is None else now
        q = self._recent(key, now)
        if len(q) < self.max_failures:
            return 0
        return max(1, int(self.window_s - (now - q[0])) + 1)

    def failure(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        if key not in self._failures and len(self._failures) >= self._max_keys:
            # Bounded memory: forget the client whose last failure is the oldest.
            stalest = min(self._failures, key=lambda k: self._failures[k][-1])
            del self._failures[stalest]
        self._failures.setdefault(key, deque()).append(now)

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


class _Credentials(BaseModel):
    username: str = Field(max_length=MAX_USERNAME_LEN)
    password: str = Field(max_length=MAX_PASSWORD_LEN)


class _SetupRequest(_Credentials):
    setup_token: str | None = Field(default=None, max_length=256)


class _PasswordChange(BaseModel):
    current_password: str = Field(max_length=MAX_PASSWORD_LEN)
    new_password: str = Field(max_length=MAX_PASSWORD_LEN)


class _NewUser(_Credentials):
    role: Role = "viewer"


class _RoleChange(BaseModel):
    role: Role


class _PasswordReset(BaseModel):
    password: str = Field(max_length=MAX_PASSWORD_LEN)


class _TokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scope: Literal["read", "write"] = "read"
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


_READ_METHODS = {"GET", "HEAD"}


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def register_auth(
    app: FastAPI,
    storage: Storage,
    require_auth: bool = True,
    *,
    setup_token: str | None = None,
    cookie_secure: CookieSecure = "auto",
    throttle: LoginThrottle | None = None,
) -> None:
    """Install the auth middleware (if enabled) and the auth routes + login page."""
    throttle = throttle or LoginThrottle()
    setup_lock = asyncio.Lock()

    def _too_many(key: str) -> None:
        if wait := throttle.retry_after(key):
            raise HTTPException(
                429, "too many failed attempts, try again later", {"Retry-After": str(wait)}
            )

    async def _new_session(request: Request, username: str) -> str:
        return await storage.create_session(username, MAX_AGE, _client_key(request),
                                            request.headers.get("user-agent"))

    def _start_session(request: Request, token: str) -> JSONResponse:
        secure = cookie_secure == "always" or (
            cookie_secure == "auto" and request.url.scheme == "https"
        )
        resp = JSONResponse({"ok": True})
        resp.set_cookie(
            COOKIE_NAME, token, httponly=True, samesite="lax", secure=secure,
            max_age=MAX_AGE, path="/",
        )
        return resp

    async def _current_session(request: Request) -> dict | None:
        token = request.cookies.get(COOKIE_NAME)
        return await storage.get_session(token) if token else None

    async def _current_user(request: Request) -> str | None:
        session = await _current_session(request)
        return session["username"] if session else None

    async def _token_principal(bearer: str) -> Principal | None:
        api_token = await storage.get_api_token(bearer)
        if api_token is None:
            return None
        owner = await storage.get_user(api_token["created_by"])
        if owner is None:  # the account is gone: so is what it delegated
            return None
        role = lower_role(owner["role"], TOKEN_CAP[api_token["scope"]])
        return Principal(owner["username"], role, "token", token=api_token["name"])

    def _password_ok(password: str) -> None:
        if len(password) < MIN_PASSWORD_LEN:
            raise HTTPException(400, f"password must be at least {MIN_PASSWORD_LEN} characters")

    def _bearer(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        return value.strip() if scheme.lower() == "bearer" and value.strip() else None

    if require_auth:

        @app.middleware("http")
        async def _auth_mw(request: Request, call_next):
            path = request.url.path
            if path in _PUBLIC_PATHS:
                return await call_next(request)
            bearer = _bearer(request)
            if bearer is not None:
                who = await _token_principal(bearer)
                if who is None:
                    return JSONResponse({"detail": "invalid, expired or revoked API token"},
                                        status_code=401)
                if path.startswith("/api/tokens"):
                    return JSONResponse(
                        {"detail": "API tokens cannot manage tokens: use the dashboard"},
                        status_code=403)
                if request.method not in _READ_METHODS and who.role == "viewer":
                    return JSONResponse({"detail": "this API token is read-only"},
                                        status_code=403)
            else:
                session = await _current_session(request)
                if session is None:
                    if path.startswith("/api/"):
                        return JSONResponse({"detail": "authentication required"},
                                            status_code=401)
                    return RedirectResponse("/login", status_code=302)
                who = Principal(session["username"], session["role"], "session",
                                session_id=session["id"])
                if (request.method not in _READ_METHODS and who.role == "viewer"
                        and not path.startswith(_SELF_SERVICE)):
                    return JSONResponse({"detail": "viewers can look but not change anything"},
                                        status_code=403)
            request.state.principal = who
            request.state.user = who.name
            request.state.via_token = who.via == "token"
            return await call_next(request)

    def _session_only(request: Request) -> str:
        if not require_auth:
            raise HTTPException(400, "the login is disabled (--no-auth): the API needs no token")
        user = getattr(request.state, "user", None)
        if user is None or getattr(request.state, "via_token", False):
            raise HTTPException(403, "sign in to the dashboard to manage API tokens")
        return user

    @app.get("/api/tokens")
    async def list_tokens(request: Request):
        """Your tokens (an admin sees everyone's)."""
        user = _session_only(request)
        owner = None if principal(request).role == "admin" else user
        return await storage.list_api_tokens(owner)

    @app.post("/api/tokens", status_code=201)
    async def create_token(body: _TokenRequest, request: Request):
        user = _session_only(request)
        if body.scope == "write" and principal(request).role == "viewer":
            raise HTTPException(403, "a viewer can create read tokens only")
        ttl = body.expires_in_days * 86400 if body.expires_in_days else None
        meta, token = await storage.create_api_token(body.name.strip(), body.scope, user, ttl)
        await storage.audit(user, "token.created", meta["id"],
                            {"name": meta["name"], "scope": body.scope})
        return {**meta, "token": token}  # the only time the token is ever returned

    @app.delete("/api/tokens/{token_id}", status_code=204)
    async def revoke_token(token_id: str, request: Request):
        user = _session_only(request)
        owner = None if principal(request).role == "admin" else user
        if not await storage.revoke_api_token(token_id, owner):
            raise HTTPException(404, "token not found")
        await storage.audit(user, "token.revoked", token_id)
        return JSONResponse(status_code=204, content=None)

    # ---- your account: password and sessions -------------------------------------- #
    @app.post("/api/auth/password")
    async def change_password(body: _PasswordChange, request: Request):
        """Change your own password; your other sessions end, this one stays."""
        user = _session_only(request)
        key = _client_key(request)
        _too_many(key)
        if not await storage.verify_credentials(user, body.current_password):
            throttle.failure(key)
            raise HTTPException(403, "the current password is not correct")
        _password_ok(body.new_password)
        await storage.set_password(user, body.new_password,
                                   keep_session_token=request.cookies.get(COOKIE_NAME))
        await storage.audit(user, "account.password_changed", user)
        return {"ok": True}

    @app.get("/api/auth/sessions")
    async def list_sessions(request: Request):
        user = _session_only(request)
        current = principal(request).session_id
        return [{"id": s["id"], "created_at": s["created_at"], "expires_at": s["expires_at"],
                 "client": s["client"], "user_agent": s["user_agent"],
                 "current": s["id"] == current}
                for s in await storage.list_sessions(user)]

    @app.delete("/api/auth/sessions/{session_id}", status_code=204)
    async def revoke_session(session_id: str, request: Request):
        user = _session_only(request)
        if not await storage.delete_session_by_id(user, session_id):
            raise HTTPException(404, "session not found")
        await storage.audit(user, "account.session_revoked", session_id)
        return JSONResponse(status_code=204, content=None)

    # ---- accounts (admin) ------------------------------------------------------------ #
    def _admin(request: Request) -> str:
        _session_only(request)
        return require(request, "admin", session=True).name

    @app.get("/api/users")
    async def list_users(request: Request):
        _admin(request)
        return await storage.list_users()

    @app.post("/api/users", status_code=201)
    async def create_user(body: _NewUser, request: Request):
        actor = _admin(request)
        username = body.username.strip()
        if not username:
            raise HTTPException(400, "username is required")
        _password_ok(body.password)
        if not await storage.create_user(username, body.password, body.role):
            raise HTTPException(409, "that username is taken")
        await storage.audit(actor, "user.created", username, {"role": body.role})
        return await storage.get_user(username)

    @app.patch("/api/users/{username}")
    async def change_role(username: str, body: _RoleChange, request: Request):
        actor = _admin(request)
        before = await storage.get_user(username)
        if before is None:
            raise HTTPException(404, "user not found")
        try:
            await storage.set_role(username, body.role)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        await storage.audit(actor, "user.role_changed", username,
                            {"from": before["role"], "to": body.role})
        return await storage.get_user(username)

    @app.post("/api/users/{username}/password")
    async def reset_password(username: str, body: _PasswordReset, request: Request):
        """Set someone's password: all their sessions and API tokens end with it."""
        actor = _admin(request)
        _password_ok(body.password)
        if not await storage.set_password(username, body.password):
            raise HTTPException(404, "user not found")
        revoked = await storage.revoke_user_tokens(username)
        await storage.audit(actor, "user.password_reset", username,
                            {"tokens_revoked": revoked})
        return {"ok": True, "tokens_revoked": revoked}

    @app.delete("/api/users/{username}", status_code=204)
    async def delete_user(username: str, request: Request):
        actor = _admin(request)
        try:
            deleted = await storage.delete_user(username)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        if not deleted:
            raise HTTPException(404, "user not found")
        await storage.audit(actor, "user.deleted", username)
        return JSONResponse(status_code=204, content=None)

    @app.get("/api/audit")
    async def audit_log(request: Request, limit: int = 200, before: int | None = None):
        """Who did what, newest first (admin)."""
        _admin(request)
        return await storage.list_audit(max(1, min(limit, 1000)), before)

    @app.get("/api/auth/status")
    async def auth_status(request: Request):
        session = await _current_session(request)
        user = session["username"] if session else None
        bearer = _bearer(request)
        api_token = await storage.get_api_token(bearer) if bearer else None
        token_who = await _token_principal(bearer) if bearer else None
        setup_required = not await storage.has_admin()
        authenticated = user is not None or token_who is not None or not require_auth
        status = {
            "auth_enabled": require_auth,
            "authenticated": authenticated,
            "setup_required": setup_required,
            "setup_token_required": setup_required and setup_token is not None,
            "username": user,
            "role": (session["role"] if session else token_who.role if token_who
                     else "admin" if not require_auth else None),
        }
        if authenticated:  # the version only to whoever may use the instance
            status["version"] = __version__
        if bearer:  # lets `mcpsonar doctor` check a CLI token without changing anything
            status["token"] = (
                {"valid": False} if api_token is None or token_who is None else
                {"valid": True, "scope": api_token["scope"],
                 "expires_at": api_token["expires_at"]}
            )
        return status

    @app.post("/api/auth/setup")
    async def auth_setup(body: _SetupRequest, request: Request):
        key = _client_key(request)
        if setup_token is not None:
            _too_many(key)  # the setup token must not be guessable either
            if not hmac.compare_digest((body.setup_token or "").encode(), setup_token.encode()):
                throttle.failure(key)
                raise HTTPException(
                    403, "a valid setup token is required: it is printed in the server log at "
                    "startup (or set it with MCPSONAR_SETUP_TOKEN)",
                )
        username = body.username.strip()
        if not username:
            raise HTTPException(400, "username is required")
        if len(body.password) < MIN_PASSWORD_LEN:
            raise HTTPException(400, f"password must be at least {MIN_PASSWORD_LEN} characters")
        async with setup_lock:  # the insert is atomic anyway; the lock keeps the error clean
            if not await storage.create_first_admin(username, body.password):
                raise HTTPException(400, "an admin account already exists")
        throttle.reset(key)
        await storage.audit(username, "account.setup", username, {"role": "admin"})
        return _start_session(request, await _new_session(request, username))

    @app.post("/api/auth/login")
    async def auth_login(creds: _Credentials, request: Request):
        key = _client_key(request)
        _too_many(key)
        if not await storage.verify_credentials(creds.username, creds.password):
            throttle.failure(key)
            raise HTTPException(401, "invalid username or password")
        throttle.reset(key)
        await storage.audit(creds.username, "account.login", creds.username,
                            {"client": _client_key(request)})
        return _start_session(request, await _new_session(request, creds.username))

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request):
        token = request.cookies.get(COOKIE_NAME)
        if token:
            await storage.delete_session(token)  # revoke server-side, not just in the browser
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        return HTMLResponse(_LOGIN_PAGE)


_LOGIN_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcpsonar · sign in</title>
<style>
  :root{
    --bg:#f1f4f9; --surface:#ffffff; --surface-2:#f6f9fc; --border:#d2dbe8;
    --text:#0e1a2b; --muted:#5b6b83; --accent:#0d9488; --accent-strong:#0f766e;
    --accent-ink:#fff; --accent-soft:rgba(13,148,136,.10); --down:#dc2626;
    --shadow:0 24px 70px rgba(14,26,43,.18);
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  @media (prefers-color-scheme:dark){
    :root{ --bg:#070c15; --surface:#0f1826; --surface-2:#131f30; --border:#2c3c54;
      --text:#e7eefb; --muted:#93a3bd; --accent:#2dd4bf; --accent-strong:#5eead4;
      --accent-ink:#04120f; --accent-soft:rgba(45,212,191,.12); --down:#f87171;
      --shadow:0 28px 80px rgba(0,0,0,.6); }
  }
  *{box-sizing:border-box;}
  body{font-family:var(--sans);background:
       radial-gradient(1100px 520px at 50% -12%, var(--accent-soft), transparent 60%), var(--bg);
       color:var(--text);margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:34px 32px;
        width:min(390px,94vw);box-shadow:var(--shadow);}
  .logo{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;font-size:24px;margin-bottom:16px;
        background:linear-gradient(150deg,var(--accent),var(--accent-strong));
        box-shadow:0 8px 22px var(--accent-soft), inset 0 1px 0 rgba(255,255,255,.25);}
  h1{font-size:21px;margin:0 0 2px;letter-spacing:-.02em;}
  .sub{color:var(--muted);font-size:13px;margin-bottom:22px;}
  label{display:block;font-size:12.5px;font-weight:600;margin:14px 0 5px;}
  input{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:9px;font:inherit;
        background:var(--surface-2);color:var(--text);transition:border-color .12s,box-shadow .12s;}
  input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);}
  button{width:100%;margin-top:22px;padding:11px;border:none;border-radius:10px;
         background:linear-gradient(150deg,var(--accent),var(--accent-strong));color:var(--accent-ink);
         font:inherit;font-weight:650;cursor:pointer;transition:filter .12s;}
  button:hover{filter:brightness(1.06);}
  .hint{color:var(--muted);font-size:12px;margin-top:6px;}
  .err{color:var(--down);font-size:13px;min-height:18px;margin-top:12px;}
</style></head>
<body>
<form class="card" onsubmit="submitForm(event)">
  <div class="logo">🛰️</div>
  <h1>mcpsonar</h1>
  <div class="sub" id="sub">Sign in</div>
  <label>Username</label><input id="u" autocomplete="username" autofocus>
  <label>Password</label><input id="p" type="password" autocomplete="current-password">
  <div id="tokRow" style="display:none"><label>Setup token</label>
    <input id="t" autocomplete="off" spellcheck="false" placeholder="printed in the server log">
    <div class="hint">Shown in the log when mcpsonar starts (<code>docker logs mcpsonar</code>).</div></div>
  <button id="btn" type="submit">Sign in</button>
  <div class="err" id="err"></div>
</form>
<script>
let setup = false, needToken = false;
const qsToken = new URLSearchParams(location.search).get("setup_token");
if (qsToken) history.replaceState(null, "", "/login");  // keep it out of the address bar
async function init(){
  const s = await (await fetch("/api/auth/status")).json();
  if (s.authenticated && !s.setup_required){ location.href="/"; return; }
  setup = s.setup_required; needToken = !!s.setup_token_required;
  if (needToken){ document.getElementById("tokRow").style.display="";
    if (qsToken) document.getElementById("t").value = qsToken; }
  document.getElementById("sub").textContent = setup
    ? "Create your admin account" : "Sign in to continue";
  document.getElementById("btn").textContent = setup ? "Create account" : "Sign in";
}
async function submitForm(e){
  e.preventDefault();
  const err = document.getElementById("err"); err.textContent="";
  const data = {username:document.getElementById("u").value,
                password:document.getElementById("p").value};
  if (setup && needToken) data.setup_token = document.getElementById("t").value.trim();
  const body = JSON.stringify(data);
  const r = await fetch(setup ? "/api/auth/setup" : "/api/auth/login",
    {method:"POST", headers:{"Content-Type":"application/json"}, body});
  if (r.ok){ location.href="/"; return; }
  const d = await r.json().catch(()=>({}));
  err.textContent = typeof d.detail === "string" ? d.detail : "Sign-in failed";
}
init();
</script>
</body></html>"""

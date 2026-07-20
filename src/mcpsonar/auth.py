"""Single-admin authentication for the dashboard.

Self-contained, no extra dependencies: passwords are hashed with PBKDF2 (stdlib), sessions
are signed cookies (HMAC-SHA256 over a persisted secret). On first run no admin exists, so
the login page offers a one-time "create admin" setup. When ``require_auth`` is off (behind a
trusted proxy) the middleware is not installed and everything is open.

``/metrics`` stays public so Prometheus can scrape it (it exposes only status gauges, no
secrets); everything else requires a valid session.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from .storage import Storage

COOKIE_NAME = "mcpsonar_session"
MAX_AGE = 7 * 24 * 3600  # 7 days
_ITERATIONS = 200_000
_PUBLIC_PATHS = {
    "/login",
    "/api/auth/status",
    "/api/auth/login",
    "/api/auth/setup",
    "/metrics",
    "/favicon.ico",
}


# ---- password hashing (used by storage) ------------------------------------ #
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) for a password using PBKDF2-HMAC-SHA256."""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS)
    return salt, dk.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, computed = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)


# ---- signed session cookie ------------------------------------------------- #
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_session(payload: dict, secret: str) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_session(token: str | None, secret: str, max_age: int = MAX_AGE) -> dict | None:
    if not token or "." not in token:
        return None
    body, sig = token.split(".", 1)
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64d(body))
    except Exception:
        return None
    if time.time() - payload.get("iat", 0) > max_age:
        return None
    return payload


class _Credentials(BaseModel):
    username: str
    password: str


def register_auth(app: FastAPI, storage: "Storage", require_auth: bool = True) -> None:
    """Install the auth middleware (if enabled) and the auth routes + login page."""
    _secret: dict[str, str] = {}

    async def secret() -> str:
        if "s" not in _secret:
            _secret["s"] = await storage.get_or_create_session_secret()
        return _secret["s"]

    def _set_cookie(resp: JSONResponse, username: str, token: str) -> JSONResponse:
        resp.set_cookie(
            COOKIE_NAME, token, httponly=True, samesite="lax", max_age=MAX_AGE, path="/"
        )
        return resp

    if require_auth:

        @app.middleware("http")
        async def _auth_mw(request: Request, call_next):
            path = request.url.path
            if path in _PUBLIC_PATHS:
                return await call_next(request)
            user = verify_session(request.cookies.get(COOKIE_NAME), await secret())
            if user is None:
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "authentication required"}, status_code=401)
                return RedirectResponse("/login", status_code=302)
            request.state.user = user.get("u")
            return await call_next(request)

    @app.get("/api/auth/status")
    async def auth_status(request: Request):
        user = verify_session(request.cookies.get(COOKIE_NAME), await secret())
        return {
            "auth_enabled": require_auth,
            "authenticated": (user is not None) or (not require_auth),
            "setup_required": not await storage.has_admin(),
            "username": user.get("u") if user else None,
        }

    @app.post("/api/auth/setup")
    async def auth_setup(creds: _Credentials):
        if await storage.has_admin():
            raise HTTPException(400, "an admin account already exists")
        if not creds.username.strip():
            raise HTTPException(400, "username is required")
        if len(creds.password) < 8:
            raise HTTPException(400, "password must be at least 8 characters")
        await storage.create_admin(creds.username.strip(), creds.password)
        token = sign_session({"u": creds.username.strip(), "iat": int(time.time())}, await secret())
        return _set_cookie(JSONResponse({"ok": True}), creds.username.strip(), token)

    @app.post("/api/auth/login")
    async def auth_login(creds: _Credentials):
        if not await storage.verify_credentials(creds.username, creds.password):
            raise HTTPException(401, "invalid username or password")
        token = sign_session({"u": creds.username, "iat": int(time.time())}, await secret())
        return _set_cookie(JSONResponse({"ok": True}), creds.username, token)

    @app.post("/api/auth/logout")
    async def auth_logout():
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
  .err{color:var(--down);font-size:13px;min-height:18px;margin-top:12px;}
</style></head>
<body>
<form class="card" onsubmit="submitForm(event)">
  <div class="logo">🛰️</div>
  <h1>mcpsonar</h1>
  <div class="sub" id="sub">Sign in</div>
  <label>Username</label><input id="u" autocomplete="username" autofocus>
  <label>Password</label><input id="p" type="password" autocomplete="current-password">
  <button id="btn" type="submit">Sign in</button>
  <div class="err" id="err"></div>
</form>
<script>
let setup = false;
async function init(){
  const s = await (await fetch("/api/auth/status")).json();
  if (s.authenticated && !s.setup_required){ location.href="/"; return; }
  setup = s.setup_required;
  document.getElementById("sub").textContent = setup
    ? "Create your admin account" : "Sign in to continue";
  document.getElementById("btn").textContent = setup ? "Create account" : "Sign in";
}
async function submitForm(e){
  e.preventDefault();
  const err = document.getElementById("err"); err.textContent="";
  const body = JSON.stringify({username:document.getElementById("u").value,
                               password:document.getElementById("p").value});
  const r = await fetch(setup ? "/api/auth/setup" : "/api/auth/login",
    {method:"POST", headers:{"Content-Type":"application/json"}, body});
  if (r.ok){ location.href="/"; return; }
  const d = await r.json().catch(()=>({}));
  err.textContent = d.detail || "Sign-in failed";
}
init();
</script>
</body></html>"""

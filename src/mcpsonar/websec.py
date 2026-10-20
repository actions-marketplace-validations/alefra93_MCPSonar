"""Browser-facing request hardening for the dashboard/API, independent of login.

The API can launch processes (stdio servers) and make outbound requests, so the question
"may *this browser request* do that?" matters even with ``--no-auth``. Four layers:

* **Host allowlist** — rejects requests whose ``Host`` is not one this instance answers to.
  This is what stops *DNS rebinding*: a page on ``evil.example`` re-pointed at 127.0.0.1
  still sends ``Host: evil.example``. ``mcpsonar run --no-auth`` enables it by default for
  the loopback names; otherwise it is opt-in (``--allowed-host``).
* **Cross-site request guard** (CSRF) — a state-changing request (anything but GET/HEAD/
  OPTIONS) is refused when the browser says it comes from another site or origin
  (``Sec-Fetch-Site``) or carries an ``Origin`` that does not match ``Host``. ``SameSite``
  cookies alone are not enough: ``localhost:3000`` and ``localhost:8675`` are the *same
  site*, and with ``--no-auth`` there is no cookie at all. Non-browser clients (curl,
  scripts, Prometheus) send neither header and are unaffected.
* **Body size limit** — ``Content-Length`` above the limit is refused with 413 before the
  body is read (bodies without a length are capped where they are read, see
  :func:`read_limited_body`).
* **Security headers** — no framing (the "approve tool changes" button must not be
  clickjackable), no MIME sniffing, no referrer leaks, a same-origin CSP.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MiB: far above any config/import a human writes
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# The dashboard is one self-contained page: inline <style>/<script> and inline handlers, no
# external assets. 'unsafe-inline' is needed for those; everything else is locked to self.
_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": _CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
}


def split_host(host_header: str) -> str:
    """The hostname part of a ``Host`` header, lowercased (``[::1]:8675`` -> ``::1``)."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    for pattern in allowed:
        pattern = pattern.strip().lower().strip("[]")
        if pattern == "*" or pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
    return False


def _normalize_origin(origin: str) -> str:
    parts = urlsplit(origin.strip())
    return f"{parts.scheme}://{parts.netloc}".lower()


def cross_site_reason(
    method: str, headers: dict[str, str] | object, trusted_origins: Iterable[str] = ()
) -> str | None:
    """Why a state-changing browser request must be refused, or None if it may proceed."""
    if method.upper() in _SAFE_METHODS:
        return None
    get = headers.get  # type: ignore[attr-defined]
    origin = get("origin")
    trusted = {_normalize_origin(o) for o in trusted_origins}
    if origin is not None and origin != "null" and _normalize_origin(origin) in trusted:
        return None
    fetch_site = (get("sec-fetch-site") or "").lower()
    if fetch_site in ("cross-site", "same-site"):
        return f"cross-origin request blocked (Sec-Fetch-Site: {fetch_site})"
    if origin is None:
        return None  # not a browser, or a same-origin request from an old browser
    if origin == "null":
        return "cross-origin request blocked (opaque Origin)"
    host = (get("host") or "").lower()
    if urlsplit(origin).netloc.lower() != host:
        return (
            f"cross-origin request blocked: Origin {origin} does not match Host {host}. "
            "Behind a reverse proxy, forward the original Host header, or list the public "
            "origin with --trusted-origin / MCPSONAR_TRUSTED_ORIGINS."
        )
    return None


def install_web_security(
    app: FastAPI,
    *,
    allowed_hosts: list[str] | None = None,
    trusted_origins: Iterable[str] = (),
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> None:
    """Install the request guards. Call it *after* the auth middleware is registered, so
    these run first (Starlette runs the most recently added middleware outermost)."""
    trusted = list(trusted_origins)
    app.state.max_body_bytes = max_body_bytes

    @app.middleware("http")
    async def _web_security(request: Request, call_next):
        if allowed_hosts is not None:
            host = split_host(request.headers.get("host", ""))
            if not host_allowed(host, allowed_hosts):
                return JSONResponse(
                    {"detail": f"host '{host}' is not allowed (see --allowed-host)"},
                    status_code=400,
                )
        reason = cross_site_reason(request.method, request.headers, trusted)
        if reason is not None:
            return JSONResponse({"detail": reason}, status_code=403)
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > max_body_bytes):
            return JSONResponse({"detail": "request body too large"}, status_code=413)

        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


async def read_limited_body(request: Request) -> bytes:
    """Read a request body, refusing more than the configured limit even when the client
    sent no ``Content-Length`` (chunked upload)."""
    limit = getattr(request.app.state, "max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, "request body too large")
        chunks.append(chunk)
    return b"".join(chunks)

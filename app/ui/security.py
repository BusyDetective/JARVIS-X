"""Local-access security for the dashboard.

Trust model: single user on this machine (or a network they explicitly opened). Binding to 127.0.0.1 is NOT
treated as sufficient: other local users/processes and web pages in the user's own browser can reach it, so:
  * every /api request (except login/health) needs a session cookie obtained by presenting the local token;
  * the Host header must be an allowed host (blocks DNS-rebinding);
  * unsafe methods must carry an allowed Origin (blocks cross-site requests/CSRF) AND a custom header AND JSON
    or octet-stream content; cookies are HttpOnly + SameSite=Strict;
  * there is no CORS support at all (same-origin only);
  * login attempts are throttled.
"""
from __future__ import annotations

import hmac
import secrets
import time
from collections import deque
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE_NAME = "jx_session"
CLIENT_HEADER = "x-jarvisx-client"
CLIENT_HEADER_VALUE = "dashboard"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {"/api/auth/login", "/api/health"}


def generate_token() -> str:
    return secrets.token_urlsafe(32)


class AuthManager:
    def __init__(self, token: str, ttl_seconds: int, clock=time.monotonic) -> None:
        if len(token) < 16:
            raise ValueError("auth token must be at least 16 characters")
        self._token = token.encode()
        self._ttl = ttl_seconds
        self._clock = clock
        self._sessions: dict[str, float] = {}
        self._failures: deque[float] = deque()

    def locked_out(self) -> bool:
        now = self._clock()
        while self._failures and now - self._failures[0] > 60:
            self._failures.popleft()
        return len(self._failures) >= 5

    def login(self, presented: str) -> str | None:
        if self.locked_out():
            return None
        if hmac.compare_digest(presented.encode(), self._token):
            sid = secrets.token_urlsafe(32)
            self._sessions[sid] = self._clock() + self._ttl
            return sid
        self._failures.append(self._clock())
        return None

    def valid(self, sid: str | None) -> bool:
        if not sid:
            return False
        expiry = self._sessions.get(sid)
        if expiry is None:
            return False
        if self._clock() > expiry:
            self._sessions.pop(sid, None)
            return False
        return True

    def logout(self, sid: str | None) -> None:
        if sid:
            self._sessions.pop(sid, None)


SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
                                "script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                                "base-uri 'none'; form-action 'none'; object-src 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(self)",
}


def _reject(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"error": detail}, status_code=status, headers=SECURITY_HEADERS)


class LocalGuardMiddleware:
    """Pure ASGI middleware (no body buffering). Order of checks: Host → Origin/CSRF → auth."""

    def __init__(self, app: ASGIApp, *, auth: AuthManager, allowed_hosts: set[str]) -> None:
        self.app, self.auth = app, auth
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    def _origin_ok(self, origin: str) -> bool:
        try:
            parts = urlsplit(origin)
        except ValueError:
            return False
        return parts.scheme in ("http", "https") and (parts.netloc or "").lower() in self.allowed_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":  # startup/shutdown hooks (browser cleanup) must reach the app
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":  # the dashboard has no websockets
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        request = Request(scope)
        path, method = request.url.path, request.method.upper()

        async def respond(resp: Response) -> None:
            await resp(scope, receive, send)

        host = (request.headers.get("host") or "").lower()
        if host not in self.allowed_hosts:
            return await respond(_reject(403, "host not allowed"))

        if method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if not origin or not self._origin_ok(origin):
                return await respond(_reject(403, "cross-origin request refused"))
            if request.headers.get(CLIENT_HEADER) != CLIENT_HEADER_VALUE:
                return await respond(_reject(403, "missing client header"))
            ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            has_body = request.headers.get("content-length", "0") not in ("", "0") or "transfer-encoding" in request.headers
            if has_body and not (ctype == "application/json" or ctype.startswith("audio/") or ctype == "application/octet-stream"):
                return await respond(_reject(415, "unsupported content type"))

        if path.startswith("/api/") and path not in PUBLIC_PATHS:
            if not self.auth.valid(request.cookies.get(COOKIE_NAME)):
                return await respond(_reject(401, "unauthorized"))

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for k, v in SECURITY_HEADERS.items():
                    if k.lower().encode() not in present:
                        headers.append((k.lower().encode(), v.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


def build_allowed_hosts(host: str, port: int, extra: str = "") -> set[str]:
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if host not in ("0.0.0.0", "::", ""):
        hosts.add(f"{host}:{port}" if ":" not in host else f"[{host}]:{port}")
    hosts |= {h.strip().lower() for h in extra.split(",") if h.strip()}
    return hosts

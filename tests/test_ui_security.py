"""Dashboard access control: auth, Host/Origin/CSRF, content types, throttling, headers, static assets."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ui.app import create_app
from app.ui.security import AuthManager, build_allowed_hosts
from tests.phase9_helpers import ORIGIN, TOKEN, ScriptedRouter, client_ctx, make_services

STATIC = Path("app/ui/static")


@pytest.fixture
def services(tmp_path):
    return make_services(tmp_path, ScriptedRouter([]))


def raw_client(services, headers=None, base=ORIGIN):
    return TestClient(create_app(services), base_url=base, headers=headers or {})


def test_health_is_public_and_minimal(services):
    r = raw_client(services).get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize("method,path", [
    ("get", "/api/sessions"), ("post", "/api/sessions"), ("get", "/api/approvals"), ("get", "/api/tasks"),
    ("get", "/api/capabilities"), ("get", "/api/settings"), ("get", "/api/voice/status"), ("get", "/api/browser/status"),
    ("get", "/api/self-improvement"), ("post", "/api/voice/transcribe"), ("get", "/api/auth/status")])
def test_every_api_route_requires_authentication(services, method, path):
    c = raw_client(services, {"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"})
    r = getattr(c, method)(path, **({"json": {}} if method == "post" else {}))
    assert r.status_code == 401 and r.json() == {"error": "unauthorized"}


def test_login_with_wrong_token_fails_and_correct_token_sets_hardened_cookie(services):
    c = raw_client(services, {"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"})
    assert c.post("/api/auth/login", json={"token": "wrong"}).status_code == 401
    r = c.post("/api/auth/login", json={"token": TOKEN})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert c.get("/api/auth/status").status_code == 200


def test_cookie_secure_flag_follows_configuration(services):
    services.cookie_secure = True
    c = raw_client(services, {"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"})
    assert "secure" in c.post("/api/auth/login", json={"token": TOKEN}).headers["set-cookie"].lower()


def test_login_throttling_after_repeated_failures(services):
    c = raw_client(services, {"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"})
    for _ in range(5):
        assert c.post("/api/auth/login", json={"token": "bad"}).status_code == 401
    assert c.post("/api/auth/login", json={"token": TOKEN}).status_code == 429   # even the right token is refused while locked


def test_logout_invalidates_session(services):
    with client_ctx(services) as c:
        assert c.get("/api/sessions").status_code == 200
        c.post("/api/auth/logout", json={})
        assert c.get("/api/sessions").status_code == 401


def test_dns_rebinding_host_header_rejected(services):
    with client_ctx(services) as c:
        for host in ("evil.example", "127.0.0.1:9999", "localhost.evil.com:8765", ""):
            r = c.get("/api/sessions", headers={"Host": host})
            assert r.status_code == 403, host


def test_localhost_and_ipv6_loopback_hosts_allowed(services):
    with client_ctx(services) as c:
        for host in ("localhost:8765", "127.0.0.1:8765", "[::1]:8765"):
            assert c.get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("origin", ["http://evil.example", "http://127.0.0.1:9999", "null", "http://127.0.0.1:8765.evil.com", "file://", ""])
def test_cross_origin_state_changing_requests_refused(services, origin):
    with client_ctx(services) as c:
        r = c.post("/api/sessions", json={}, headers={"Origin": origin})
        assert r.status_code == 403
        assert c.get("/api/sessions").json()["sessions"] == []         # nothing was created


def test_state_changing_request_without_origin_or_client_header_refused(services):
    with client_ctx(services) as c:
        no_origin = c.post("/api/sessions", json={}, headers={"Origin": ""})
        assert no_origin.status_code == 403
        c.headers.pop("X-JarvisX-Client")
        assert c.post("/api/sessions", json={}).status_code == 403


def test_form_encoded_and_text_plain_bodies_refused(services):
    with client_ctx(services) as c:
        for ctype in ("application/x-www-form-urlencoded", "text/plain", "multipart/form-data; boundary=x"):
            r = c.post("/api/sessions", content=b"title=x", headers={"Content-Type": ctype})
            assert r.status_code == 415, ctype


def test_no_cors_headers_are_ever_emitted(services):
    with client_ctx(services) as c:
        r = c.get("/api/sessions", headers={"Origin": "http://evil.example"})
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
        pre = c.options("/api/sessions", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
        assert "access-control-allow-origin" not in {k.lower() for k in pre.headers}


def test_security_headers_on_every_response_class(services):
    with client_ctx(services) as c:
        for path in ("/", "/api/sessions", "/static/app.js", "/api/health", "/nope"):
            h = {k.lower(): v for k, v in c.get(path).headers.items()}
            assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
            assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["cache-control"] == "no-store"


def test_errors_have_no_stack_traces_or_internal_details(services, monkeypatch):
    monkeypatch.setattr(services.session_manager, "list_sessions", lambda **k: (_ for _ in ()).throw(RuntimeError("SECRET-INTERNAL /home/x")))
    with TestClient(create_app(services), base_url=ORIGIN, raise_server_exceptions=False,
                    headers={"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"}) as c:
        assert c.post("/api/auth/login", json={"token": TOKEN}).status_code == 200
        r = c.get("/api/sessions")
        assert r.status_code == 500 and r.json() == {"error": "internal error"} and "SECRET" not in r.text


def test_openapi_and_docs_are_not_exposed(services):
    with client_ctx(services) as c:
        for p in ("/docs", "/redoc", "/openapi.json"):
            assert c.get(p).status_code == 404


def test_websocket_connections_are_refused(services):
    c = raw_client(services)
    with pytest.raises(Exception):
        with c.websocket_connect("/api/ws"):
            pass


def test_allowed_hosts_builder():
    h = build_allowed_hosts("127.0.0.1", 8000, "dash.example:443, ")
    assert h == {"127.0.0.1:8000", "localhost:8000", "[::1]:8000", "dash.example:443"}
    assert "0.0.0.0:8000" not in build_allowed_hosts("0.0.0.0", 8000)


def test_auth_manager_rejects_weak_tokens_and_expires_sessions():
    with pytest.raises(ValueError):
        AuthManager("short", 10)
    now = [0.0]
    a = AuthManager("x" * 20, 10, clock=lambda: now[0])
    sid = a.login("x" * 20)
    assert a.valid(sid)
    now[0] = 11
    assert not a.valid(sid) and not a.valid(None) and not a.valid("forged")


# ------------------------------ static assets ------------------------------

def test_static_assets_have_no_inline_script_style_or_external_resources():
    html = (STATIC / "index.html").read_text()
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "style.css").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)               # no inline <script>
    assert not re.search(r"\son[a-z]+\s*=", html) and "style=" not in html    # no inline handlers / styles
    assert "<style" not in html
    for text in (html, js, css):
        assert not re.search(r"(?:src|href)=[\"']https?://", text) and "url(http" not in text and "@import" not in text
    assert "eval(" not in js and "new Function" not in js and "document.write" not in js
    code_only = re.sub(r"//[^\n]*", "", js)                                   # comments may mention innerHTML
    assert "innerHTML" not in code_only and "outerHTML" not in code_only and "insertAdjacentHTML" not in code_only
    assert "localStorage" not in js and "sessionStorage" not in js            # no tokens kept in web storage


def test_frontend_never_handles_secrets_or_provider_keys():
    js = (STATIC / "app.js").read_text().lower()
    for word in ("api_key", "apikey", "bearer ", "authorization"):
        assert word not in js

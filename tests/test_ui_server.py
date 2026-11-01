"""Real server smoke test: `python -m app.ui` under uvicorn (real sockets, real lifespan)."""
from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import sys
import time

import httpx


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def env_for(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UI_", "BROWSER_", "VOICE_", "SPEECH_", "SELF_IMPROVEMENT"))}
    env.update(DATA_DIR=str(tmp_path / "data"), WORKSPACE_ROOT=str(tmp_path / "ws"), WEB_RESEARCH_ENABLED="false",
               SOFTWARE_ENGINEERING_ENABLED="false", PROVIDER_ORDER="ollama", PYTHONUNBUFFERED="1")
    env.update(extra)
    return env


def test_dashboard_starts_serves_authenticates_and_shuts_down_cleanly(tmp_path):
    port = free_port()
    proc = subprocess.Popen([sys.executable, "-m", "app.ui"], env=env_for(tmp_path, UI_PORT=str(port)),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        token, deadline, out = None, time.time() + 30, []
        while time.time() < deadline and token is None:
            line = proc.stdout.readline()
            out.append(line)
            m = re.search(r"Access token \(generated.*?\): (\S+)", line)
            if m:
                token = m.group(1)
            if proc.poll() is not None:
                break
        assert token, "no token printed:\n" + "".join(out)
        base = f"http://127.0.0.1:{port}"
        hdr = {"Origin": base, "X-JarvisX-Client": "dashboard"}
        with httpx.Client(base_url=base, headers=hdr, timeout=10) as c:
            for _ in range(50):
                try:
                    if c.get("/api/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.1)
            assert c.get("/api/sessions").status_code == 401
            assert c.post("/api/auth/login", json={"token": "nope"}).status_code == 401
            assert c.post("/api/auth/login", json={"token": token}).status_code == 200
            r = c.post("/api/sessions", json={"title": "smoke"})
            assert r.status_code == 201 and c.get("/api/sessions").json()["sessions"][0]["title"] == "smoke"
            settings = c.get("/api/settings").json()
            assert settings["providers"]["configured"]["gemini"] is False and settings["browser"]["available"] is False
            si = c.get("/api/self-improvement").json()
            assert si["config_enabled"] is False and "DISABLED" in si["message"]
            index = c.get("/")
            assert index.status_code == 200 and "JARVIS-X" in index.text and "content-security-policy" in index.headers
            # wrong Host (DNS-rebinding style) against the REAL server
            assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 403
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
    assert rc in (0, -signal.SIGINT), f"unclean shutdown rc={rc}"


def test_configured_token_is_never_printed(tmp_path):
    port = free_port()
    secret = "configured-secret-token-0123456789abcdef"
    proc = subprocess.Popen([sys.executable, "-m", "app.ui"], env=env_for(tmp_path, UI_PORT=str(port), UI_AUTH_TOKEN=secret),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 30
        base = f"http://127.0.0.1:{port}"
        while time.time() < deadline:
            try:
                if httpx.get(base + "/api/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        r = httpx.post(base + "/api/auth/login", json={"token": secret}, headers={"Origin": base, "X-JarvisX-Client": "dashboard"})
        assert r.status_code == 200
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            text = proc.communicate(timeout=15)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            text = proc.communicate()[0]
    assert secret not in text and "the value of UI_AUTH_TOKEN" in text


def test_refuses_non_loopback_bind_without_explicit_opt_in(tmp_path):
    p = subprocess.run([sys.executable, "-m", "app.ui"], env=env_for(tmp_path, UI_HOST="0.0.0.0", UI_PORT=str(free_port())),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "UI_ALLOW_REMOTE" in p.stderr
    p = subprocess.run([sys.executable, "-m", "app.ui"], env=env_for(tmp_path, UI_HOST="0.0.0.0", UI_ALLOW_REMOTE="true", UI_PORT=str(free_port())),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "UI_AUTH_TOKEN" in p.stderr

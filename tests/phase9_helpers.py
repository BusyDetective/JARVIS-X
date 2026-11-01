"""Shared Phase 9 test helpers.

MOCK vs REAL: `FakeDriver` is a MOCK of the PageDriver protocol — tests using it exercise manager/policy LOGIC and
prove nothing about browser isolation. Real-browser behaviour is tested only in tests/test_browser_real.py."""
from __future__ import annotations

from dataclasses import dataclass, field
from fastapi.testclient import TestClient

from app.browser.driver import NavResult, RawClickable, RawField, RawLink, Shot
from app.browser.manager import BrowserManager
from app.browser.models import BrowserLimits
from app.browser.policy import BrowserPolicy
from app.capabilities.manager import CapabilityManager
from app.core.orchestrator import Orchestrator
from app.sessions.manager import build_session_services
from app.tasks.manager import TaskManager
from app.tasks.repository import TaskRepository
from app.tools.registry import ToolRegistry
from app.ui.app import UIServices, create_app
from app.ui.approvals import WebApprovalHandler
from app.ui.runs import RunManager
from app.ui.security import AuthManager
from app.voice.service import VoiceService
from app.voice.recognition import NullRecognizer
from app.voice.synthesis import NullSynthesizer
from app.web.urls import UrlValidator

TOKEN = "unit-test-token-0123456789"
PUBLIC_IP = "93.184.216.34"


class FakeResolver:
    """name -> addresses; anything unknown resolves to loopback (so it must be blocked)."""

    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        return list(self.table.get(host, ["127.0.0.1"]))


def public_validator(*hosts: str) -> UrlValidator:
    return UrlValidator(FakeResolver({h: [PUBLIC_IP] for h in hosts}))


@dataclass
class FakeDriver:
    """MOCK PageDriver."""

    url_: str = ""
    title_: str = "Fake Page"
    text: str = "hello world"
    link_list: list[RawLink] = field(default_factory=list)
    field_list: list[RawField] = field(default_factory=list)
    click_list: list[RawClickable] = field(default_factory=list)
    redirects: dict[str, str] = field(default_factory=dict)
    nav_log: list[str] = field(default_factory=list)
    actions: list[tuple] = field(default_factory=list)
    blocked_count: int = 0
    alive: bool = True
    closed: bool = False
    close_raises: bool = False
    fail_with: Exception | None = None
    shot_bytes: bytes = b"\xff\xd8fakejpeg"

    async def navigate(self, url: str) -> NavResult:
        if self.fail_with:
            raise self.fail_with
        self.nav_log.append(url)
        if url in self.redirects:
            return NavResult(redirect_to=self.redirects[url])
        self.url_ = url
        return NavResult()

    async def back(self) -> NavResult:
        self.nav_log.append("<back>")
        return NavResult()

    async def forward(self) -> NavResult:
        self.nav_log.append("<forward>")
        return NavResult()

    async def url(self) -> str:
        return self.url_

    async def title(self) -> str:
        return self.title_

    async def body_text(self) -> str:
        if self.fail_with:
            raise self.fail_with
        return self.text

    async def links(self, limit: int) -> list[RawLink]:
        return self.link_list[:limit]

    async def fields(self, limit: int) -> list[RawField]:
        return self.field_list[:limit]

    async def clickables(self, limit: int) -> list[RawClickable]:
        return self.click_list[:limit]

    async def fill(self, f: RawField, value: str) -> None:
        self.actions.append(("fill", f.index, value))

    async def click(self, item: RawClickable) -> None:
        self.actions.append(("click", item.index))

    async def screenshot(self, max_bytes: int) -> Shot:
        return Shot(self.shot_bytes, "image/jpeg", 1280, 800)

    async def is_alive(self) -> bool:
        return self.alive

    async def close(self) -> None:
        self.closed = True
        if self.close_raises:
            raise RuntimeError("boom during close")


def make_manager(driver: FakeDriver | None = None, limits: BrowserLimits | None = None, hosts=("site.test",),
                 clock=None) -> tuple[BrowserManager, list[FakeDriver]]:
    created: list[FakeDriver] = []
    limits = limits or BrowserLimits()
    policy = BrowserPolicy(limits, public_validator(*hosts))

    async def factory() -> FakeDriver:
        d = driver if (driver is not None and not created) else FakeDriver()
        created.append(d)
        return d

    kwargs = {"clock": clock} if clock else {}
    return BrowserManager(limits, policy, factory, **kwargs), created


def link(i: int, text: str, href: str, **attrs: str) -> RawLink:
    return RawLink(i, text, href, {"href": href, **attrs})


# ------------------------------- dashboard ----------------------------------

def make_services(tmp_path, router, *, browser: BrowserManager | None = None, extra_tools=(), voice: VoiceService | None = None,
                  approval_timeout: float = 5.0, install_browser: bool = True) -> UIServices:
    from app.browser.capability import register_browser_capability
    from app.config.settings import settings

    db = tmp_path / "ui.db"
    sm, cm = build_session_services(db)
    tm = TaskManager(TaskRepository(db_path=db))
    registry = ToolRegistry()
    caps = CapabilityManager(registry)
    approvals = WebApprovalHandler(approval_timeout)
    if browser is not None and install_browser:
        old = settings.browser_enabled
        settings.browser_enabled = True
        try:
            register_browser_capability(caps, browser)
        finally:
            settings.browser_enabled = old
        approvals.add_describer("browser_", browser.describe)
    for t in extra_tools:
        registry.register(t)
    orch = Orchestrator(router, registry, approvals, task_manager=tm, conversation_manager=cm)
    voice = voice or VoiceService(NullRecognizer(), NullSynthesizer(), input_enabled=False, output_enabled=False,
                                  max_audio_bytes=1000, speech_max_chars=500, speech_chunk_chars=100,
                                  input_reason="off", output_reason="off")
    return UIServices(
        session_manager=sm, conversation_manager=cm, task_manager=tm, capabilities=caps, approvals=approvals,
        runs=RunManager(orch, approvals, 4), voice=voice, auth=AuthManager(TOKEN, 3600), browser=browser,
        browser_unavailable_reason=None if browser else "BROWSER_ENABLED is false", host="127.0.0.1", port=8765)


ORIGIN = "http://127.0.0.1:8765"


def make_client(services: UIServices, login: bool = True) -> TestClient:
    client = TestClient(create_app(services), base_url=ORIGIN, headers={"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"})
    if login:
        r = client.post("/api/auth/login", json={"token": TOKEN})
        assert r.status_code == 200, r.text
    return client


# ------------------------------- context-managed client + run helpers ------------------------------

import time
from contextlib import contextmanager

from pydantic import BaseModel

from app.providers.schemas import ToolCall
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from tests.test_orchestrator_persistence import ScriptedRouter, _response


@contextmanager
def client_ctx(services: UIServices, login: bool = True):
    """TestClient kept open so background runs created by a request keep running between requests."""
    with TestClient(create_app(services), base_url=ORIGIN, headers={"Origin": ORIGIN, "X-JarvisX-Client": "dashboard"}) as c:
        if login:
            assert c.post("/api/auth/login", json={"token": TOKEN}).status_code == 200
        yield c


def new_conversation(c: TestClient, title: str | None = None) -> tuple[str, str]:
    r = c.post("/api/sessions", json={"title": title} if title else {})
    assert r.status_code == 201, r.text
    return r.json()["session"]["id"], r.json()["conversation"]["id"]


def wait_run(c: TestClient, run_id: str, timeout: float = 10.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        run = c.get(f"/api/runs/{run_id}").json()["run"]
        if run["state"] in ("completed", "failed"):
            return run
        time.sleep(0.02)
    raise AssertionError("run did not finish")


def wait_pending(c: TestClient, timeout: float = 10.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        pending = c.get("/api/approvals").json()["pending"]
        if pending:
            return pending[0]
        time.sleep(0.02)
    raise AssertionError("no approval became pending")


class EmptyArgs(BaseModel):
    pass


class ConfirmTool(Tool):
    name = "confirm_tool"
    description = "needs confirmation"
    args_model = EmptyArgs
    permission_level = PermissionLevel.CONFIRM
    executed = 0

    async def execute(self, args):
        ConfirmTool.executed += 1
        return {"done": True}


class DangerTool(Tool):
    name = "danger_tool"
    description = "dangerous"
    args_model = EmptyArgs
    permission_level = PermissionLevel.DANGEROUS
    executed = 0

    async def execute(self, args):
        DangerTool.executed += 1
        return {"done": True}


def call(name: str, **args) -> ToolCall:
    return ToolCall.new(name, args)


RE_EXPORTED = (ScriptedRouter, _response)   # re-exported for the Phase 9 test modules

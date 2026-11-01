"""Browser tools + capability registration (mock driver where a manager is needed)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.browser.capability import BROWSER_CAPABILITY_ID, browser_package, build_browser_manager, register_browser_capability
from app.browser.errors import BrowserError, BrowserUnavailableError
from app.browser.tools import (
    UNTRUSTED_NOTICE, BrowserOpenTool, ClickArgs, FillArgs, FollowLinkArgs, OpenArgs, build_browser_tools,
)
from app.capabilities.manager import CapabilityManager
from app.config.settings import settings
from app.security.permissions import PermissionLevel
from app.tools.registry import ToolRegistry
from tests.phase9_helpers import FakeDriver, make_manager


def test_all_tools_have_typed_args_and_explicit_permissions():
    mgr, _ = make_manager()
    tools = {t.name: t for t in build_browser_tools(mgr)}
    assert set(tools) == {"browser_open", "browser_get_state", "browser_list_links", "browser_list_form_fields",
                          "browser_list_clickables", "browser_screenshot", "browser_back", "browser_forward",
                          "browser_follow_link", "browser_fill_field", "browser_click", "browser_close"}
    confirm = {n for n, t in tools.items() if t.permission_level == PermissionLevel.CONFIRM}
    assert confirm == {"browser_open", "browser_follow_link", "browser_fill_field", "browser_click"}
    assert all(t.permission_level in (PermissionLevel.SAFE, PermissionLevel.CONFIRM) for t in tools.values())
    for t in tools.values():                       # no generic/scripting surface
        assert t.args_model.model_config.get("extra") == "forbid"
        assert "script" not in t.name and "eval" not in t.name and "exec" not in t.name
        assert t.to_tool_schema().parameters["type"] == "object"


@pytest.mark.parametrize("model,payload", [
    (OpenArgs, {}), (OpenArgs, {"url": ""}), (OpenArgs, {"url": "x" * 3000}), (OpenArgs, {"url": "http://a", "js": "alert(1)"}),
    (FollowLinkArgs, {"link_id": "../etc"}), (FollowLinkArgs, {"link_id": "l"}), (ClickArgs, {"element_id": "l1"}),
    (FillArgs, {"field_id": "f1", "value": "x" * 501}), (FillArgs, {"field_id": "q", "value": "x"}), (FillArgs, {"field_id": "f1"}),
])
def test_argument_validation_rejects_bad_input(model, payload):
    with pytest.raises(ValidationError):
        model.model_validate(payload)


async def test_results_carry_untrusted_notice_and_bounded_payload():
    mgr, _ = make_manager(FakeDriver(text="B" * 40_000))
    out = await BrowserOpenTool(mgr).execute(OpenArgs(url="https://site.test/"))
    assert out["notice"] == UNTRUSTED_NOTICE and len(out["page"]["text"]) <= mgr.limits.max_text_chars + 1


async def test_blocked_url_surfaces_as_safe_browser_error():
    mgr, _ = make_manager()
    with pytest.raises(BrowserError) as ei:
        await BrowserOpenTool(mgr).execute(OpenArgs(url="http://169.254.169.254/latest/meta-data/iam"))
    assert "blocked" in str(ei.value)


async def test_unexpected_exceptions_are_masked():
    class Boom(FakeDriver):
        async def navigate(self, url):
            raise RuntimeError("password=hunter2 /home/user/.ssh")
    mgr, _ = make_manager(Boom())
    with pytest.raises(BrowserError) as ei:
        await BrowserOpenTool(mgr).execute(OpenArgs(url="https://site.test/"))
    assert "hunter2" not in str(ei.value) and ".ssh" not in str(ei.value)


async def test_tool_refuses_when_capability_disabled_at_execution_time():
    mgr, _ = make_manager()
    flag = {"on": True}
    tool = BrowserOpenTool(mgr, lambda: flag["on"])
    await tool.execute(OpenArgs(url="https://site.test/"))
    flag["on"] = False
    with pytest.raises(BrowserUnavailableError):
        await tool.execute(OpenArgs(url="https://site.test/"))


def _caps():
    return CapabilityManager(ToolRegistry())


def test_registration_requires_browser_enabled(monkeypatch):
    mgr, _ = make_manager()
    caps = _caps()
    monkeypatch.setattr(settings, "browser_enabled", False)
    assert register_browser_capability(caps, mgr) is False and not caps.registry.has(BROWSER_CAPABILITY_ID)
    monkeypatch.setattr(settings, "browser_enabled", True)
    assert register_browser_capability(caps, mgr) is True
    assert register_browser_capability(caps, mgr) is False          # idempotent
    cap = caps.get_capability(BROWSER_CAPABILITY_ID)
    assert cap.enabled and len(cap.tool_names) == 12 and cap.max_permission == PermissionLevel.CONFIRM


def test_disabling_capability_removes_tools_from_registry(monkeypatch):
    mgr, _ = make_manager()
    caps = _caps()
    monkeypatch.setattr(settings, "browser_enabled", True)
    register_browser_capability(caps, mgr)
    assert caps.tool_registry.get("browser_open") is not None
    caps.disable(BROWSER_CAPABILITY_ID)
    assert caps.tool_registry.get("browser_open") is None
    assert "browser_open" not in {s.name for s in caps.model_tool_schemas()}
    caps.enable(BROWSER_CAPABILITY_ID)
    assert caps.tool_registry.get("browser_open") is not None


def test_missing_playwright_fails_clearly(monkeypatch):
    import importlib.util
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None)
    with pytest.raises(BrowserUnavailableError) as ei:
        build_browser_manager()
    assert "requirements-browser.txt" in str(ei.value)


def test_browser_defaults_are_safe():
    from app.config.settings import Settings
    s = Settings(_env_file=None)
    assert s.browser_enabled is False and s.browser_javascript_enabled is False and s.browser_no_sandbox is False
    assert s.browser_allowed_ports == "80,443" and s.self_improvement_enabled is False
    assert s.voice_input_enabled is False and s.speech_output_enabled is False
    assert s.voice_stt_provider == "none" and s.speech_synthesis_provider == "none"
    assert s.ui_host == "127.0.0.1" and s.ui_allow_remote is False and s.voice_stt_allow_download is False


def test_package_tool_names_match_capability():
    mgr, _ = make_manager()
    cap, tools = browser_package(mgr)
    assert tuple(t.name for t in tools) == cap.tool_names

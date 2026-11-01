from __future__ import annotations

import pytest

from app.capabilities.manager import CapabilityManager, CapabilityValidationError
from app.capabilities.models import Capability, CapabilitySource
from app.capabilities.registry import DuplicateCapabilityError
from app.core.orchestrator import Orchestrator
from app.providers.schemas import ToolCall
from app.security.approval import AutoApproveHandler
from app.tools.registry import ToolRegistry
from tests.test_orchestrator_persistence import ScriptedRouter, _response


def fresh():
    return CapabilityManager(ToolRegistry(), enabled=True)


def test_builtin_bootstrap_registers_in_dependency_order():
    m = fresh()
    assert m.register_builtin_capabilities() == ["core", "text_utilities"]
    infos = {c.id: c for c in m.list_available_capabilities()}
    assert infos["core"].source is CapabilitySource.BUILTIN
    assert [t.name for t in infos["core"].tools] == ["echo", "get_current_time"]
    assert infos["text_utilities"].depends_on == ["core"]
    assert infos["text_utilities"].dependency_status.satisfied
    assert all(c.enabled for c in infos.values())
    assert {t.name for t in m.tool_registry.list_tools()} == {"echo", "get_current_time", "text_transform"}


def test_repeated_bootstrap_is_idempotent_and_deterministic():
    m = fresh()
    first = m.register_builtin_capabilities()
    snap = m.snapshot().to_json()
    assert m.register_builtin_capabilities() == []
    assert m.snapshot().to_json() == snap and first == ["core", "text_utilities"]
    assert len(m.tool_registry.list_tools()) == 3


def test_bootstrap_does_not_reenable_what_was_disabled():
    m = fresh()
    m.register_builtin_capabilities()
    m.disable("text_utilities")
    m.register_builtin_capabilities()
    assert not m.is_enabled("text_utilities")


def test_two_bootstraps_in_separate_managers_are_independent():
    a, b = fresh(), fresh()
    a.register_builtin_capabilities()
    a.disable("text_utilities")
    b.register_builtin_capabilities()
    assert b.is_enabled("text_utilities") and a.snapshot().to_json() != b.snapshot().to_json()
    assert a.tool_registry.get("echo") is not b.tool_registry.get("echo")


def test_bootstrap_refuses_to_overwrite_nonbuiltin_capability_and_installs_nothing():
    m = fresh()
    m.install(Capability(id="text_utilities", name="Mine", source=CapabilitySource.LOCAL), [])
    with pytest.raises(DuplicateCapabilityError):
        m.register_builtin_capabilities()
    assert not m.registry.has("core") and m.tool_registry.list_tools(include_disabled=True) == []


def test_bootstrap_tool_name_collision_raises_before_installing_anything():
    from tests.test_capability_manager import make_tool

    m = fresh()
    m.tool_registry.register(make_tool("echo"))
    with pytest.raises(CapabilityValidationError):
        m.register_builtin_capabilities()
    assert m.registry.list() == []


def test_disabled_by_config_registers_nothing():
    m = CapabilityManager(ToolRegistry(), enabled=False)
    assert m.register_builtin_capabilities() == []
    assert m.snapshot().capabilities == []


def test_default_follows_settings(monkeypatch):
    from app.config.settings import settings

    monkeypatch.setattr(settings, "capabilities_enabled", False)
    assert CapabilityManager(ToolRegistry()).enabled is False
    monkeypatch.setattr(settings, "capabilities_enabled", True)
    assert CapabilityManager(ToolRegistry()).enabled is True


async def test_builtin_tools_work_through_the_orchestrator():
    m = fresh()
    m.register_builtin_capabilities()
    calls = [
        ToolCall(id="c1", name="echo", arguments={"text": "hi"}),
        ToolCall(id="c2", name="text_transform", arguments={"text": "abc", "mode": "reverse"}),
        ToolCall(id="c3", name="get_current_time", arguments={}),
        ToolCall(id="c4", name="text_transform", arguments={"text": "abc", "mode": "bogus"}),
    ]
    router = ScriptedRouter([_response(tool_calls=calls), _response(text="done")])
    result = await Orchestrator(router, m.tool_registry, AutoApproveHandler()).run("go")
    out = result.tool_calls
    assert out[0].success and out[0].result == "hi"
    assert out[1].success and out[1].result == "cba"
    assert out[2].success and out[2].result.endswith("+00:00")
    assert out[3].success is False  # invalid args rejected by validation

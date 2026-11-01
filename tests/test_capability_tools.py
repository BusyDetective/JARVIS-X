"""Capability-aware tool availability end-to-end through the real Orchestrator."""
from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability
from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as RunStatus
from app.providers.schemas import ToolCall
from app.security.approval import AutoApproveHandler, AutoDenyHandler
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from app.tools.registry import ToolRegistry
from tests.test_orchestrator_persistence import ScriptedRouter, _response


class Args(BaseModel):
    x: int = 1


class CountingTool(Tool):
    description = "counts executions"
    args_model = Args

    def __init__(self, tool_name, level=PermissionLevel.SAFE):
        self.name = tool_name
        self.permission_level = level
        self.calls = 0

    async def execute(self, args):
        self.calls += 1
        return {"ran": self.name}


def setup(level=PermissionLevel.SAFE, declared=PermissionLevel.SAFE):
    tool = CountingTool("probe", level)
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    mgr.install(Capability(id="cap", name="Cap", tool_names=("probe",), max_permission=declared), [tool])
    return mgr, tool


def call(name="probe"):
    return ToolCall(id="c1", name=name, arguments={"x": 1})


async def run(mgr, router, handler=None):
    orch = Orchestrator(router, mgr.tool_registry, handler or AutoApproveHandler())
    return await orch.run("go")


async def test_enabled_capability_tool_executes_normally():
    mgr, tool = setup()
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="done")])
    result = await run(mgr, router)
    assert result.status == RunStatus.COMPLETED and tool.calls == 1
    assert result.tool_calls[0].success is True


async def test_disabled_capability_tool_never_executes():
    mgr, tool = setup()
    mgr.disable("cap")
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="ok")])
    result = await run(mgr, router)
    assert tool.calls == 0
    failed = result.tool_calls[0]
    assert failed.success is False and "not available" in failed.error


async def test_disabled_tool_is_not_offered_to_the_model():
    mgr, _ = setup()
    mgr.disable("cap")
    assert mgr.tool_registry.schemas() == [] and mgr.model_tool_schemas() == []


async def test_disabling_between_iterations_blocks_execution():
    """Capability disabled AFTER the model was shown the tool but before the
    call executes: still refused (lookup happens at execution time)."""
    mgr, tool = setup()

    class DisablingRouter(ScriptedRouter):
        async def _next(self, messages):
            out = await super()._next(messages)
            mgr.disable("cap")
            return out

    router = DisablingRouter([_response(tool_calls=[call()]), _response(text="ok")])
    result = await run(mgr, router)
    assert tool.calls == 0 and result.tool_calls[0].success is False


async def test_re_enabling_restores_execution():
    mgr, tool = setup()
    mgr.disable("cap")
    mgr.enable("cap")
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="ok")])
    await run(mgr, router)
    assert tool.calls == 1


async def test_tool_permission_stays_authoritative_when_capability_says_safe():
    mgr, tool = setup(level=PermissionLevel.DANGEROUS, declared=PermissionLevel.SAFE)
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="ok")])
    result = await run(mgr, router, AutoDenyHandler())
    assert tool.calls == 0 and result.tool_calls[0].success is False  # approval still required


async def test_dangerous_tool_runs_only_with_approval():
    mgr, tool = setup(level=PermissionLevel.DANGEROUS, declared=PermissionLevel.SAFE)
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="ok")])
    await run(mgr, router, AutoApproveHandler())
    assert tool.calls == 1


async def test_blocked_tool_never_runs_even_if_capability_enabled_and_approved():
    mgr, tool = setup(level=PermissionLevel.BLOCKED)
    router = ScriptedRouter([_response(tool_calls=[call()]), _response(text="ok")])
    result = await run(mgr, router, AutoApproveHandler())
    assert tool.calls == 0 and result.tool_calls[0].success is False


async def test_tool_registered_directly_is_unaffected_by_capabilities():
    mgr, _ = setup()
    plain = CountingTool("plain")
    mgr.tool_registry.register(plain)
    mgr.disable("cap")
    router = ScriptedRouter([_response(tool_calls=[call("plain")]), _response(text="ok")])
    await run(mgr, router)
    assert plain.calls == 1


# --- ToolRegistry compatibility --------------------------------------------------------


def test_tool_registry_default_behavior_unchanged():
    reg = ToolRegistry()
    t = CountingTool("t")
    reg.register(t)
    with pytest.raises(ValueError):
        reg.register(CountingTool("t"))
    assert reg.get("t") is t and reg.get("nope") is None
    assert reg.list_tools() == [t] and [s.name for s in reg.schemas()] == ["t"]


def test_tool_registry_enable_disable_and_unregister():
    reg = ToolRegistry()
    reg.register(CountingTool("t"))
    reg.set_enabled("t", False)
    assert reg.get("t") is None and reg.has("t") and not reg.is_enabled("t")
    assert reg.list_tools() == [] and len(reg.list_tools(include_disabled=True)) == 1
    reg.unregister("t")
    assert not reg.has("t")
    with pytest.raises(KeyError):
        reg.set_enabled("t", True)
    with pytest.raises(KeyError):
        reg.unregister("t")
    reg.register(CountingTool("t"))  # re-registering after unregister starts enabled
    assert reg.get("t") is not None


# --- Model-facing information ------------------------------------------------------------


def test_model_schema_has_only_what_is_needed_to_call_the_tool():
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    mgr.register_builtin_capabilities()
    schemas = {s.name: s for s in mgr.model_tool_schemas()}
    t = schemas["text_transform"]
    assert set(vars(t)) == {"name", "description", "parameters"}
    assert t.parameters["properties"]["mode"]["enum"] == ["upper", "lower", "title", "reverse"]
    assert "title" not in t.parameters  # no Python class name leaked
    blob = json.dumps({n: [s.name, s.description, s.parameters] for n, s in schemas.items()})
    for leak in ("_TransformArgs", "app.capabilities", "TextTransformTool", "/home", "capability", "permission"):
        assert leak not in blob


def test_model_schemas_match_registry_schemas_and_exclude_disabled():
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    mgr.register_builtin_capabilities()
    mgr.disable("text_utilities")
    names = [s.name for s in mgr.model_tool_schemas()]
    assert names == ["echo", "get_current_time"]
    assert sorted(s.name for s in mgr.tool_registry.schemas()) == names


def test_model_tool_schemas_are_deterministic():
    def build():
        m = CapabilityManager(ToolRegistry(), enabled=True)
        m.register_builtin_capabilities()
        return [s.__dict__ for s in m.model_tool_schemas()]

    assert build() == build()


def test_tool_info_has_no_internal_leakage_and_full_metadata():
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    mgr.register_builtin_capabilities()
    infos = {t.name: t for t in mgr.list_available_tools()}
    t = infos["text_transform"]
    assert t.capability_id == "text_utilities" and t.category.value == "productivity"
    assert t.permission_level is PermissionLevel.SAFE and t.requires_approval is False
    assert t.version == "1.0.0" and t.timeout_seconds == 30.0 and t.enabled is True
    blob = json.dumps([i.model_dump(mode="json") for i in infos.values()])
    for leak in ("TextTransformTool", "_TransformArgs", "app.capabilities", ".py", "/home"):
        assert leak not in blob
    assert [i.name for i in infos.values()] == sorted(infos)

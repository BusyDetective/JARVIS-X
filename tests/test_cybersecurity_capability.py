"""Capability-aware end-to-end tests through the real Orchestrator, plus
registration-level tests (disabled by default, master switch)."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.capabilities.manager import CapabilitiesDisabledError, CapabilityManager
from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as RunStatus
from app.cybersecurity import adapter
from app.cybersecurity.capability import (
    CYBERSECURITY_CAPABILITY_ID,
    build_cybersecurity_manager,
    cybersecurity_package,
    register_cybersecurity_capability,
)
from app.cybersecurity.models import AuthorizedScope, CyberLimits, OperationType, utcnow
from app.cybersecurity.scope import ScopeStore
from app.providers.schemas import ToolCall
from app.security.approval import AutoApproveHandler, AutoDenyHandler
from app.tools.registry import ToolRegistry
from tests.test_orchestrator_persistence import ScriptedRouter, _response


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=tuple(OperationType),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
        max_targets=5,
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


@pytest.fixture(autouse=True)
def _reset_adapter_state():
    adapter._cache = None
    yield
    adapter._cache = None


@pytest.fixture
def _fake_authorize(monkeypatch):
    async def _fake(request, scope_store):
        from app.cybersecurity.authorization import AuthorizedTarget
        scope = scope_store.find_for_domain(request.target, request.operation)
        return AuthorizedTarget(domain=request.target, scope=scope, addresses=("93.184.216.34",))

    monkeypatch.setattr(adapter, "authorize", _fake)


@pytest.fixture
def _fake_engine(monkeypatch):
    engine = SimpleNamespace(get_subdomains=lambda domain: ["a.example.com"])
    monkeypatch.setattr(adapter._Engine, "get", classmethod(lambda cls: engine))
    return engine


def _manager(store=None, limits=None):
    store = store or ScopeStore([_scope()])
    limits = limits or CyberLimits()
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    capability, tools = cybersecurity_package(store, limits)
    mgr.install(capability, tools)
    return mgr


def _call(name="cyber_subdomain_enum"):
    return ToolCall(id="c1", name=name, arguments={"domain": "example.com"})


async def _run(mgr, router, handler=None):
    orch = Orchestrator(router, mgr.tool_registry, handler or AutoApproveHandler())
    return await orch.run("go")


# ───────────────────────── disabled by default / master switch ─────────────────────────


def test_disabled_by_default(monkeypatch):
    from app.config.settings import settings
    monkeypatch.setattr(settings, "cybersecurity_enabled", False)
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    installed = register_cybersecurity_capability(mgr, ScopeStore([]), CyberLimits())
    assert installed is False
    assert not mgr.registry.has(CYBERSECURITY_CAPABILITY_ID)


def test_enabled_flag_installs_the_capability(monkeypatch):
    from app.config.settings import settings
    monkeypatch.setattr(settings, "cybersecurity_enabled", True)
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    installed = register_cybersecurity_capability(mgr, ScopeStore([]), CyberLimits())
    assert installed is True
    assert mgr.registry.has(CYBERSECURITY_CAPABILITY_ID)
    for cls_name in (
        "cyber_subdomain_enum", "cyber_alive_check", "cyber_endpoint_discovery",
        "cyber_tech_fingerprint", "cyber_risk_scoring", "cyber_report_generation",
    ):
        assert mgr.tool_registry.get(cls_name) is not None


def test_registering_twice_is_a_noop(monkeypatch):
    from app.config.settings import settings
    monkeypatch.setattr(settings, "cybersecurity_enabled", True)
    mgr = CapabilityManager(ToolRegistry(), enabled=True)
    assert register_cybersecurity_capability(mgr, ScopeStore([]), CyberLimits()) is True
    assert register_cybersecurity_capability(mgr, ScopeStore([]), CyberLimits()) is False


def test_build_cybersecurity_manager_fails_closed_without_a_scope_file(monkeypatch):
    from app.config.settings import settings
    monkeypatch.setattr(settings, "cybersecurity_scope_file", None)
    store, limits = build_cybersecurity_manager()
    assert len(store) == 0  # installs, but authorizes nothing


def test_master_switch_disabled_blocks_capabilities_manager_entirely():
    store = ScopeStore([_scope()])
    mgr = CapabilityManager(ToolRegistry(), enabled=False)  # global capabilities_enabled=False
    capability, tools = cybersecurity_package(store, CyberLimits())
    with pytest.raises(CapabilitiesDisabledError):
        mgr.install(capability, tools)


# ───────────────────────── approval / permission flow ─────────────────────────


async def test_tool_runs_only_with_approval(_fake_authorize, _fake_engine):
    mgr = _manager()
    router = ScriptedRouter([_response(tool_calls=[_call()]), _response(text="ok")])
    result = await _run(mgr, router, AutoApproveHandler())
    assert result.status == RunStatus.COMPLETED
    assert result.tool_calls[0].success is True


async def test_approval_denied_blocks_execution(_fake_authorize, _fake_engine):
    mgr = _manager()
    router = ScriptedRouter([_response(tool_calls=[_call()]), _response(text="ok")])
    result = await _run(mgr, router, AutoDenyHandler())
    assert result.tool_calls[0].success is False
    assert "not approved" in result.tool_calls[0].error


async def test_report_tool_also_requires_approval_confirm_level(_fake_authorize):
    mgr = _manager()
    router = ScriptedRouter(
        [_response(tool_calls=[_call("cyber_report_generation")]), _response(text="ok")]
    )
    result = await _run(mgr, router, AutoDenyHandler())
    assert result.tool_calls[0].success is False
    assert "not approved" in result.tool_calls[0].error


# ───────────────────────── disabled capability cannot execute ─────────────────────────


async def test_disabled_capability_tool_never_executes(_fake_authorize, _fake_engine):
    mgr = _manager()
    mgr.disable(CYBERSECURITY_CAPABILITY_ID)
    router = ScriptedRouter([_response(tool_calls=[_call()]), _response(text="ok")])
    result = await _run(mgr, router)
    assert result.tool_calls[0].success is False
    assert "not available" in result.tool_calls[0].error


async def test_disabling_between_iterations_blocks_execution(_fake_authorize, _fake_engine):
    """Disabled AFTER the model was shown the tool but before the call
    executes — the lookup happens at execution time, so it's still
    refused. Mirrors tests/test_capability_tools.py for the generic
    mechanism; this confirms OUR capability goes through the same path."""
    mgr = _manager()

    class DisablingRouter(ScriptedRouter):
        async def _next(self, messages):
            out = await super()._next(messages)
            mgr.disable(CYBERSECURITY_CAPABILITY_ID)
            return out

    router = DisablingRouter([_response(tool_calls=[_call()]), _response(text="ok")])
    result = await _run(mgr, router)
    assert result.tool_calls[0].success is False


async def test_disabled_capability_tools_not_offered_to_model():
    mgr = _manager()
    mgr.disable(CYBERSECURITY_CAPABILITY_ID)
    assert mgr.tool_registry.schemas() == []


# ───────────────────────── capability metadata honesty ─────────────────────────


def test_declared_max_permission_is_not_lower_than_any_tool():
    from app.security.permissions import PermissionLevel

    store = ScopeStore([_scope()])
    capability, tools = cybersecurity_package(store, CyberLimits())
    highest = max(tool.permission_level for tool in tools)
    assert capability.max_permission >= highest
    assert capability.max_permission == PermissionLevel.DANGEROUS


def test_capability_source_is_builtin():
    from app.capabilities.models import CapabilitySource

    store = ScopeStore([_scope()])
    capability, _ = cybersecurity_package(store, CyberLimits())
    assert capability.source == CapabilitySource.BUILTIN
    assert capability.id == CYBERSECURITY_CAPABILITY_ID

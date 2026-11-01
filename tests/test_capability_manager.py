from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from app.capabilities.manager import (
    CapabilitiesDisabledError,
    CapabilityDependencyError,
    CapabilityManager,
    CapabilitySourceError,
    CapabilityValidationError,
    find_dependency_cycles,
)
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.capabilities.registry import CapabilityNotFoundError, DuplicateCapabilityError
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from app.tools.registry import ToolRegistry


class Args(BaseModel):
    x: int = 0


def make_tool(tool_name, level=PermissionLevel.SAFE):
    class _T(Tool):
        name = tool_name
        description = f"{tool_name} tool"
        args_model = Args
        permission_level = level

        async def execute(self, args):
            return args.x

    return _T()


def cap(cid, tools=(), deps=(), **kw):
    return Capability(id=cid, name=cid.title(), tool_names=tuple(tools), depends_on=tuple(deps), **kw)


@pytest.fixture
def mgr():
    return CapabilityManager(ToolRegistry(), enabled=True)


def install(mgr, cid, tools=(), deps=(), level=PermissionLevel.SAFE, **kw):
    return mgr.install(cap(cid, tools, deps, **kw), [make_tool(t, level) for t in tools])


def test_install_registers_capability_and_tools(mgr):
    install(mgr, "a", ["t1", "t2"])
    assert mgr.is_enabled("a")
    assert [t.name for t in mgr.resolve_tools("a")] == ["t1", "t2"]
    assert mgr.tool_registry.get("t1") is not None


def test_install_validation(mgr):
    with pytest.raises(CapabilityValidationError):
        mgr.install(cap("a", ["t1"]), [])  # declared tool missing
    with pytest.raises(CapabilityValidationError):
        mgr.install(cap("a", []), [make_tool("extra")])  # undeclared tool
    with pytest.raises(CapabilityValidationError):
        mgr.install(cap("a", ["t"]), [make_tool("t"), make_tool("t")])
    mgr.tool_registry.register(make_tool("taken"))
    with pytest.raises(CapabilityValidationError):
        mgr.install(cap("b", ["taken"]), [make_tool("taken")])
    assert mgr.registry.list() == []  # nothing half-installed


def test_duplicate_install_rejected_and_state_untouched(mgr):
    install(mgr, "a", ["t1"])
    with pytest.raises(DuplicateCapabilityError):
        install(mgr, "a", ["t9"])
    assert not mgr.tool_registry.has("t9")
    assert [c.id for c in mgr.registry.list()] == ["a"]


def test_install_rejects_tool_owned_by_other_capability_without_leaking_tools(mgr):
    install(mgr, "a", ["t1"])
    with pytest.raises(Exception):
        install(mgr, "b", ["t1"])
    assert mgr.tool_registry.get("t1") is not None and not mgr.registry.has("b")


@pytest.mark.parametrize("source", [CapabilitySource.PLUGIN, CapabilitySource.FUTURE_EXTERNAL])
def test_external_sources_cannot_install(mgr, source):
    with pytest.raises(CapabilitySourceError):
        mgr.install(cap("a", source=source), [])
    assert mgr.registry.list() == []


def test_framework_disabled_by_config():
    m = CapabilityManager(ToolRegistry(), enabled=False)
    with pytest.raises(CapabilitiesDisabledError):
        m.install(cap("a"), [])
    assert m.register_builtin_capabilities() == []
    assert m.tool_registry.list_tools(include_disabled=True) == []


def test_enable_disable_controls_tool_availability(mgr):
    install(mgr, "a", ["t1"])
    mgr.disable("a")
    assert not mgr.is_enabled("a")
    assert mgr.tool_registry.get("t1") is None and mgr.tool_registry.schemas() == []
    assert mgr.tool_registry.get("t1", include_disabled=True) is not None
    assert mgr.resolve_tools("a") == [] and len(mgr.resolve_tools("a", include_disabled=True)) == 1
    mgr.enable("a")
    assert mgr.tool_registry.get("t1") is not None


def test_install_disabled_then_enable(mgr):
    mgr.install(cap("a", ["t1"], enabled=False), [make_tool("t1")])
    assert mgr.tool_registry.get("t1") is None
    mgr.enable("a")
    assert mgr.tool_registry.get("t1") is not None


def test_unknown_capability_errors(mgr):
    for fn in (mgr.enable, mgr.disable, mgr.unregister, mgr.dependencies_of, mgr.resolve_tools):
        with pytest.raises(CapabilityNotFoundError):
            fn("nope")
    assert mgr.get_capability("nope") is None and mgr.is_enabled("nope") is False


# --- dependencies ---------------------------------------------------------------


def test_missing_dependency_blocks_enabled_install_and_enable(mgr):
    with pytest.raises(CapabilityDependencyError, match="missing: b"):
        install(mgr, "a", ["t1"], deps=["b"])
    install(mgr, "a", ["t1"], deps=["b"], enabled=False)
    assert mgr.dependencies_of("a").missing == ["b"]
    with pytest.raises(CapabilityDependencyError):
        mgr.enable("a")
    assert not mgr.is_enabled("a") and mgr.tool_registry.get("t1") is None


def test_a_depends_on_b_and_b_disabled_means_a_cannot_be_enabled(mgr):
    install(mgr, "b", ["tb"])
    install(mgr, "a", ["ta"], deps=["b"])
    mgr.disable("a")
    mgr.disable("b")
    with pytest.raises(CapabilityDependencyError, match="disabled: b"):
        mgr.enable("a")
    assert not mgr.is_enabled("a") and mgr.tool_registry.get("ta") is None
    mgr.enable("b")
    mgr.enable("a")
    assert mgr.tool_registry.get("ta") is not None


def test_cannot_disable_dependency_of_enabled_capability_without_cascade(mgr):
    install(mgr, "b", ["tb"])
    install(mgr, "a", ["ta"], deps=["b"])
    install(mgr, "c", ["tc"], deps=["a"])
    with pytest.raises(CapabilityDependencyError):
        mgr.disable("b")
    assert mgr.is_enabled("b") and mgr.is_enabled("a")
    mgr.disable("b", cascade=True)
    assert not any(mgr.is_enabled(i) for i in "abc")
    assert mgr.tool_registry.list_tools() == []


def test_cycle_detected_on_install(mgr):
    install(mgr, "a", ["ta"], deps=["b"], enabled=False)
    with pytest.raises(CapabilityDependencyError, match="cycle"):
        install(mgr, "b", ["tb"], deps=["a"], enabled=False)
    assert not mgr.registry.has("b") and not mgr.tool_registry.has("tb")
    assert mgr.detect_cycles() == []


def test_longer_cycle_detected_on_install(mgr):
    install(mgr, "a", deps=["b"], enabled=False)
    install(mgr, "b", deps=["c"], enabled=False)
    with pytest.raises(CapabilityDependencyError, match="cycle"):
        install(mgr, "c", deps=["a"], enabled=False)


def test_find_dependency_cycles_pure():
    assert find_dependency_cycles({"a": ("b",), "b": ("a",)}) == [["a", "b"]]
    assert find_dependency_cycles({"a": ("b",), "b": ("c",), "c": ("a",), "d": ("a",)}) == [["a", "b", "c"]]
    assert find_dependency_cycles({"a": ("b",), "b": (), "c": ("zzz",)}) == []
    assert find_dependency_cycles({"a": ("a",)}) == [["a"]]


def test_unregister_blocked_by_dependents_then_removes_tools(mgr):
    install(mgr, "b", ["tb"])
    install(mgr, "a", ["ta"], deps=["b"])
    assert mgr.dependents_of("b") == ["a"]
    with pytest.raises(CapabilityDependencyError):
        mgr.unregister("b")
    mgr.unregister("a")
    mgr.unregister("b")
    assert mgr.registry.list() == [] and mgr.tool_registry.list_tools(include_disabled=True) == []


# --- permissions --------------------------------------------------------------------


def test_capability_cannot_lower_tool_permission(mgr):
    mgr.install(cap("a", ["danger"], max_permission=PermissionLevel.SAFE), [make_tool("danger", PermissionLevel.DANGEROUS)])
    assert mgr.tool_registry.get("danger").permission_level is PermissionLevel.DANGEROUS
    info = mgr.list_available_capabilities()[0]
    assert info.declared_max_permission is PermissionLevel.SAFE
    assert info.effective_max_permission is PermissionLevel.DANGEROUS
    assert info.permission_mismatch is True
    assert mgr.list_available_tools()[0].permission_level is PermissionLevel.DANGEROUS


def test_capability_cannot_raise_tool_permission(mgr):
    mgr.install(cap("a", ["safe"], max_permission=PermissionLevel.DANGEROUS), [make_tool("safe")])
    assert mgr.tool_registry.get("safe").permission_level is PermissionLevel.SAFE
    info = mgr.list_available_capabilities()[0]
    assert info.effective_max_permission is PermissionLevel.SAFE and info.permission_mismatch is False


def test_dependencies_do_not_escalate_permissions(mgr):
    install(mgr, "b", ["tb"], level=PermissionLevel.DANGEROUS)
    install(mgr, "a", ["ta"], deps=["b"])
    assert mgr.tool_registry.get("ta").permission_level is PermissionLevel.SAFE


def test_check_usable(mgr):
    install(mgr, "b", ["tb"], level=PermissionLevel.CONFIRM)
    install(mgr, "a", ["ta"], deps=["b"])
    assert mgr.check_usable("a").usable
    assert mgr.check_usable("b", PermissionLevel.SAFE).usable is False
    assert mgr.check_usable("b", PermissionLevel.CONFIRM).usable is True
    assert mgr.check_usable("missing").usable is False
    mgr.disable("a")
    assert "capability is disabled" in mgr.check_usable("a").reasons
    mgr.tool_registry.set_enabled("tb", False)
    assert any("tool 'tb' is disabled" in r for r in mgr.check_usable("b").reasons)
    install(mgr, "x", ["tx"], level=PermissionLevel.BLOCKED)
    assert any("BLOCKED" in r for r in mgr.check_usable("x").reasons)


# --- discovery & snapshot --------------------------------------------------------------


def test_discovery_and_snapshot_are_sorted_serializable_and_deterministic(mgr):
    install(mgr, "zeta", ["tz"], category=CapabilityCategory.SYSTEM)
    install(mgr, "alpha", ["tb", "ta"], deps=["zeta"], version="2.1.0")
    mgr.tool_registry.register(make_tool("legacy"))
    mgr.disable("alpha")

    snap = mgr.snapshot()
    assert [c.id for c in snap.capabilities] == ["alpha", "zeta"]
    alpha = snap.capabilities[0]
    assert alpha.version == "2.1.0" and alpha.enabled is False
    assert [t.name for t in alpha.tools] == ["ta", "tb"] and all(not t.enabled for t in alpha.tools)
    assert alpha.dependency_status.satisfied is True and alpha.depends_on == ["zeta"]
    assert json.loads(snap.to_json()) == snap.canonical_dict()
    assert snap.to_json() == mgr.snapshot().to_json()

    assert [c.id for c in mgr.list_available_capabilities()] == ["zeta"]
    assert [c.id for c in mgr.list_available_capabilities(include_disabled=True)] == ["alpha", "zeta"]
    assert [t.name for t in mgr.list_available_tools()] == ["legacy", "tz"]
    legacy = mgr.list_available_tools()[0]
    assert legacy.capability_id is None and legacy.enabled
    assert [t.name for t in mgr.list_available_tools(include_disabled=True)] == ["legacy", "ta", "tb", "tz"]

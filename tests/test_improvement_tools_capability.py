from __future__ import annotations

import json
import re

import httpx
import pytest
from pydantic import ValidationError

from app.capabilities.manager import CapabilityDependencyError, CapabilityManager
from app.capabilities.models import CapabilityCategory, CapabilitySource
from app.config.settings import Settings, settings
from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as RunStatus
from app.engineering.capability import SOFTWARE_ENGINEERING_CAPABILITY_ID, register_software_engineering_capability
from app.improvement.capability import (
    SELF_IMPROVEMENT_CAPABILITY_ID as CAP_ID, build_improvement_manager, register_self_improvement_capability,
    self_improvement_package,
)
from app.improvement.models import ImprovementState as S
from app.improvement.tools import improvement_tools
from app.providers.schemas import ToolCall
from app.security.approval import AutoApproveHandler, AutoDenyHandler
from app.security.permissions import PermissionLevel
from app.tools.registry import ToolRegistry
from app.workspace.manager import WorkspaceManager
from tests.github_helpers import make_client, repo_json
from tests.improvement_helpers import FakeValidator, make_manager, sha, tree_hashes
from tests.test_orchestrator_persistence import ScriptedRouter, _response

ALL_TOOLS = {"improvement_research", "improvement_evaluate", "improvement_create_plan", "improvement_propose",
             "improvement_validate", "improvement_status", "improvement_rollback"}
UTIL = "def add(a, b):\n    return a + b\n"
GOAL = "Improve the util module for readability"


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", True)


def web_manager():
    from app.web.limits import WebLimits
    from app.web.research import WebResearchManager
    from tests.web_helpers import FakeFetcher, FakeSearchProvider
    return WebResearchManager(FakeSearchProvider(["https://a.example.com/x"]), FakeFetcher(), WebLimits())


def build(tmp_path, with_web=True, **kw):
    manager, project = make_manager(tmp_path, FakeValidator, web=web_manager() if with_web else None, **kw)
    caps = CapabilityManager(ToolRegistry(), enabled=True)
    register_software_engineering_capability(caps, make_client(lambda r: httpx.Response(200, json=repo_json())), WorkspaceManager(project))
    return caps, manager, project


def call(name, args, cid="c1"):
    return ToolCall(id=cid, name=name, arguments=args)


async def run(caps, router, handler=None):
    orch = Orchestrator(router, caps.tool_registry, handler or AutoApproveHandler())
    return await orch.run("improve things")


def prepared(manager):
    """An improvement that is evaluated and planned, ready for the propose tool."""
    r = manager.submit_request(GOAL)
    manager.evaluate(r.id, ["app/util.py"])
    manager.create_plan(r.id)
    return r


MODIFY = {"path": "app/util.py", "operation": "modify", "new_content": "def add(a, b):\n    return b + a\n", "original_hash": sha(UTIL), "reason": "tidy"}


# --- master switch and registration ---------------------------------------------------------------------


def test_self_improvement_is_off_by_default():
    assert Settings.model_fields["self_improvement_enabled"].default is False
    assert Settings.model_fields["self_improvement_safe_automatic"].default is False


def test_disabled_master_switch_prevents_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", False)
    caps, manager, _ = build(tmp_path)
    assert register_self_improvement_capability(caps, manager) is False
    assert not caps.registry.has(CAP_ID) and not any(t.name.startswith("improvement_") for t in caps.tool_registry.list_tools(include_disabled=True))


def test_enabled_registration_through_the_capability_manager(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    assert register_self_improvement_capability(caps, manager) is True
    assert register_self_improvement_capability(caps, manager) is False  # idempotent
    info = {c.id: c for c in caps.list_available_capabilities()}[CAP_ID]
    assert info.category is CapabilityCategory.DEVELOPMENT and info.source is CapabilitySource.BUILTIN
    assert info.depends_on == [SOFTWARE_ENGINEERING_CAPABILITY_ID] and info.dependency_status.satisfied
    assert {t.name for t in info.tools} == ALL_TOOLS and info.enabled
    assert info.declared_max_permission is PermissionLevel.CONFIRM and info.effective_max_permission is PermissionLevel.CONFIRM
    assert info.permission_mismatch is False
    levels = {t.name: t.permission_level for t in info.tools}
    assert levels["improvement_validate"] is PermissionLevel.CONFIRM and levels["improvement_rollback"] is PermissionLevel.CONFIRM
    assert all(lvl is PermissionLevel.SAFE for n, lvl in levels.items() if n not in ("improvement_validate", "improvement_rollback"))


def test_research_tool_only_offered_when_web_research_is_configured(tmp_path):
    manager, _ = make_manager(tmp_path, FakeValidator)
    assert "improvement_research" not in {t.name for t in improvement_tools(manager)}
    manager_web, _ = make_manager(tmp_path / "w", FakeValidator, web=web_manager())
    assert "improvement_research" in {t.name for t in improvement_tools(manager_web)}


def test_requires_the_software_engineering_capability(tmp_path, enabled):
    manager, _ = make_manager(tmp_path, FakeValidator)
    bare = CapabilityManager(ToolRegistry(), enabled=True)
    with pytest.raises(CapabilityDependencyError, match="software_engineering"):
        register_self_improvement_capability(bare, manager)
    assert not bare.registry.has(CAP_ID)


def test_dependency_system_governs_the_capability(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    with pytest.raises(CapabilityDependencyError):
        caps.disable(SOFTWARE_ENGINEERING_CAPABILITY_ID)  # self_improvement depends on it
    caps.disable(SOFTWARE_ENGINEERING_CAPABILITY_ID, cascade=True)
    assert not caps.is_enabled(CAP_ID) and caps.tool_registry.list_tools() == []
    with pytest.raises(CapabilityDependencyError):
        caps.enable(CAP_ID)  # cannot come back before its dependency
    caps.enable(SOFTWARE_ENGINEERING_CAPABILITY_ID)
    caps.enable(CAP_ID)
    assert caps.tool_registry.get("improvement_status") is not None


def test_build_improvement_manager_from_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_root", tmp_path / "imp")
    m = build_improvement_manager(db_path=tmp_path / "t.db")
    from app.sandbox.container import ContainerBackend
    assert m.store.root == (tmp_path / "imp").resolve() and m.store.current() is None and m.web is None
    assert (tmp_path / "imp" / "releases").is_dir() and not (tmp_path / "imp" / "guard").exists()
    assert isinstance(m.sandbox.backend, ContainerBackend) and m.sandbox.backend.name in ("container", "docker", "podman")  # the only backend type wired


def test_build_improvement_manager_rejects_a_misconfigured_backend(tmp_path, monkeypatch):
    from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
    monkeypatch.setattr(settings, "improvement_isolation_backend", "lxc")
    with pytest.raises(IsolationUnavailableError) as ei:
        build_improvement_manager(db_path=tmp_path / "t.db", root=tmp_path / "imp")
    assert ei.value.reason is IsolationFailure.MISCONFIGURED


# --- model-facing surface ----------------------------------------------------------------------------------


def test_no_shell_exec_promote_or_arbitrary_write_tools_and_no_command_arguments(tmp_path):
    manager, _ = make_manager(tmp_path, FakeValidator, web=web_manager())
    capability, tools = self_improvement_package(manager)
    names = {t.name for t in tools}
    assert names == ALL_TOOLS and capability.tool_names == tuple(t.name for t in tools)
    assert not any(re.search(r"shell|exec|command|terminal|run_|promote|approve|apply|write|patch_file|install|delete", n) for n in names)
    forbidden_args = {"command", "cmd", "argv", "args", "executable", "env", "environment", "shell", "script", "path_to_run"}
    for t in tools:
        schema = json.dumps(t.to_tool_schema().__dict__)
        props = set(re.findall(r'"([a-z_]+)": \{', schema))
        assert not props & forbidden_args, (t.name, props & forbidden_args)


def test_argument_validation(tmp_path):
    manager, _ = make_manager(tmp_path, FakeValidator, web=web_manager())
    t = {x.name: x for x in improvement_tools(manager)}
    for name, bad in [("improvement_validate", dict(improvement_id="short")), ("improvement_evaluate", dict(improvement_id="x" * 50)),
                      ("improvement_propose", dict(improvement_id="a" * 36, title="ok title", changes=[])),
                      ("improvement_rollback", dict(reason="x")), ("improvement_research", dict(query="ab")),
                      ("improvement_research", dict(query="valid query", max_results=0))]:
        with pytest.raises(ValidationError):
            t[name].args_model(**bad)
    assert t["improvement_research"].args_model(query="valid query", max_pages=500).max_pages == 500  # clamped server-side


async def test_status_tool_reports_limits_honestly(tmp_path):
    manager, _ = make_manager(tmp_path, FakeValidator)
    tool = {t.name: t for t in improvement_tools(manager)}["improvement_status"]
    out = await tool.execute(tool.args_model())
    iso = out["data"]["isolation"]
    assert "NOT a perfect boundary" in iso["residual_risk"] and "no host execution" in iso["execution"] and "--network none" in iso["network"]
    assert out["data"]["current_version"] == manager.store.current_version() and "UNTRUSTED" in out["notice"]


# --- through the orchestrator ------------------------------------------------------------------------------


async def test_propose_tool_builds_a_sandbox_candidate_and_never_touches_current(tmp_path, enabled):
    caps, manager, project = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    before_cur, live = manager.store.hash_release(manager.store.current_version()), tree_hashes(project)
    r = prepared(manager)
    router = ScriptedRouter([_response(tool_calls=[call("improvement_propose", {"improvement_id": str(r.id), "title": "Tidy util",
                                                                                 "rationale": "readability", "changes": [MODIFY]})]),
                             _response(text="proposed")])
    result = await run(caps, router)
    assert result.status == RunStatus.COMPLETED and result.tool_calls[0].success
    out = result.tool_calls[0].result
    assert out["data"]["risk"] == "medium" and out["data"]["mode"] == "propose_only" and out["data"]["requires_approval"] is True
    assert "return b + a" in out["data"]["diff_preview"] and out["data"]["next_step"] == "improvement_validate"
    assert manager.get_run(r.id).state is S.SANDBOXED
    assert manager.store.hash_release(manager.store.current_version()) == before_cur and tree_hashes(project) == live


async def test_validate_and_rollback_tools_need_approval(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    r = prepared(manager)
    manager.propose(r.id, "Tidy util", "r", [__import__("app.improvement.proposals", fromlist=["ProposedChange"]).ProposedChange(**MODIFY)])
    manager.create_sandbox(r.id)
    denied = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_validate", {"improvement_id": str(r.id)}),
                                                                   call("improvement_rollback", {"reason": "because"}, "c2")]),
                                             _response(text="ok")]), AutoDenyHandler())
    assert [x.success for x in denied.tool_calls] == [False, False]
    assert manager.validator.calls == 0 and manager.get_run(r.id).state is S.SANDBOXED
    approved = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_validate", {"improvement_id": str(r.id)})]),
                                               _response(text="ok")]), AutoApproveHandler())
    assert approved.tool_calls[0].success and approved.tool_calls[0].result["data"]["validation"]["status"] == "passed"
    assert manager.get_run(r.id).state is S.VALIDATED


async def test_no_tool_can_approve_or_promote(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    v1 = manager.store.current_version()
    r = prepared(manager)
    calls = [call("improvement_propose", {"improvement_id": str(r.id), "title": "Tidy util", "changes": [MODIFY]}, "c1"),
             call("improvement_validate", {"improvement_id": str(r.id)}, "c2"),
             call("improvement_promote", {"improvement_id": str(r.id)}, "c3"),
             call("improvement_approve", {"improvement_id": str(r.id)}, "c4"),
             call("promote_release", {}, "c5"), call("shell", {"command": "rm -rf /"}, "c6")]
    result = await run(caps, ScriptedRouter([_response(tool_calls=calls), _response(text="done")]))
    assert [x.success for x in result.tool_calls] == [True, True, False, False, False, False]
    assert manager.get_run(r.id).state is S.VALIDATED  # the farthest a model-driven flow can reach
    assert manager.store.current_version() == v1


@pytest.mark.parametrize("change", [
    {"path": "../outside.py", "operation": "add", "new_content": "x", "reason": "r"},
    {"path": "/etc/cron.d/evil", "operation": "add", "new_content": "x", "reason": "r"},
    {"path": ".env", "operation": "add", "new_content": "K=1", "reason": "r"},
    {"path": "app/%2e%2e/x.py", "operation": "add", "new_content": "x", "reason": "r"},
    {"path": ".git/hooks/post-checkout", "operation": "add", "new_content": "#!/bin/sh", "reason": "r"},
])
async def test_malicious_proposal_paths_are_refused_through_the_tool(tmp_path, enabled, change):
    caps, manager, project = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    before, live = manager.store.hash_release(manager.store.current_version()), tree_hashes(project)
    r = prepared(manager)
    result = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_propose", {"improvement_id": str(r.id), "title": "Bad idea", "changes": [change]})]),
                                             _response(text="ok")]))
    assert result.tool_calls[0].success is False and "invalid path" in result.tool_calls[0].error
    assert manager.get_run(r.id).state is S.PLANNED and manager.store.hash_release(manager.store.current_version()) == before
    assert tree_hashes(project) == live and not (tmp_path / "outside.py").exists() and list(manager.sandbox.candidates_dir.iterdir()) == []


async def test_protected_self_modification_is_flagged_critical(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    r = prepared(manager)
    evil = {"path": "app/security/approval.py", "operation": "modify", "new_content": "def approve():\n    return True\n",
            "original_hash": sha("def approve():\n    return False\n"), "reason": "make approval easier"}
    result = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_propose", {"improvement_id": str(r.id), "title": "Simplify approval", "changes": [evil]})]),
                                             _response(text="ok")]))
    data = result.tool_calls[0].result["data"]
    assert data["risk"] == "critical" and data["mode"] == "approval_required" and "protected_area" in data["flags"] and data["requires_approval"]


async def test_tool_output_is_redacted_and_bounded(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    r = prepared(manager)
    leaky = {**MODIFY, "new_content": "def add(a, b):\n    password = 'hunter2hunter2'\n    token = 'ghp_abcdefghijklmnopqrstuvwxyz0123'\n    return a + b\n" + "# filler\n" * 3000}
    result = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_propose", {"improvement_id": str(r.id), "title": "Leaky", "changes": [leaky]})]),
                                             _response(text="ok")]))
    blob = json.dumps(result.tool_calls[0].result)
    assert "hunter2hunter2" not in blob and "ghp_abcdefghijklmnopqrstuvwxyz0123" not in blob and "[REDACTED" in blob
    assert len(result.tool_calls[0].result["data"]["diff_preview"]) <= 8000 and len(blob) <= manager.max_output_chars + 200


async def test_research_tool_starts_an_improvement_and_keeps_web_text_as_tool_data(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    before = manager.store.hash_release(manager.store.current_version())
    result = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_research", {"goal": GOAL, "query": "util best practices"})]),
                                             _response(text="ok")]))
    out = result.tool_calls[0].result
    assert out["improvement_id"] and "UNTRUSTED" in out["notice"] and out["sources"]
    run_ = manager.get_run(out["improvement_id"])
    assert run_.state is S.DISCOVERED and run_.request.requested_by == "model" and run_.evidence["source_count"] == 1
    assert manager.store.hash_release(manager.store.current_version()) == before
    missing = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_research", {"query": "no goal or id"})]), _response(text="x")]))
    assert missing.tool_calls[0].success is False and "improvement_id or a goal" in missing.tool_calls[0].error


async def test_disabled_capability_hides_and_refuses_every_tool(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)
    caps.disable(CAP_ID)
    assert not any(s.name.startswith("improvement_") for s in caps.model_tool_schemas())
    r = prepared(manager)
    calls = [call(n, {"improvement_id": str(r.id)} if n != "improvement_rollback" else {"reason": "because"}, f"c{i}")
             for i, n in enumerate(sorted(ALL_TOOLS - {"improvement_research", "improvement_propose"}))]
    result = await run(caps, ScriptedRouter([_response(tool_calls=calls), _response(text="ok")]))
    assert all(x.success is False and "not available" in x.error for x in result.tool_calls)
    assert manager.validator.calls == 0 and manager.get_run(r.id).state is S.PLANNED
    caps.enable(CAP_ID)
    again = await run(caps, ScriptedRouter([_response(tool_calls=[call("improvement_status", {})]), _response(text="ok")]))
    assert again.tool_calls[0].success is True


async def test_mid_run_disable_blocks_improvement_tools(tmp_path, enabled):
    caps, manager, _ = build(tmp_path)
    register_self_improvement_capability(caps, manager)

    class DisablingRouter(ScriptedRouter):
        async def _next(self, messages):
            out = await super()._next(messages)
            caps.disable(CAP_ID)
            return out

    result = await run(caps, DisablingRouter([_response(tool_calls=[call("improvement_status", {})]), _response(text="ok")]))
    assert result.tool_calls[0].success is False


async def test_unexpected_errors_are_genericized(tmp_path, monkeypatch):
    manager, _ = make_manager(tmp_path, FakeValidator)

    def boom(*a, **k):
        raise RuntimeError("password=hunter2 /home/u/.ssh/id_rsa")

    monkeypatch.setattr(manager, "status", boom)
    tool = {t.name: t for t in improvement_tools(manager)}["improvement_status"]
    from app.improvement.errors import ImprovementError
    with pytest.raises(ImprovementError) as ei:
        await tool.execute(tool.args_model())
    assert str(ei.value) == "self-improvement operation failed unexpectedly"

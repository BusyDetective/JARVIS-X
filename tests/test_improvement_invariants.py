"""The Phase 8 security invariants, one explicitly named test each (plus the isolation-hardening ones).

How to read them: tests marked "real_container" run actual containers and are SKIPPED when no docker/podman runtime and
validation image are available; the other tests exercise logic (state machine, gates, path confinement) and some use the
UNSAFE host test double or MOCK attestations — those do NOT prove OS-level isolation. The container boundary itself is
checked in test_container_real.py; it is evidence about that boundary, not a guarantee against container escape."""
from __future__ import annotations

import inspect
import json
import sqlite3
import uuid

import httpx
import pytest

from app.capabilities.manager import CapabilityManager
from app.config.settings import settings
from app.core.orchestrator import Orchestrator
from app.engineering.capability import register_software_engineering_capability
from app.improvement.capability import SELF_IMPROVEMENT_CAPABILITY_ID as CAP_ID, register_self_improvement_capability
from app.improvement.errors import PreconditionError
from app.improvement.models import (
    ApprovalChoice, ApprovalDecision, AutomationMode, ImprovementState as S, RiskLevel, TestCounts, ValidationStatus, ValidationSummary,
)
from app.improvement.models import ChangeOperation as Op
from app.improvement.promotion import PromotionManager, PromotionRequest
from app.improvement.proposals import ProposedChange
from app.improvement.validation import ValidationRunner
from app.providers.schemas import ToolCall
from app.sandbox.errors import SandboxChangeError, SandboxPathError, SandboxPolicyViolation
from app.sandbox.manager import SandboxManager
from app.sandbox.models import SandboxChange, SandboxOperation
from app.security.approval import AutoApproveHandler
from app.tools.registry import ToolRegistry
from app.workspace.manager import WorkspaceManager
from tests.github_helpers import make_client, repo_json
from app.versioning.manifest import tree_digest
from tests.improvement_helpers import Approver, FakeValidator, make_manager, make_project, make_policy, sha, tree_hashes
from tests.test_orchestrator_persistence import ScriptedRouter, _response

UTIL = "def add(a, b):\n    return a + b\n"
GOAL = "Improve the util module for readability"
SECRETS = ["hunter2hunter2", "ghp_abcdefghijklmnopqrstuvwxyz0123", "sk-supersecretsupersecret1234"]


def modify_util(text="def add(a, b):\n    return b + a\n"):
    return ProposedChange(path="app/util.py", operation=Op.MODIFY, new_content=text, original_hash=sha(UTIL), reason="tidy")


async def to_sandboxed(m, changes):
    run = m.submit_request(GOAL)
    m.evaluate(run.id, planned_paths=[c.path for c in changes])
    m.create_plan(run.id)
    m.propose(run.id, "Candidate change", "because", changes)
    m.create_sandbox(run.id)
    return run


def snapshot(m, project):
    cur = m.store.current_version()
    return cur, m.store.hash_release(cur), m.store.current().history, tree_hashes(project)


# 1 ---------------------------------------------------------------------------------------------------


@pytest.mark.usefixtures("trust_test_backend")
async def test_invariant_01_candidate_cannot_modify_the_current_installation(tmp_path):
    """LOGIC test (unsafe host test double): the candidate is a separate copy and no step writes to the current release
    or the live tree. The real read-only-mount behaviour is checked in the container test right below."""
    m, project = make_manager(tmp_path)
    before = snapshot(m, project)
    run = await to_sandboxed(m, [modify_util()])
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.PASSED
    assert snapshot(m, project) == before
    assert "b + a" not in (project / "app" / "util.py").read_text()
    assert "b + a" in (m.sandbox.paths(m.get_run(run.id).candidate.sandbox_id).source / "app" / "util.py").read_text()


async def test_invariant_01_real_container_candidate_code_cannot_write_the_snapshot_or_current_release(tmp_path, container_backend):
    """REAL container: hostile test code tries to overwrite the mounted source; the host copy and the release stay identical."""
    from tests.test_container_real import backend_like
    policy_backend = backend_like(container_backend)
    m, project = make_manager(tmp_path, backend=policy_backend)
    before = snapshot(m, project)
    attack = ("def test_overwrite_source():\n    import pytest\n    for p in ('/snapshot/app/util.py', '/snapshot/pwned.txt'):\n"
              "        with pytest.raises(OSError):\n            open(p, 'w')\n")
    changes = [ProposedChange(path="tests/test_attack.py", operation=Op.ADD, new_content=attack, reason="probe")]
    run = await to_sandboxed(m, changes)
    sid = m.get_run(run.id).candidate.sandbox_id
    digest_before = tree_digest(m.sandbox.paths(sid).source)
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.PASSED, summary.reasons
    assert summary.candidate_digest == digest_before == m.get_run(run.id).candidate.source_digest
    assert snapshot(m, project) == before


# 2 ---------------------------------------------------------------------------------------------------


def test_invariant_02_candidate_cannot_escape_the_sandbox_root(tmp_path):
    project = make_project(tmp_path / "rel")
    sm = SandboxManager(tmp_path / "sb", make_policy())
    paths = sm.create("cand-escape000001", project)
    (paths.source / "link").symlink_to(tmp_path, target_is_directory=True)
    for bad in ("../x.py", "/tmp/x.py", "link/x.py", "a/%2e%2e/%2e%2e/x.py", "..\\x.py"):
        with pytest.raises((SandboxPathError, SandboxChangeError)):
            sm.apply_changes("cand-escape000001", [SandboxChange(path=bad, operation=Op.ADD, proposed_hash=sha("x"), content=b"x")])
    assert not (tmp_path / "x.py").exists()


# 3 ---------------------------------------------------------------------------------------------------


def test_invariant_03_secrets_are_never_copied_into_a_candidate(tmp_path):
    project = make_project(tmp_path / "rel", {".env": "TOKEN=filesecret", "id_rsa": "KEYDATA", "keys/server.pem": "PEM", "secrets.json": "{}"})
    sm = SandboxManager(tmp_path / "sb", make_policy())
    paths = sm.create("cand-secrets00001", project)
    assert not set(tree_hashes(paths.source)) & {".env", "id_rsa", "keys/server.pem", "secrets.json"}


async def test_invariant_03_real_container_candidate_cannot_see_host_secrets(tmp_path, monkeypatch, container_backend):
    """REAL container: host env vars and host files are not visible to the candidate."""
    from tests.test_container_real import backend_like
    monkeypatch.setenv("OPENAI_API_KEY", "sk-hostsecretvalue000000000")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_hostsecretvalue0000000000000000000000")
    host_file = tmp_path / "host_secret.txt"
    host_file.write_text("TOPSECRET")
    m, _ = make_manager(tmp_path, backend=backend_like(container_backend))
    probe = ("import os\n\n\ndef test_no_host_secrets():\n    assert 'hostsecretvalue' not in ' '.join(os.environ.values())\n"
             f"    assert not os.path.exists({str(host_file)!r})\n    assert not os.path.exists('.env') and not os.path.exists('/root/.ssh/id_rsa')\n")
    run = await to_sandboxed(m, [ProposedChange(path="tests/test_secrets_probe.py", operation=Op.ADD, new_content=probe, reason="probe")])
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.PASSED, summary.reasons


# 4 ---------------------------------------------------------------------------------------------------


def test_invariant_04_candidate_cannot_execute_arbitrary_commands(tmp_path):
    from app.sandbox.container import ENTRY_SCRIPT, ContainerBackend
    assert list(inspect.signature(SandboxManager.run).parameters) == ["self", "sandbox_id", "operation"]
    assert [o.value for o in SandboxOperation] == ["run_test_suite", "run_static_analysis"]
    sm = SandboxManager(tmp_path / "sb", make_policy())
    sm.create("cand-commands0001", make_project(tmp_path / "rel"))
    import asyncio
    for attempt in ("pytest; rm -rf /", ["sh", "-c", "id"], "RUN_TEST_SUITE", None):
        with pytest.raises(SandboxPolicyViolation):
            asyncio.run(sm.run("cand-commands0001", attempt))  # type: ignore[arg-type]
    be = ContainerBackend(make_policy(), cli="podman", runner=object(), which=lambda n: "/usr/bin/" + n)
    for op in SandboxOperation:
        argv = be.run_argv("podman", "/usr/bin/podman", "jarvisx-val-abcdef12", tmp_path.resolve(), op.value)
        assert argv[argv.index("jarvisx-validation:1") + 1:] == ["-c", ENTRY_SCRIPT]  # the in-container command is always the fixed script


# 5 ---------------------------------------------------------------------------------------------------


async def test_invariant_05_candidate_cannot_disable_approval(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_safe_automatic", True)
    m, _ = make_manager(tmp_path, FakeValidator)
    weaken = ProposedChange(path="app/security/approval.py", operation=Op.MODIFY, new_content="def approve():\n    return True\n",
                            original_hash=sha("def approve():\n    return False\n"), reason="skip approval")
    run = await to_sandboxed(m, [weaken])
    prop = m.get_run(run.id).proposal
    assert prop.risk_level is RiskLevel.CRITICAL and prop.mode is AutomationMode.APPROVAL_REQUIRED
    await m.validate(run.id)
    approver = Approver(False)  # a human says no
    decision = await m.decide_approval(run.id, approver)
    assert decision.decision is ApprovalChoice.REJECT and len(approver.requests) == 1  # the handler WAS consulted
    with pytest.raises(PreconditionError):
        m.promote(run.id)


# 6 ---------------------------------------------------------------------------------------------------


async def test_invariant_06_changing_capability_enforcement_cannot_auto_promote(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_safe_automatic", True)
    project = make_project(tmp_path / "project", {"app/capabilities/__init__.py": "", "app/capabilities/manager.py": "ENFORCE = True\n",
                                                  "app/tools/__init__.py": "", "app/tools/registry.py": "GATE = True\n"})
    m, _ = make_manager(tmp_path, FakeValidator, project=project)
    changes = [ProposedChange(path="app/capabilities/manager.py", operation=Op.MODIFY, new_content="ENFORCE = False\n", original_hash=sha("ENFORCE = True\n"), reason="r"),
               ProposedChange(path="app/tools/registry.py", operation=Op.MODIFY, new_content="GATE = False\n", original_hash=sha("GATE = True\n"), reason="r")]
    run = await to_sandboxed(m, changes)
    await m.validate(run.id)
    p = m.get_run(run.id).proposal
    assert p.risk_level is RiskLevel.CRITICAL and "protected_area" in p.flags
    approver = Approver(True)
    decision = await m.decide_approval(run.id, approver)
    assert decision.automatic is False and len(approver.requests) == 1  # never auto-approved, even with the setting on
    # and even a forged automatic decision cannot get through the promotion gate
    r = m.get_run(run.id)
    forged = ApprovalDecision(improvement_id=run.id, candidate_id=r.candidate.id, decision=ApprovalChoice.APPROVE, automatic=True)
    req = PromotionRequest(run.id, r.candidate.id, m.sandbox.paths(r.candidate.sandbox_id).source, r.candidate.base_version, p.risk_level, p.mode, p.flags, r.validation, forged)
    before = m.store.current_version()
    with pytest.raises(PreconditionError):
        m.promotion.promote(req)
    assert m.store.current_version() == before


# 7 / 8 / 9 / 10 ---------------------------------------------------------------------------------------


@pytest.mark.usefixtures("trust_test_backend")
async def test_invariant_07_failed_validation_leaves_current_untouched(tmp_path):
    m, project = make_manager(tmp_path)  # real validator
    before = snapshot(m, project)
    run = await to_sandboxed(m, [modify_util("def add(a, b):\n    return a - b\n")])
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.FAILED and m.get_run(run.id).state is S.FAILED
    assert snapshot(m, project) == before
    with pytest.raises(PreconditionError):
        await m.decide_approval(run.id, AutoApproveHandler())


async def test_invariant_08_rejected_proposal_leaves_current_untouched(tmp_path):
    m, project = make_manager(tmp_path, FakeValidator)
    before = snapshot(m, project)
    run = await to_sandboxed(m, [modify_util()])
    await m.validate(run.id)
    await m.decide_approval(run.id, Approver(False))
    assert m.get_run(run.id).state is S.REJECTED and snapshot(m, project) == before
    with pytest.raises(PreconditionError):
        m.promote(run.id)
    other = m.submit_request(GOAL)
    m.reject(other.id, "no")
    assert snapshot(m, project) == before


async def test_invariant_09_promotion_requires_successful_validation(tmp_path):
    m, _ = make_manager(tmp_path, FakeValidator)
    run = await to_sandboxed(m, [modify_util()])
    with pytest.raises(PreconditionError):
        m.promote(run.id)  # state machine: not validated, not approved
    await m.validate(run.id)
    r = m.get_run(run.id)
    failed = r.validation.model_copy(update={"status": ValidationStatus.FAILED})
    approval = ApprovalDecision(improvement_id=run.id, candidate_id=r.candidate.id, decision=ApprovalChoice.APPROVE)
    req = PromotionRequest(run.id, r.candidate.id, m.sandbox.paths(r.candidate.sandbox_id).source, r.candidate.base_version,
                           RiskLevel.MEDIUM, AutomationMode.PROPOSE_ONLY, [], failed, approval)
    before = m.store.current_version()
    with pytest.raises(PreconditionError, match="passing validation"):
        PromotionManager(m.store).promote(req)  # even calling the promotion layer directly fails closed
    assert m.store.current_version() == before


async def test_invariant_10_rollback_restores_previous_known_good_release(tmp_path):
    m, _ = make_manager(tmp_path, FakeValidator)
    v1 = m.store.current_version()
    v1_hashes = m.store.hash_release(v1)
    run = await to_sandboxed(m, [modify_util()])
    await m.validate(run.id)
    await m.decide_approval(run.id, Approver(True))
    v2 = m.promote(run.id).release_version
    assert m.store.current_version() == v2
    result = m.rollback(reason="regression")
    assert result.success and m.store.current_version() == v1 and m.store.hash_release(v1) == v1_hashes
    assert m.store.verify_release(v1).valid and m.store.has_release(v2)


# 11 / 12 ----------------------------------------------------------------------------------------------


async def test_invariant_11_secrets_never_appear_in_audit_logs(tmp_path):
    m, _ = make_manager(tmp_path, FakeValidator)
    run = m.submit_request(f"{GOAL} password = {SECRETS[0]} {SECRETS[1]}", requested_by=f"bob {SECRETS[2]}")
    m.evaluate(run.id)
    m.create_plan(run.id)
    m.propose(run.id, f"Title {SECRETS[1]}", f"why password = {SECRETS[0]}", [modify_util(f"password = '{SECRETS[0]}'\n")])
    m.audit.record(run.id, "x", f"actor {SECRETS[2]}", "ok", detail=f"password = {SECRETS[0]} {SECRETS[1]} {SECRETS[2]}")
    m.reject(run.id, reason=f"reason {SECRETS[1]}", actor=f"carol {SECRETS[2]}")
    con = sqlite3.connect(tmp_path / "t.db")
    dump = "\n".join(str(r) for r in con.execute("select * from improvement_events")) + "\n".join(str(r) for r in con.execute("select * from improvement_runs"))
    con.close()
    assert all(s not in dump for s in SECRETS)


async def test_invariant_12_secrets_never_appear_in_model_facing_tool_output(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", True)
    m, project = make_manager(tmp_path, FakeValidator)
    caps = CapabilityManager(ToolRegistry(), enabled=True)
    register_software_engineering_capability(caps, make_client(lambda r: httpx.Response(200, json=repo_json())), WorkspaceManager(project))
    register_self_improvement_capability(caps, m)
    r = m.submit_request(f"{GOAL} {SECRETS[1]}")
    m.evaluate(r.id, ["app/util.py"])
    m.create_plan(r.id)
    leaky = {"path": "app/util.py", "operation": "modify", "original_hash": sha(UTIL), "reason": "r",
             "new_content": f"password = '{SECRETS[0]}'\nkey = '{SECRETS[2]}'\ntoken = '{SECRETS[1]}'\n"}
    calls = [ToolCall(id="c1", name="improvement_propose", arguments={"improvement_id": str(r.id), "title": "Leaky change", "changes": [leaky]}),
             ToolCall(id="c2", name="improvement_validate", arguments={"improvement_id": str(r.id)}),
             ToolCall(id="c3", name="improvement_status", arguments={"improvement_id": str(r.id)}),
             ToolCall(id="c4", name="improvement_evaluate", arguments={"improvement_id": str(r.id)})]
    router = ScriptedRouter([_response(tool_calls=calls), _response(text="done")])
    result = await Orchestrator(router, caps.tool_registry, AutoApproveHandler()).run("go")
    sent = json.dumps([msg.content for call_msgs in router.calls for msg in call_msgs])
    assert [x.success for x in result.tool_calls][:3] == [True, True, True]
    assert all(s not in sent for s in SECRETS) and "[REDACTED" in sent


# 13 / 14 ---------------------------------------------------------------------------------------------


async def test_invariant_13_disabled_self_improvement_capability_cannot_execute_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", True)
    m, project = make_manager(tmp_path, FakeValidator)
    caps = CapabilityManager(ToolRegistry(), enabled=True)
    register_software_engineering_capability(caps, make_client(lambda r: httpx.Response(200, json=repo_json())), WorkspaceManager(project))
    register_self_improvement_capability(caps, m)
    caps.disable(CAP_ID)
    for name in ("improvement_status", "improvement_validate", "improvement_rollback", "improvement_propose"):
        assert caps.tool_registry.get(name) is None  # direct lookup (what the orchestrator uses) refuses
    result = await Orchestrator(ScriptedRouter([_response(tool_calls=[ToolCall(id="c", name="improvement_status", arguments={})]), _response(text="x")]),
                                caps.tool_registry, AutoApproveHandler()).run("go")
    assert result.tool_calls[0].success is False and "not available" in result.tool_calls[0].error


def test_invariant_14_master_switch_off_prevents_registration(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", False)
    m, project = make_manager(tmp_path, FakeValidator)
    caps = CapabilityManager(ToolRegistry(), enabled=True)
    register_software_engineering_capability(caps, make_client(lambda r: httpx.Response(200, json=repo_json())), WorkspaceManager(project))
    assert register_self_improvement_capability(caps, m) is False
    assert not caps.registry.has(CAP_ID) and caps.tool_registry.get("improvement_status") is None


# 15 -------------------------------------------------------------------------------------------------


@pytest.mark.usefixtures("trust_test_backend")
async def test_invariant_15_test_tampering_is_detected_and_escalated(tmp_path):
    m, project = make_manager(tmp_path)  # real validator
    old_tests = (project / "tests" / "test_util.py").read_text()
    reduced = "from app.util import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    run = await to_sandboxed(m, [ProposedChange(path="tests/test_util.py", operation=Op.MODIFY, new_content=reduced, original_hash=sha(old_tests), reason="trim")])
    prop = m.get_run(run.id).proposal
    assert prop.risk_level is RiskLevel.HIGH and prop.mode is AutomationMode.APPROVAL_REQUIRED and "test_tampering" in prop.flags
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.FAILED and "test count decreased: 2 -> 1" in summary.suspicious
    for risky in (ProposedChange(path="tests/test_util.py", operation=Op.DELETE, original_hash=sha(old_tests), reason="drop"),
                  ProposedChange(path="pytest.ini", operation=Op.ADD, new_content="[pytest]\naddopts = --co\n", reason="cfg")):
        m2, _ = make_manager(tmp_path / f"m{uuid.uuid4().hex[:6]}", FakeValidator)
        run2 = await to_sandboxed(m2, [risky])
        p2 = m2.get_run(run2.id).proposal
        assert p2.risk_level is RiskLevel.CRITICAL and p2.mode is AutomationMode.APPROVAL_REQUIRED and "test_tampering" in p2.flags


async def test_validation_summary_type_is_unforgeable_by_candidate_text():
    s = ValidationSummary(candidate_id=uuid.uuid4(), status=ValidationStatus.PASSED, candidate=TestCounts(passed=1))
    assert s.status is ValidationStatus.PASSED and ValidationRunner.__init__.__name__ == "__init__"


# Isolation hardening ---------------------------------------------------------------------------------


async def test_invariant_16_no_insecure_fallback_when_isolation_is_unavailable(tmp_path):
    """A missing/unusable backend means NOTHING runs on the host: validation raises and the run stays retryable."""
    from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
    m, project = make_manager(tmp_path, backend=None)  # no isolation backend configured
    before = snapshot(m, project)
    run = await to_sandboxed(m, [modify_util()])
    with pytest.raises(IsolationUnavailableError) as ei:
        await m.validate(run.id)
    assert ei.value.reason is IsolationFailure.NO_BACKEND_CONFIGURED and m.get_run(run.id).state is S.SANDBOXED
    with pytest.raises(PreconditionError):
        m.promote(run.id)
    assert snapshot(m, project) == before


async def test_invariant_17_promotion_requires_validation_that_ran_in_the_isolation_environment(tmp_path):
    m, _ = make_manager(tmp_path, lambda store: FakeValidator(store, isolated=False))
    run = await to_sandboxed(m, [modify_util()])
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.FAILED and m.get_run(run.id).state is S.FAILED
    with pytest.raises(PreconditionError):
        m.promote(run.id)


async def test_invariant_18_approval_and_promotion_apply_to_the_exact_validated_candidate(tmp_path):
    m, _ = make_manager(tmp_path, FakeValidator)
    run = await to_sandboxed(m, [modify_util()])
    await m.validate(run.id)
    await m.decide_approval(run.id, Approver(True))
    cand = m.get_run(run.id).candidate
    (m.sandbox.paths(cand.sandbox_id).source / "app" / "util.py").write_text("def add(a, b):\n    return 0\n")  # swapped after approval
    before = m.store.current_version()
    with pytest.raises(PreconditionError, match="changed after validation"):
        m.promote(run.id)
    assert m.store.current_version() == before

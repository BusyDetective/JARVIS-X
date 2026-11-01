from __future__ import annotations

import json
import shutil
import uuid

import pytest

from app.improvement.errors import PreconditionError
from app.improvement.models import (
    ApprovalChoice, ApprovalDecision, AutomationMode, RiskLevel, TestCounts, ValidationStatus, ValidationSummary,
)
from app.improvement.promotion import PromotionManager, PromotionRequest, check_promotion_preconditions
from app.improvement.rollback import RollbackManager
from app.versioning.manager import ReleaseStore, VersioningError
from app.versioning.manifest import tree_digest
from tests.improvement_helpers import fake_attestation, make_project, tree_hashes


class SimulatedCrash(BaseException):
    """Not an Exception: promotion cleanup must NOT run, just like a real crash."""


@pytest.fixture
def world(tmp_path):
    project = make_project(tmp_path / "project")
    store = ReleaseStore(tmp_path / "store")
    v1 = store.bootstrap(project)
    cand = tmp_path / "candidate"
    shutil.copytree(store.release_source(v1), cand)
    (cand / "app" / "util.py").write_text("def add(a, b):\n    return b + a\n")
    return store, v1, cand


def make_req(store, v1, cand, **over):
    cid = uuid.uuid4()
    digest = tree_digest(cand)
    fields = dict(
        improvement_id=uuid.uuid4(), candidate_id=cid, candidate_source=cand, base_version=v1, risk=RiskLevel.MEDIUM,
        mode=AutomationMode.PROPOSE_ONLY, flags=[],
        validation=ValidationSummary(candidate_id=cid, status=ValidationStatus.PASSED, baseline=TestCounts(passed=2),
                                     candidate=TestCounts(passed=2), test_count_delta=0,
                                     isolation=fake_attestation(), candidate_digest=digest),  # MOCK attestation: gate logic only
        approval=ApprovalDecision(improvement_id=uuid.uuid4(), candidate_id=cid, decision=ApprovalChoice.APPROVE, candidate_digest=digest),
        candidate_digest=digest, files_changed=["app/util.py"])
    fields.update(over)
    return PromotionRequest(**fields)


# --- preconditions: promotion fails closed -------------------------------------------------


def test_promotion_requires_a_passing_validation(world):
    store, v1, cand = world
    req = make_req(store, v1, cand)
    bad = req.validation.model_copy(update={"status": ValidationStatus.FAILED})
    with pytest.raises(PreconditionError, match="passing validation"):
        check_promotion_preconditions(make_req(store, v1, cand, validation=bad, candidate_id=bad.candidate_id), store)
    other = req.validation.model_copy(update={"candidate_id": uuid.uuid4()})
    with pytest.raises(PreconditionError, match="passing validation"):
        check_promotion_preconditions(make_req(store, v1, cand, validation=other), store)
    assert PromotionManager(store).promote.__name__ == "promote"
    with pytest.raises(PreconditionError):
        PromotionManager(store).promote(make_req(store, v1, cand, validation=other))
    assert store.current_version() == v1 and store.list_releases() == [v1]


def test_promotion_requires_an_explicit_approval(world):
    store, v1, cand = world
    req = make_req(store, v1, cand)
    rejected = req.approval.model_copy(update={"decision": ApprovalChoice.REJECT})
    with pytest.raises(PreconditionError, match="explicit approval"):
        PromotionManager(store).promote(make_req(store, v1, cand, approval=rejected, candidate_id=req.candidate_id, validation=req.validation))
    wrong = req.approval.model_copy(update={"candidate_id": uuid.uuid4()})
    with pytest.raises(PreconditionError, match="explicit approval"):
        PromotionManager(store).promote(make_req(store, v1, cand, approval=wrong, candidate_id=req.candidate_id, validation=req.validation))
    assert store.current_version() == v1


@pytest.mark.parametrize("risk,mode,flags", [
    (RiskLevel.CRITICAL, AutomationMode.APPROVAL_REQUIRED, ["protected_area"]),
    (RiskLevel.HIGH, AutomationMode.APPROVAL_REQUIRED, []),
    (RiskLevel.MEDIUM, AutomationMode.PROPOSE_ONLY, []),
    (RiskLevel.LOW, AutomationMode.SAFE_AUTOMATIC, ["dependency_change"]),
    (RiskLevel.LOW, AutomationMode.APPROVAL_REQUIRED, []),
])
def test_automatic_approval_only_for_low_risk_safe_automatic(world, risk, mode, flags):
    store, v1, cand = world
    req = make_req(store, v1, cand, risk=risk, mode=mode, flags=flags)
    forged = req.approval.model_copy(update={"automatic": True, "decided_by": "policy:safe_automatic"})
    with pytest.raises(PreconditionError, match="automatically|human"):
        check_promotion_preconditions(make_req(store, v1, cand, risk=risk, mode=mode, flags=flags, approval=forged,
                                               candidate_id=req.candidate_id, validation=req.validation), store)


def test_low_risk_safe_automatic_may_use_automatic_approval(world):
    store, v1, cand = world
    req = make_req(store, v1, cand, risk=RiskLevel.LOW, mode=AutomationMode.SAFE_AUTOMATIC)
    auto = req.approval.model_copy(update={"automatic": True})
    check_promotion_preconditions(make_req(store, v1, cand, risk=RiskLevel.LOW, mode=AutomationMode.SAFE_AUTOMATIC, approval=auto,
                                           candidate_id=req.candidate_id, validation=req.validation), store)


def test_stale_candidate_is_rejected_when_current_moved(world):
    store, v1, cand = world
    other = store.create_release(cand)
    store.write_pointer(other, [v1])
    with pytest.raises(PreconditionError, match="current release changed"):
        PromotionManager(store).promote(make_req(store, v1, cand))
    assert store.current_version() == other


# --- isolation and exact-candidate binding (gate logic; attestations here are MOCKS) -----------------------


def refused(store, v1, req, match):
    before = (store.current_version(), store.list_releases(), store.current().history)
    with pytest.raises(PreconditionError, match=match):
        PromotionManager(store).promote(req)
    assert (store.current_version(), store.list_releases(), store.current().history) == before and not store.journal_path.exists()


def test_promotion_is_impossible_without_isolated_validation(world):
    store, v1, cand = world
    base = make_req(store, v1, cand)
    for iso in (None, fake_attestation(network="host"), fake_attestation(user="0:0"), fake_attestation(read_only_rootfs=False),
                fake_attestation(capabilities_dropped=False), fake_attestation(no_new_privileges=False), fake_attestation(canary_passed=False),
                fake_attestation(backend="test-double"), fake_attestation(backend="host"), fake_attestation(host_mounts=["snapshot:ro", "home:rw"]),
                fake_attestation(writable_host_mounts=1)):
        validation = base.validation.model_copy(update={"isolation": iso})
        refused(store, v1, make_req(store, v1, cand, validation=validation, candidate_id=base.candidate_id, approval=base.approval),
                "required isolation environment")


def test_a_validation_summary_from_the_unsafe_test_double_is_not_promotable(world):
    """The host test double is only trusted when a test opts in; production never trusts it."""
    store, v1, cand = world
    base = make_req(store, v1, cand)
    validation = base.validation.model_copy(update={"isolation": fake_attestation(backend="test-double", image="TEST-DOUBLE-NOT-ISOLATED")})
    refused(store, v1, make_req(store, v1, cand, validation=validation, candidate_id=base.candidate_id, approval=base.approval),
            "required isolation environment")


def test_validation_and_approval_must_be_for_the_exact_candidate_tree(world):
    store, v1, cand = world
    base = make_req(store, v1, cand)
    other = "0" * 64
    refused(store, v1, make_req(store, v1, cand, candidate_id=base.candidate_id, approval=base.approval,
                                validation=base.validation.model_copy(update={"candidate_digest": other})), "not the candidate being promoted")
    refused(store, v1, make_req(store, v1, cand, candidate_id=base.candidate_id, validation=base.validation,
                                approval=base.approval.model_copy(update={"candidate_digest": other})), "not the candidate being promoted")
    refused(store, v1, make_req(store, v1, cand, candidate_id=base.candidate_id, validation=base.validation, approval=base.approval,
                                candidate_digest=other), "not the candidate being promoted")
    refused(store, v1, make_req(store, v1, cand, candidate_id=base.candidate_id, approval=base.approval, candidate_digest="",
                                validation=base.validation.model_copy(update={"candidate_digest": None})), "not the candidate being promoted")


def test_a_candidate_modified_after_validation_cannot_be_promoted(world):
    store, v1, cand = world
    req = make_req(store, v1, cand)  # digest taken (and "validated") now
    (cand / "app" / "util.py").write_text("def add(a, b):\n    return 42  # changed after validation\n")
    refused(store, v1, req, "changed after validation")
    (cand / "app" / "evil.py").write_text("x = 1\n")
    refused(store, v1, req, "changed after validation")


def test_a_candidate_tree_with_non_release_files_cannot_be_promoted(world):
    store, v1, cand = world
    (cand / ".env").write_text("TOKEN=secret")
    refused(store, v1, make_req(store, v1, cand), "not part of a release")


# --- successful promotion ---------------------------------------------------------------------


def test_successful_promotion_switches_atomically_and_keeps_the_old_release(world):
    store, v1, cand = world
    before_v1 = store.hash_release(v1)
    result = PromotionManager(store).promote(make_req(store, v1, cand))
    assert result.success and result.completed_steps == ["PREPARE", "VERIFY", "SWITCH", "CONFIRM"]
    v2 = result.release_version
    assert result.from_version == v1 and v2 != v1 and store.current_version() == v2 and store.current().history == [v1]
    assert store.verify_release(v1).valid and store.verify_release(v2).valid and store.hash_release(v1) == before_v1
    assert "return b + a" in (store.release_source(v2) / "app" / "util.py").read_text()
    assert "return a + b" in (store.release_source(v1) / "app" / "util.py").read_text()
    upd = store.read_update(v2)
    assert upd.parent_version == v1 and upd.risk_level == "medium" and upd.validation_status == "passed"
    assert upd.approval_status == "approved" and upd.files_changed == ["app/util.py"] and upd.test_summary["candidate"] == 2
    assert store.get_baseline(v2).passed == 2  # the new current release carries its own baseline
    assert not store.journal_path.exists() and result.rollback_available is True


def test_promotion_does_not_modify_the_candidate_or_leave_temp_dirs(world):
    store, v1, cand = world
    before = tree_hashes(cand)
    PromotionManager(store).promote(make_req(store, v1, cand))
    assert tree_hashes(cand) == before and list(store.releases_dir.glob(".tmp-*")) == []


# --- failures leave the current release untouched --------------------------------------------------


def test_failure_while_preparing_leaves_current_untouched(world, monkeypatch):
    store, v1, cand = world

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(store, "create_release", boom)
    result = PromotionManager(store).promote(make_req(store, v1, cand))
    assert result.success is False and result.failed_step == "PREPARE" and "unchanged" in result.error
    assert store.current_version() == v1 and store.list_releases() == [v1] and not store.journal_path.exists()


def test_failed_verification_removes_the_new_release_and_keeps_current(world, monkeypatch):
    store, v1, cand = world
    real = store.verify_release

    def fake(version):
        report = real(version)
        return report.model_copy(update={"valid": False}) if version != v1 else report

    monkeypatch.setattr(store, "verify_release", fake)
    result = PromotionManager(store).promote(make_req(store, v1, cand))
    assert result.success is False and result.failed_step == "VERIFY"
    assert store.current_version() == v1 and store.list_releases() == [v1] and not store.journal_path.exists()


def test_failed_switch_leaves_old_pointer(world, monkeypatch):
    store, v1, cand = world

    def boom(*a, **k):
        raise OSError("cannot write pointer")

    monkeypatch.setattr(store, "write_pointer", boom)
    result = PromotionManager(store).promote(make_req(store, v1, cand))
    assert result.success is False and result.failed_step == "SWITCH"
    assert store.current_version() == v1 and store.list_releases() == [v1]


def test_failed_confirmation_restores_the_previous_release(world, monkeypatch):
    store, v1, cand = world
    real = store.verify_release
    calls = {"n": 0}

    def flaky(version):
        calls["n"] += 1
        report = real(version)
        return report.model_copy(update={"valid": False}) if calls["n"] >= 2 and version != v1 else report  # passes VERIFY, fails CONFIRM

    monkeypatch.setattr(store, "verify_release", flaky)
    result = PromotionManager(store).promote(make_req(store, v1, cand))
    assert result.success is False and result.failed_step == "CONFIRM" and "previous release restored" in result.error
    assert store.current_version() == v1 and store.current().history == [] and store.list_releases() == [v1]


# --- crash recovery ----------------------------------------------------------------------------------


def crash_at(point):
    def hook(p):
        if p == point:
            raise SimulatedCrash(p)
    return hook


@pytest.mark.parametrize("point", ["journal_prepare", "after_prepare", "after_verify"])
def test_crash_before_the_switch_is_discarded_on_restart(world, point):
    store, v1, cand = world
    with pytest.raises(SimulatedCrash):
        PromotionManager(store, crash_at(point)).promote(make_req(store, v1, cand))
    assert store.journal_path.exists()
    restarted = ReleaseStore(store.root)  # a fresh process
    result = PromotionManager(restarted).recover()
    assert result.action == "DISCARDED" and result.current_version == v1
    assert restarted.current_version() == v1 and restarted.list_releases() == [v1]
    assert not restarted.journal_path.exists() and list(restarted.releases_dir.glob(".tmp-*")) == []
    assert restarted.verify_release(v1).valid


def test_crash_after_switch_completes_on_restart(world):
    store, v1, cand = world
    with pytest.raises(SimulatedCrash):
        PromotionManager(store, crash_at("after_switch")).promote(make_req(store, v1, cand))
    restarted = ReleaseStore(store.root)
    new_version = restarted.current_version()
    assert new_version != v1  # the pointer had already moved
    result = PromotionManager(restarted).recover()
    assert result.action == "COMPLETED" and result.current_version == new_version
    assert restarted.current().history == [v1] and restarted.verify_release(new_version).valid and not restarted.journal_path.exists()


def test_crash_after_switch_with_corrupted_new_release_reverts(world):
    store, v1, cand = world
    with pytest.raises(SimulatedCrash):
        PromotionManager(store, crash_at("after_switch")).promote(make_req(store, v1, cand))
    new_version = store.current_version()
    (store.release_source(new_version) / "app" / "util.py").write_text("corrupted")
    result = PromotionManager(ReleaseStore(store.root)).recover()
    assert result.action == "REVERTED" and result.current_version == v1
    fresh = ReleaseStore(store.root)
    assert fresh.current_version() == v1 and fresh.current().history == [] and not fresh.has_release(new_version)


def test_recover_with_no_journal_is_a_noop_and_cleans_temp_dirs(world):
    store, v1, _ = world
    (store.releases_dir / ".tmp-leftover").mkdir()
    result = PromotionManager(store).recover()
    assert result.action == "NONE" and result.current_version == v1 and not (store.releases_dir / ".tmp-leftover").exists()


def test_recover_with_unreadable_journal(world):
    store, v1, _ = world
    store.journal_path.write_text("{garbage")
    result = PromotionManager(store).recover()
    assert result.action == "DISCARDED" and store.current_version() == v1 and not store.journal_path.exists()


def test_journal_phases_are_written_in_order(world):
    store, v1, cand = world
    seen = []

    def hook(point):
        seen.append((point, json.loads(store.journal_path.read_text())["phase"]))

    PromotionManager(store, hook).promote(make_req(store, v1, cand))
    assert seen == [("journal_prepare", "PREPARE"), ("after_prepare", "VERIFY"), ("after_verify", "SWITCH"), ("after_switch", "SWITCH")]


# --- rollback ---------------------------------------------------------------------------------------


def promoted(world):
    store, v1, cand = world
    return store, v1, PromotionManager(store).promote(make_req(store, v1, cand)).release_version


def test_rollback_restores_the_previous_release_and_keeps_the_rolled_back_one(world):
    store, v1, v2 = promoted(world)
    result = RollbackManager(store).rollback()
    assert result.success and result.from_version == v2 and result.restored_version == v1
    assert store.current_version() == v1 and store.current().history == []
    assert store.has_release(v2) and store.verify_release(v2).valid  # never silently deleted


def test_rollback_walks_back_through_history(world, tmp_path):
    store, v1, v2 = promoted(world)
    cand = tmp_path / "cand3"
    shutil.copytree(store.release_source(v2), cand)
    (cand / "app" / "util.py").write_text("def add(a, b):\n    return a + b + 0\n")
    v3 = PromotionManager(store).promote(make_req(store, v2, cand)).release_version
    assert store.current().history == [v1, v2]
    assert RollbackManager(store).rollback().restored_version == v2
    assert RollbackManager(store).rollback().restored_version == v1
    assert RollbackManager(store).rollback().error_type == "NO_PREVIOUS_RELEASE" and store.has_release(v3)


def test_rollback_without_history_or_current(world, tmp_path):
    store, v1, _ = world
    r = RollbackManager(store).rollback()
    assert r.success is False and r.error_type == "NO_PREVIOUS_RELEASE" and store.current_version() == v1
    empty = ReleaseStore(tmp_path / "empty")
    assert RollbackManager(empty).rollback().error_type == "NO_CURRENT"


def test_rollback_refuses_a_corrupted_previous_release(world):
    store, v1, v2 = promoted(world)
    (store.release_source(v1) / "app" / "util.py").write_text("corrupted")
    r = RollbackManager(store).rollback()
    assert r.success is False and r.error_type == "INTEGRITY_FAILURE" and "1 modified" in r.error
    assert store.current_version() == v2 and store.current().history == [v1]


def test_rollback_with_missing_previous_release(world):
    store, v1, v2 = promoted(world)
    shutil.rmtree(store.releases_dir / v1)
    r = RollbackManager(store).rollback()
    assert r.success is False and r.error_type == "INTEGRITY_FAILURE" and store.current_version() == v2


def test_rollback_switch_failure_is_typed_and_leaves_current(world, monkeypatch):
    store, v1, v2 = promoted(world)

    def boom(*a, **k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(store, "write_pointer", boom)
    r = RollbackManager(store).rollback()
    assert r.success is False and r.error_type == "SWITCH_FAILED" and store.current_version() == v2


def test_rolled_back_release_is_protected_while_referenced(world):
    store, v1, v2 = promoted(world)
    with pytest.raises(VersioningError):
        store.remove_unreferenced_release(v1)

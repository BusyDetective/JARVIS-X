from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.improvement.errors import PreconditionError
from app.improvement.models import (
    ApprovalChoice,
    ApprovalDecision,
    AutomationMode,
    PromotionResult,
    RecoveryResult,
    RiskLevel,
    ValidationStatus,
    ValidationSummary,
)
from app.versioning.manager import ReleaseStore, atomic_write_json
from app.versioning.manifest import hash_tree, tree_digest
from app.versioning.models import TestBaseline, UpdateManifest

logger = logging.getLogger(__name__)
PHASES = ("PREPARE", "VERIFY", "SWITCH", "CONFIRM")


@dataclass
class PromotionRequest:
    improvement_id: uuid.UUID
    candidate_id: uuid.UUID
    candidate_source: Path
    base_version: str
    risk: RiskLevel
    mode: AutomationMode
    flags: list[str]
    validation: ValidationSummary
    approval: ApprovalDecision
    candidate_digest: str = ""  # digest of the exact candidate tree this request is for
    files_changed: list[str] = field(default_factory=list)


def check_promotion_preconditions(req: PromotionRequest, store: ReleaseStore) -> None:
    """Fail-closed gate, independent of whoever calls promote(): validated,
    approved, authorised for its risk, and based on the CURRENT release."""
    if req.validation.status != ValidationStatus.PASSED or req.validation.candidate_id != req.candidate_id:
        raise PreconditionError("promotion requires a passing validation of this candidate")
    if req.approval.decision != ApprovalChoice.APPROVE or req.approval.candidate_id != req.candidate_id:
        raise PreconditionError("promotion requires an explicit approval of this candidate")
    iso = req.validation.isolation
    if iso is None or not iso.satisfies_requirements():
        raise PreconditionError("validation did not run in the required isolation environment")
    if not req.candidate_digest or not (req.validation.candidate_digest == req.candidate_digest == req.approval.candidate_digest):
        raise PreconditionError("the validated or approved tree is not the candidate being promoted")
    if tree_digest(req.candidate_source) != req.candidate_digest:
        raise PreconditionError("the candidate tree changed after validation")
    if hash_tree(req.candidate_source, only_snapshot=True) != hash_tree(req.candidate_source, only_snapshot=False):
        raise PreconditionError("the candidate tree contains files that are not part of a release")
    eligible_for_auto = req.risk == RiskLevel.LOW and req.mode == AutomationMode.SAFE_AUTOMATIC and not req.flags
    if req.approval.automatic and not eligible_for_auto:
        raise PreconditionError("only low-risk SAFE_AUTOMATIC changes may be approved automatically")
    if req.risk == RiskLevel.CRITICAL and req.approval.automatic:
        raise PreconditionError("critical changes always need a human approval")
    if store.current_version() != req.base_version:
        raise PreconditionError("the current release changed since this candidate was built; rebuild it")


class PromotionManager:
    """PREPARE -> VERIFY -> SWITCH -> CONFIRM, journaled, so an interrupted
    promotion can be resolved deterministically by `recover()`.

    The ONLY thing that changes what is "current" is the atomic pointer swap in
    SWITCH. Every earlier step only creates a NEW release directory, which is
    deleted again if anything fails. The previous release is never touched.
    `crash_hook(point)` exists so tests can simulate a crash between steps."""

    def __init__(self, store: ReleaseStore, crash_hook: Callable[[str], None] | None = None) -> None:
        self._store = store
        self._hook = crash_hook or (lambda point: None)

    def _journal(self, phase: str, **extra) -> None:
        atomic_write_json(self._store.journal_path, {"phase": phase, **extra})

    def _clear_journal(self) -> None:
        self._store.journal_path.unlink(missing_ok=True)

    def promote(self, req: PromotionRequest) -> PromotionResult:
        check_promotion_preconditions(req, self._store)
        state = self._store.current()
        assert state is not None
        from_version = state.version
        old_history = list(state.history)
        steps: list[str] = []
        new_version: str | None = None
        step = "PREPARE"
        switched = False
        base = dict(improvement_id=str(req.improvement_id), from_version=from_version)
        try:
            self._journal("PREPARE", **base)
            self._hook("journal_prepare")
            cand = req.validation.candidate
            update = UpdateManifest(
                version="pending", parent_version=from_version, change_id=str(req.candidate_id),
                risk_level=req.risk.value, validation_status=req.validation.status.value,
                approval_status="approved_automatic" if req.approval.automatic else "approved",
                files_changed=sorted(req.files_changed),
                test_summary={"baseline": req.validation.baseline.passed if req.validation.baseline else None,
                              "candidate": cand.passed, "delta": req.validation.test_count_delta})
            new_version = self._store.create_release(
                req.candidate_source, update, TestBaseline(passed=cand.passed, failed=cand.failed, skipped=cand.skipped))
            steps.append("PREPARE")
            self._journal("VERIFY", new_version=new_version, **base)
            self._hook("after_prepare")

            step = "VERIFY"
            report = self._store.verify_release(new_version)
            if not report.valid:
                raise PreconditionError("the prepared release failed integrity verification")
            steps.append("VERIFY")
            self._journal("SWITCH", new_version=new_version, **base)
            self._hook("after_verify")

            step = "SWITCH"
            self._store.write_pointer(new_version, [*old_history, from_version])
            switched = True
            steps.append("SWITCH")
            self._hook("after_switch")

            step = "CONFIRM"
            now = self._store.current()
            if now is None or now.version != new_version or not self._store.verify_release(new_version).valid:
                raise PreconditionError("the switch could not be confirmed")
            steps.append("CONFIRM")
            self._clear_journal()
            logger.info("promotion: %s -> %s", from_version, new_version)
            return PromotionResult(success=True, improvement_id=req.improvement_id, from_version=from_version,
                                   release_version=new_version, completed_steps=steps, rollback_available=True)
        except Exception as exc:  # BaseException (a simulated or real crash) deliberately skips cleanup
            try:
                if switched:
                    self._store.write_pointer(from_version, old_history)  # put the old release back
                if new_version is not None:
                    self._store.remove_unreferenced_release(new_version)
                self._store.cleanup_temp_dirs()
                self._clear_journal()
            except Exception:  # noqa: BLE001 — recover() resolves whatever is left
                logger.error("promotion cleanup incomplete; run recovery")
            logger.error("promotion failed at %s: %s", step, type(exc).__name__)
            return PromotionResult(success=False, improvement_id=req.improvement_id, from_version=from_version,
                                   completed_steps=steps, failed_step=step,
                                   error=f"promotion failed at {step} ({type(exc).__name__}); the current release is unchanged"
                                   if not switched else f"promotion failed at {step}; previous release restored",
                                   rollback_available=bool(old_history))

    def recover(self) -> RecoveryResult:
        """Resolve an interrupted promotion after a crash. Deterministic: the
        pointer decides. If it still names the old release, the half-built
        release is discarded; if it names the new one and that release
        verifies, the promotion is completed; otherwise the old release is
        restored."""
        self._store.cleanup_temp_dirs()
        if not self._store.journal_path.exists():
            return RecoveryResult(action="NONE", current_version=self._store.current_version())
        try:
            journal = json.loads(self._store.journal_path.read_text())
        except ValueError:
            self._clear_journal()
            return RecoveryResult(action="DISCARDED", current_version=self._store.current_version(),
                                  detail="unreadable journal removed")
        state = self._store.current()
        new_version = journal.get("new_version")
        from_version = journal.get("from_version")
        if state is not None and new_version and state.version == new_version:
            if self._store.verify_release(new_version).valid:
                self._clear_journal()
                return RecoveryResult(action="COMPLETED", current_version=new_version, detail="switch had completed; confirmed",
                                      improvement_id=journal.get("improvement_id"), release_version=new_version)
            history = [v for v in state.history if v != from_version]
            self._store.write_pointer(from_version, history)
            self._store.remove_unreferenced_release(new_version)
            self._clear_journal()
            return RecoveryResult(action="REVERTED", current_version=from_version,
                                  detail="new release failed verification; previous release restored",
                                  improvement_id=journal.get("improvement_id"))
        if new_version and self._store.has_release(new_version):
            self._store.remove_unreferenced_release(new_version)
        self._clear_journal()
        return RecoveryResult(action="DISCARDED", current_version=self._store.current_version(),
                              detail=f"interrupted at {journal.get('phase')}; current release unchanged",
                              improvement_id=journal.get("improvement_id"))

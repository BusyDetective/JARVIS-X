from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.engineering.analysis import ProjectInspector
from app.improvement.approval import ApprovalGate
from app.improvement.audit import AuditLog
from app.improvement.discovery import ImprovementDiscovery
from app.improvement.errors import (
    ImprovementError,
    InvalidProposalError,
    PreconditionError,
)
from app.improvement.evaluator import ImprovementEvaluator, summarize_research
from app.improvement.models import (
    ALLOWED_TRANSITIONS,
    ApprovalChoice,
    ApprovalDecision,
    EvaluationResult,
    ImprovementCandidate,
    ImprovementRun,
    ImprovementState,
    RollbackResult,
    ValidationStatus,
    ValidationSummary,
    check_transition,
    utcnow,
)
from app.improvement.planner import ImprovementPlanner
from app.improvement.promotion import PromotionManager, PromotionRequest, check_promotion_preconditions
from app.improvement.proposals import BuiltProposal, ProposalBuilder, ProposedChange
from app.improvement.repository import ImprovementRepository
from app.improvement.rollback import RollbackManager
from app.improvement.validation import ValidationRunner
from app.sandbox.errors import IsolationUnavailableError
from app.sandbox.manager import SandboxManager
from app.sandbox.models import SandboxChange
from app.security.approval import ApprovalHandler
from app.security.untrusted import redact_text
from app.versioning.manager import ReleaseStore
from app.versioning.manifest import tree_digest
from app.web.models import ResearchMode, ResearchResult
from app.web.research import WebResearchManager
from app.workspace.manager import WorkspaceManager

logger = logging.getLogger(__name__)
S = ImprovementState


class ImprovementManager:
    """Coordinates the improvement lifecycle:

      DISCOVERED -> EVALUATED -> PLANNED -> PROPOSED -> SANDBOXED -> VALIDATING
      -> VALIDATED -> APPROVED -> PROMOTED (-> ROLLED_BACK)       (REJECTED / FAILED from most states)

    Invariants (all enforced structurally, and tested):
    - the CURRENT release is only ever changed by PromotionManager (after a
      passing validation AND an explicit approval) or RollbackManager; every
      other step reads the current release and writes only to a candidate
      sandbox or the database;
    - any failure before the pointer swap leaves the current release untouched;
    - state moves only along ALLOWED_TRANSITIONS; each step is audited;
    - nothing here executes a caller-supplied command (validation uses the fixed
      sandbox operations).
    The model-facing tools call propose/validate/rollback etc.; none of them can
    approve or promote — those methods take an ApprovalHandler / are not tools.
    """

    def __init__(
        self, repository: ImprovementRepository, store: ReleaseStore, sandbox: SandboxManager,
        web: WebResearchManager | None = None, *, promotion: PromotionManager | None = None,
        rollback: RollbackManager | None = None, validator: ValidationRunner | None = None,
        evaluator: ImprovementEvaluator | None = None, planner: ImprovementPlanner | None = None,
        discovery: ImprovementDiscovery | None = None, approval_gate: ApprovalGate | None = None,
        max_diff_chars: int | None = None, max_output_chars: int = 24_000,
    ) -> None:
        self.repository, self.store, self.sandbox, self.web = repository, store, sandbox, web
        self.promotion = promotion or PromotionManager(store)
        self.rollback_manager = rollback or RollbackManager(store)
        self.validator = validator or ValidationRunner(sandbox, store)
        self.evaluator = evaluator or ImprovementEvaluator()
        self.planner = planner or ImprovementPlanner()
        self.discovery = discovery or ImprovementDiscovery()
        self.approval_gate = approval_gate or ApprovalGate()
        self.audit = AuditLog(repository)
        self.proposals = ProposalBuilder(store, max_diff_chars)
        self.max_output_chars = max_output_chars
        self._staging = store.root / "proposed"

    # --- setup ------------------------------------------------------------------

    def startup_recovery(self):
        """Resolve interrupted work after a crash/restart:
        - an interrupted promotion is resolved by the pointer (see PromotionManager.recover) and the
          affected improvement is reconciled (COMPLETED -> PROMOTED, REVERTED -> FAILED, DISCARDED -> stays
          APPROVED so it can be retried);
        - any improvement left in VALIDATING (the process died mid-validation) is failed safely and its
          sandbox removed. Leftover validation CONTAINERS are removed by the backend's stale cleanup at the
          next preflight (or explicitly via ContainerBackend.cleanup_stale()).
        The current release is never modified by the validation part."""
        result = self.promotion.recover()
        if result.improvement_id:
            try:
                run = self.repository.get_run(uuid.UUID(result.improvement_id))
                if result.action == "COMPLETED" and run.state == S.APPROVED:
                    run = self._save(run.model_copy(update={"promoted_version": result.release_version}), S.PROMOTED)
                    self._log(run, "promote", "recovered", actor="recovery", detail=f"completed after interruption: {result.release_version}")
                    self._destroy_sandbox(run)
                elif result.action == "REVERTED" and run.state == S.APPROVED:
                    run = self._save(run, S.FAILED)
                    self._log(run, "promote", "reverted", actor="recovery", detail=result.detail)
                    self._destroy_sandbox(run)
                elif result.action == "DISCARDED":
                    self._log(run, "promote", "interrupted", actor="recovery", detail=result.detail)
            except ImprovementError:
                logger.error("could not reconcile the interrupted promotion")
        interrupted: list[str] = []
        for run in self.repository.list_runs(500):
            if run.state == S.VALIDATING:
                failed = self._save(run, S.FAILED)
                self._log(failed, "validate", "interrupted", actor="recovery", detail="process stopped during validation; failed safely")
                self._destroy_sandbox(failed)
                interrupted.append(str(run.id))
        return result.model_copy(update={"interrupted_validations": interrupted})

    def ensure_current_release(self, project_root: Path) -> str:
        """Snapshot the project as the first release if none exists. Reads the
        project tree; never modifies it."""
        return self.store.bootstrap(project_root)

    def _require_current(self) -> str:
        version = self.store.current_version()
        if version is None:
            raise PreconditionError("no current release exists; bootstrap one first")
        return version

    # --- helpers --------------------------------------------------------------------

    def get_run(self, improvement_id: uuid.UUID | str) -> ImprovementRun:
        return self.repository.get_run(self._uuid(improvement_id))

    @staticmethod
    def _uuid(value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except ValueError:
            raise ImprovementError("invalid improvement id") from None

    def _save(self, run: ImprovementRun, new_state: ImprovementState | None = None) -> ImprovementRun:
        if new_state is not None and new_state != run.state:
            check_transition(run.state, new_state)
            run = run.model_copy(update={"state": new_state})
        run = run.model_copy(update={"updated_at": utcnow()})
        return self.repository.update_run(run)

    def _log(self, run: ImprovementRun, action: str, result: str, actor: str = "improvement_engine", detail: str | None = None) -> None:
        self.audit.record(run.id, action, actor, result, run.candidate.id if run.candidate else None,
                          run.risk_level.value if run.risk_level else None, detail)

    def _fail(self, run: ImprovementRun, action: str, exc: BaseException) -> None:
        """Move to FAILED (when legal) and audit — never touches the current release."""
        try:
            fresh = self.repository.get_run(run.id)
            if S.FAILED in ALLOWED_TRANSITIONS[fresh.state]:
                fresh = self._save(fresh, S.FAILED)
            self._log(fresh, action, "failed", detail=f"{type(exc).__name__}")
            self._destroy_sandbox(fresh)
        except Exception:  # noqa: BLE001
            logger.error("could not record failure of %s", action)

    def _destroy_sandbox(self, run: ImprovementRun) -> None:
        if run.candidate and self.sandbox.exists(run.candidate.sandbox_id):
            self.sandbox.destroy(run.candidate.sandbox_id)
        shutil.rmtree(self._staging / str(run.id), ignore_errors=True)

    def _expect(self, run: ImprovementRun, *states: ImprovementState) -> None:
        if run.state not in states:
            raise PreconditionError(f"this step needs state {' or '.join(s.value for s in states)}, but the improvement is {run.state.value}")

    # --- lifecycle --------------------------------------------------------------------

    def submit_request(self, goal: str, scope: list[str] | None = None, constraints: list[str] | None = None,
                       requested_by: str = "user") -> ImprovementRun:
        red = lambda t: redact_text(t)[0]  # noqa: E731 — secrets never reach the database
        request = self.discovery.create_request(
            red(goal), [red(s) for s in scope or []], [red(c) for c in constraints or []], red(requested_by))
        run = self.repository.create_run(ImprovementRun(id=request.id, state=S.DISCOVERED, request=request))
        self._log(run, "request_submitted", "ok", actor=request.requested_by)
        return run

    async def research(self, improvement_id: uuid.UUID | str, query: str, max_results: int | None = None,
                       max_pages: int | None = None) -> ResearchResult:
        run = self.get_run(improvement_id)
        self._expect(run, S.DISCOVERED, S.EVALUATED, S.PLANNED)
        if self.web is None:
            raise ImprovementError("web research is not configured")
        result = await self.web.research(query, ResearchMode.SEARCH_AND_FETCH, max_results, max_pages)
        evidence = summarize_research(result)
        run = self._save(run.model_copy(update={"evidence": evidence.model_dump()}))
        self._log(run, "research", "ok", detail=f"{evidence.source_count} sources, {evidence.fetched_pages} pages")
        return result  # untrusted external data: it informs evaluation counts only; it is never applied

    def evaluate(self, improvement_id: uuid.UUID | str, planned_paths: list[str] | None = None) -> EvaluationResult:
        run = self.get_run(improvement_id)
        self._expect(run, S.DISCOVERED, S.EVALUATED)
        from app.improvement.evaluator import ResearchEvidence
        evaluation = self.evaluator.evaluate(run.request, ResearchEvidence(**run.evidence) if run.evidence else None,
                                             planned_paths or [p for p in run.request.scope if "/" in p or "." in p])
        run = self._save(run.model_copy(update={"evaluation": evaluation}), S.EVALUATED)
        self._log(run, "evaluate", evaluation.recommended_action.value, detail=f"score={evaluation.score}")
        return evaluation

    def create_plan(self, improvement_id: uuid.UUID | str):
        run = self.get_run(improvement_id)
        self._expect(run, S.EVALUATED)
        try:
            ws = WorkspaceManager(self.store.release_source(self._require_current()))
            structure = ProjectInspector(ws).inspect()
            plan = self.planner.create_plan(run.request, structure, run.evaluation)
        except ImprovementError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._fail(run, "plan", exc)
            raise ImprovementError("planning failed") from None
        run = self._save(run.model_copy(update={"plan": plan}), S.PLANNED)
        self._log(run, "plan", "ok")
        return plan

    def propose(self, improvement_id: uuid.UUID | str, title: str, rationale: str, changes: list[ProposedChange]) -> BuiltProposal:
        run = self.get_run(improvement_id)
        self._expect(run, S.PLANNED)
        base = self._require_current()
        try:
            built = self.proposals.build(run.id, base, redact_text(title)[0], redact_text(rationale)[0], changes)
        except InvalidProposalError as exc:
            self._log(run, "propose", "invalid", detail=str(exc))
            raise  # input problem: the run stays PLANNED so a corrected proposal can be submitted
        except Exception as exc:  # noqa: BLE001
            self._fail(run, "propose", exc)
            raise ImprovementError("could not build the proposal") from None
        stage = self._staging / str(run.id)
        stage.mkdir(parents=True, exist_ok=True)
        for ref, data in built.staged.items():
            (stage / ref).write_bytes(data)
        run = self._save(run.model_copy(update={"proposal": built.proposal}), S.PROPOSED)
        self._log(run, "propose", "ok", detail=f"{len(built.proposal.change_set.files)} file(s), risk {built.proposal.risk_level.value}")
        return built

    def create_sandbox(self, improvement_id: uuid.UUID | str) -> ImprovementCandidate:
        run = self.get_run(improvement_id)
        self._expect(run, S.PROPOSED)
        proposal = run.proposal
        assert proposal is not None
        candidate = ImprovementCandidate(improvement_id=run.id, base_version=proposal.base_version,
                                         sandbox_id=f"cand-{uuid.uuid4().hex[:16]}", change_set=proposal.change_set,
                                         risk_level=proposal.risk_level, source_digest="pending")
        try:
            if self.store.current_version() != proposal.base_version:
                raise PreconditionError("the current release changed since the proposal was made")
            self.sandbox.create(candidate.sandbox_id, self.store.release_source(proposal.base_version))
            stage = self._staging / str(run.id)
            changes = [SandboxChange(
                path=f.path, operation=f.operation, original_hash=f.original_hash, proposed_hash=f.proposed_hash,
                content=(stage / f.content_ref).read_bytes() if f.content_ref else None) for f in proposal.change_set.files]
            self.sandbox.apply_changes(candidate.sandbox_id, changes)
            candidate = candidate.model_copy(update={"source_digest": tree_digest(self.sandbox.paths(candidate.sandbox_id).source)})
        except Exception as exc:  # noqa: BLE001
            if self.sandbox.exists(candidate.sandbox_id):
                self.sandbox.destroy(candidate.sandbox_id)
            self._fail(run, "sandbox", exc)
            if isinstance(exc, ImprovementError):
                raise
            raise ImprovementError(f"could not build the candidate sandbox ({type(exc).__name__})") from None
        run = self._save(run.model_copy(update={"candidate": candidate}), S.SANDBOXED)
        shutil.rmtree(self._staging / str(run.id), ignore_errors=True)
        self._log(run, "sandbox", "ok")
        return candidate

    async def validate(self, improvement_id: uuid.UUID | str) -> ValidationSummary:
        run = self.get_run(improvement_id)
        self._expect(run, S.SANDBOXED)
        cand = run.candidate
        assert cand is not None
        try:
            await self.validator.preflight()  # BEFORE any state change: no isolation => nothing runs, state unchanged
        except IsolationUnavailableError as exc:
            self._log(run, "validate", "isolation_unavailable", detail=exc.reason.value)
            raise
        run = self._save(run, S.VALIDATING)
        self._log(run, "validate", "started")
        try:
            summary = await self.validator.validate(cand.id, cand.sandbox_id, cand.base_version, cand.change_set)
        except Exception as exc:  # noqa: BLE001
            self._fail(run, "validate", exc)
            if isinstance(exc, (ImprovementError, IsolationUnavailableError)):
                raise
            raise ImprovementError(f"validation could not run ({type(exc).__name__})") from None
        # Defence in depth: whatever the validator says, it only counts if it ran isolated on THIS tree.
        if summary.status == ValidationStatus.PASSED and (
                summary.isolation is None or not summary.isolation.satisfies_requirements()
                or summary.candidate_digest != cand.source_digest):
            summary = summary.model_copy(update={
                "status": ValidationStatus.FAILED,
                "reasons": [*summary.reasons, "validation did not run in the required isolation environment on this exact candidate"]})
        run = run.model_copy(update={"validation": summary})
        if summary.status == ValidationStatus.PASSED:
            run = self._save(run, S.VALIDATED)
            self._log(run, "validate", "passed", detail=f"tests {summary.candidate.passed} (delta {summary.test_count_delta})")
        else:
            run = self._save(run, S.FAILED)
            self._log(run, "validate", "failed", detail="; ".join(summary.reasons))
            self._destroy_sandbox(run)
        return summary

    async def decide_approval(self, improvement_id: uuid.UUID | str, handler: ApprovalHandler) -> ApprovalDecision:
        run = self.get_run(improvement_id)
        self._expect(run, S.VALIDATED)
        assert run.proposal and run.candidate and run.validation
        decision = await self.approval_gate.decide(
            handler, run.id, run.candidate.id, run.proposal, run.validation,
            rollback_available=self.store.current() is not None)
        run = run.model_copy(update={"approval": decision})
        if decision.decision == ApprovalChoice.APPROVE:
            run = self._save(run, S.APPROVED)
        else:
            run = self._save(run, S.REJECTED)
            self._destroy_sandbox(run)
        self._log(run, "approval", decision.decision.value, actor=decision.decided_by)
        return decision

    def reject(self, improvement_id: uuid.UUID | str, reason: str = "", actor: str = "user") -> ImprovementRun:
        run = self.get_run(improvement_id)
        check_transition(run.state, S.REJECTED)
        run = self._save(run, S.REJECTED)
        self._log(run, "reject", "rejected", actor=actor, detail=reason)
        self._destroy_sandbox(run)
        return run

    def promote(self, improvement_id: uuid.UUID | str) -> Any:
        """Promote an APPROVED, validated candidate. Not exposed as a tool."""
        run = self.get_run(improvement_id)
        self._expect(run, S.APPROVED)
        assert run.proposal and run.candidate and run.validation and run.approval
        req = PromotionRequest(
            improvement_id=run.id, candidate_id=run.candidate.id,
            candidate_source=self.sandbox.paths(run.candidate.sandbox_id).source, base_version=run.candidate.base_version,
            risk=run.proposal.risk_level, mode=run.proposal.mode, flags=run.proposal.flags,
            validation=run.validation, approval=run.approval, candidate_digest=run.candidate.source_digest,
            files_changed=run.candidate.change_set.paths)
        try:
            check_promotion_preconditions(req, self.store)
        except PreconditionError as exc:
            self._fail(run, "promote", exc)
            raise
        result = self.promotion.promote(req)
        run = self.repository.get_run(run.id).model_copy(update={"promotion": result})
        if result.success:
            run = self._save(run.model_copy(update={"promoted_version": result.release_version}), S.PROMOTED)
            self._log(run, "promote", "promoted", detail=f"{result.from_version} -> {result.release_version}")
        else:
            run = self._save(run, S.FAILED)
            self._log(run, "promote", "failed", detail=result.error)
        self._destroy_sandbox(run)
        return result

    def rollback(self, actor: str = "user", reason: str = "") -> RollbackResult:
        current = self.store.current_version()
        result = self.rollback_manager.rollback()
        run = None
        if current:
            run = next((r for r in self.repository.list_runs(500) if r.promoted_version == current and r.state == S.PROMOTED), None)
        if result.success and run is not None:
            run = self._save(run, S.ROLLED_BACK)
        if run is not None:
            self._log(run, "rollback", "ok" if result.success else (result.error_type or "failed").lower(), actor=actor, detail=reason or result.error)
        return result

    # --- status -------------------------------------------------------------------------

    def status(self, improvement_id: uuid.UUID | str | None = None) -> dict[str, Any]:
        state = self.store.current()
        base: dict[str, Any] = {
            "current_version": state.version if state else None,
            "rollback_available": bool(state and state.history),
            "releases": self.store.list_releases()[-10:],
            "isolation": self.sandbox.isolation_report(),
        }
        if improvement_id is not None:
            run = self.get_run(improvement_id)
            base["improvement"] = self._summarize(run)
            base["events"] = [{"action": e.action, "result": e.result, "actor": e.actor, "risk": e.risk,
                               "timestamp": e.timestamp.isoformat()} for e in self.audit.events(run.id)][-30:]
        else:
            base["improvements"] = [{"id": str(r.id), "state": r.state.value,
                                     "goal": r.request.goal[:120]} for r in self.repository.list_runs(20)]
        return base

    @staticmethod
    def _summarize(run: ImprovementRun) -> dict[str, Any]:
        out: dict[str, Any] = {"id": str(run.id), "state": run.state.value, "goal": run.request.goal}
        if run.evaluation:
            out["evaluation"] = {"score": run.evaluation.score, "risk": run.evaluation.risk_level.value,
                                 "recommended_action": run.evaluation.recommended_action.value, "blockers": run.evaluation.blockers}
        if run.proposal:
            out["proposal"] = {"title": run.proposal.title, "risk": run.proposal.risk_level.value, "mode": run.proposal.mode.value,
                               "flags": run.proposal.flags,
                               "files": [{"path": f.path, "operation": f.operation.value} for f in run.proposal.change_set.files]}
        if run.validation:
            out["validation"] = {"status": run.validation.status.value, "tests_baseline": run.validation.baseline.passed if run.validation.baseline else None,
                                 "tests_candidate": run.validation.candidate.passed, "delta": run.validation.test_count_delta,
                                 "static_analysis_passed": run.validation.static_analysis_passed,
                                 "suspicious": run.validation.suspicious, "reasons": run.validation.reasons}
        if run.approval:
            out["approval"] = {"decision": run.approval.decision.value, "decided_by": run.approval.decided_by}
        if run.promoted_version:
            out["promoted_version"] = run.promoted_version
        return out

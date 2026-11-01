from __future__ import annotations

import uuid
from typing import Any

from app.config.settings import settings
from app.improvement.classification import is_docs_path
from app.improvement.models import (
    ApprovalChoice,
    ApprovalDecision,
    AutomationMode,
    ChangeOperation,
    ImprovementProposal,
    RiskLevel,
    ValidationStatus,
    ValidationSummary,
)
from app.security.approval import ApprovalHandler
from app.security.permissions import PermissionLevel
from app.security.untrusted import redact_text

APPROVAL_TOOL_NAME = "promote_release"


def approval_summary(proposal: ImprovementProposal, validation: ValidationSummary, rollback_available: bool) -> dict[str, Any]:
    """What a human sees: what changes, why, risk, files, validation, tests and
    whether rollback is possible. No source content, no raw logs."""
    return {
        "title": proposal.title,
        "why": redact_text(proposal.rationale)[0],
        "risk": proposal.risk_level.value,
        "risk_reasons": proposal.risk_reasons[:20],
        "mode": proposal.mode.value,
        "flags": proposal.flags,
        "files": [{"path": f.path, "operation": f.operation.value} for f in proposal.change_set.files],
        "change_summary": proposal.diff_summary,
        "validation": {
            "status": validation.status.value,
            "tests_baseline": validation.baseline.passed if validation.baseline else None,
            "tests_candidate": validation.candidate.passed,
            "test_count_delta": validation.test_count_delta,
            "static_analysis_passed": validation.static_analysis_passed,
            "suspicious": validation.suspicious,
        },
        "isolation": ({"backend": validation.isolation.backend, "network": validation.isolation.network,
                       "user": validation.isolation.user, "image_id": validation.isolation.image_id[:19],
                       "verified": validation.isolation.satisfies_requirements()} if validation.isolation else None),
        "rollback_available": rollback_available,
        "base_version": proposal.base_version,
    }


def auto_approval_allowed(proposal: ImprovementProposal) -> bool:
    """A policy (never the model) may auto-approve ONLY a SAFE_AUTOMATIC,
    LOW-risk, documentation-only, non-deleting change, and only if the operator
    enabled SELF_IMPROVEMENT_SAFE_AUTOMATIC. Everything else needs a human."""
    return bool(
        settings.self_improvement_safe_automatic
        and proposal.mode == AutomationMode.SAFE_AUTOMATIC
        and proposal.risk_level == RiskLevel.LOW
        and not proposal.flags
        and all(is_docs_path(f.path) and f.operation != ChangeOperation.DELETE for f in proposal.change_set.files)
    )


class ApprovalGate:
    """Reuses the project's ApprovalHandler (the same mechanism that gates
    CONFIRM/DANGEROUS tools). The decision is binary: APPROVE or REJECT."""

    async def decide(
        self, handler: ApprovalHandler, improvement_id: uuid.UUID, candidate_id: uuid.UUID,
        proposal: ImprovementProposal, validation: ValidationSummary, rollback_available: bool,
    ) -> ApprovalDecision:
        if validation.status != ValidationStatus.PASSED:
            return ApprovalDecision(improvement_id=improvement_id, candidate_id=candidate_id, decision=ApprovalChoice.REJECT,
                                    decided_by="policy", reason="validation did not pass",
                                    candidate_digest=validation.candidate_digest)
        if auto_approval_allowed(proposal):
            return ApprovalDecision(improvement_id=improvement_id, candidate_id=candidate_id, decision=ApprovalChoice.APPROVE,
                                    decided_by="policy:safe_automatic", automatic=True, reason="low-risk documentation-only change",
                                    candidate_digest=validation.candidate_digest)
        approved = await handler.approve(APPROVAL_TOOL_NAME, approval_summary(proposal, validation, rollback_available),
                                         PermissionLevel.DANGEROUS)
        return ApprovalDecision(improvement_id=improvement_id, candidate_id=candidate_id,
                                decision=ApprovalChoice.APPROVE if approved else ApprovalChoice.REJECT,
                                decided_by="approval_handler", automatic=False, candidate_digest=validation.candidate_digest)

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.engineering.models import EngineeringPlan
from app.sandbox.models import ChangeOperation, IsolationAttestation

__all__ = ["ChangeOperation"]

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


class ImprovementState(str, Enum):
    DISCOVERED = "discovered"
    EVALUATED = "evaluated"
    PLANNED = "planned"
    PROPOSED = "proposed"
    SANDBOXED = "sandboxed"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    APPROVED = "approved"
    PROMOTED = "promoted"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


S = ImprovementState
# The ONLY legal moves. Anything else raises InvalidTransitionError.
ALLOWED_TRANSITIONS: dict[ImprovementState, frozenset[ImprovementState]] = {
    S.DISCOVERED: frozenset({S.EVALUATED, S.REJECTED, S.FAILED}),
    S.EVALUATED: frozenset({S.PLANNED, S.REJECTED, S.FAILED}),
    S.PLANNED: frozenset({S.PROPOSED, S.REJECTED, S.FAILED}),
    S.PROPOSED: frozenset({S.SANDBOXED, S.REJECTED, S.FAILED}),
    S.SANDBOXED: frozenset({S.VALIDATING, S.REJECTED, S.FAILED}),
    S.VALIDATING: frozenset({S.VALIDATED, S.REJECTED, S.FAILED}),
    S.VALIDATED: frozenset({S.APPROVED, S.REJECTED, S.FAILED}),
    S.APPROVED: frozenset({S.PROMOTED, S.REJECTED, S.FAILED}),
    S.PROMOTED: frozenset({S.ROLLED_BACK}),
    S.REJECTED: frozenset(),
    S.FAILED: frozenset(),
    S.ROLLED_BACK: frozenset(),
}
TERMINAL_STATES = frozenset(s for s, nxt in ALLOWED_TRANSITIONS.items() if not nxt)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ("low", "medium", "high", "critical").index(self.value)


def max_risk(levels: list["RiskLevel"]) -> "RiskLevel":
    return max(levels, key=lambda r: r.rank, default=RiskLevel.LOW)


class AutomationMode(str, Enum):
    SAFE_AUTOMATIC = "safe_automatic"
    PROPOSE_ONLY = "propose_only"
    APPROVAL_REQUIRED = "approval_required"


class RecommendedAction(str, Enum):
    IGNORE = "ignore"
    RESEARCH_MORE = "research_more"
    PROPOSE = "propose"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalChoice(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class ValidationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"


class ImprovementRequest(BaseModel):
    """A structured request. Free-form natural language is never executed;
    it is only ever the `goal` text of one of these."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    goal: str
    scope: list[str] = Field(default_factory=list, max_length=20)
    constraints: list[str] = Field(default_factory=list, max_length=20)
    requested_by: str = "user"
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("goal")
    @classmethod
    def _goal(cls, v: str) -> str:
        v = " ".join(v.split())
        if not 10 <= len(v) <= 1000:
            raise ValueError("goal must be 10-1000 characters")
        return v

    @field_validator("scope", "constraints")
    @classmethod
    def _items(cls, v: list[str]) -> list[str]:
        out = [" ".join(i.split()) for i in v if i and i.strip()]
        if any(len(i) > 300 for i in out):
            raise ValueError("items must be at most 300 characters")
        return out

    @field_validator("requested_by")
    @classmethod
    def _by(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("requested_by must be 1-100 characters")
        return v

    _tz = field_validator("created_at")(_utc)


class ChangeFile(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    operation: ChangeOperation
    original_hash: str | None = None
    proposed_hash: str | None = None
    content_ref: str | None = None  # name of the staged proposed content (never the content itself)
    reason: str = Field(default="", max_length=500)

    @field_validator("original_hash", "proposed_hash")
    @classmethod
    def _hash(cls, v: str | None) -> str | None:
        if v is not None and not _HASH_RE.match(v):
            raise ValueError("hashes must be lowercase SHA-256 hex digests")
        return v

    @model_validator(mode="after")
    def _shape(self) -> "ChangeFile":
        op = self.operation
        if op == ChangeOperation.ADD and (self.original_hash is not None or self.proposed_hash is None):
            raise ValueError("ADD needs proposed_hash and no original_hash")
        if op == ChangeOperation.MODIFY and (self.original_hash is None or self.proposed_hash is None):
            raise ValueError("MODIFY needs original_hash and proposed_hash")
        if op == ChangeOperation.DELETE and (self.original_hash is None or self.proposed_hash is not None):
            raise ValueError("DELETE needs original_hash and no proposed_hash")
        return self


class ChangeSet(BaseModel):
    files: list[ChangeFile] = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def _unique(self) -> "ChangeSet":
        paths = [f.path for f in self.files]
        if len(set(paths)) != len(paths):
            raise ValueError("a path may appear only once in a change set")
        return self

    @property
    def paths(self) -> list[str]:
        return [f.path for f in self.files]


class EvaluationResult(BaseModel):
    score: float = Field(ge=0, le=100)
    benefit_score: float = Field(ge=0, le=100)
    compatibility_score: float = Field(ge=0, le=100)
    risk_score: float = Field(ge=0, le=100)  # higher = riskier
    confidence_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    rationale: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    recommended_action: RecommendedAction
    heuristic: bool = True  # scores are deterministic heuristics, not truth


class ImprovementProposal(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    improvement_id: uuid.UUID
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(default="", max_length=2000)
    base_version: str
    change_set: ChangeSet
    risk_level: RiskLevel
    risk_reasons: list[str] = Field(default_factory=list)
    mode: AutomationMode
    requires_approval: bool = True
    flags: list[str] = Field(default_factory=list)  # e.g. "dependency_change", "test_tampering"
    diff_summary: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    _tz = field_validator("created_at")(_utc)


class ImprovementCandidate(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    improvement_id: uuid.UUID
    base_version: str
    sandbox_id: str
    change_set: ChangeSet
    risk_level: RiskLevel
    source_digest: str  # digest of the exact candidate tree (validation and approval are bound to it)
    created_at: datetime = Field(default_factory=utcnow)

    _tz = field_validator("created_at")(_utc)


class TestCounts(BaseModel):
    __test__ = False

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0


class ValidationResult(BaseModel):
    operation: str
    passed: bool
    exit_code: int | None = None
    timed_out: bool = False
    unavailable: bool = False
    duration_seconds: float = 0.0
    output_truncated: bool = False
    summary: str = ""  # bounded, redacted tail of the output — never a full log


class ValidationSummary(BaseModel):
    candidate_id: uuid.UUID
    status: ValidationStatus
    baseline: TestCounts | None = None
    candidate: TestCounts = Field(default_factory=TestCounts)
    test_count_delta: int | None = None
    results: list[ValidationResult] = Field(default_factory=list)
    static_analysis_passed: bool | None = None
    suspicious: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    isolation: IsolationAttestation | None = None  # the boundary the tests actually ran under
    candidate_digest: str | None = None  # digest of the exact tree that was validated


class ApprovalDecision(BaseModel):
    improvement_id: uuid.UUID
    candidate_id: uuid.UUID
    decision: ApprovalChoice
    decided_by: str = "approval_handler"
    automatic: bool = False  # True only for a policy auto-approval of a SAFE_AUTOMATIC change
    candidate_digest: str | None = None  # the approval applies to this exact tree
    reason: str = Field(default="", max_length=500)
    decided_at: datetime = Field(default_factory=utcnow)

    _tz = field_validator("decided_at")(_utc)


class PromotionResult(BaseModel):
    success: bool
    improvement_id: uuid.UUID | None = None
    from_version: str | None = None
    release_version: str | None = None
    completed_steps: list[str] = Field(default_factory=list)
    failed_step: str | None = None
    error: str | None = None
    rollback_available: bool = False


class RollbackResult(BaseModel):
    success: bool
    from_version: str | None = None
    restored_version: str | None = None
    error_type: str | None = None  # NO_CURRENT / NO_PREVIOUS_RELEASE / INTEGRITY_FAILURE / SWITCH_FAILED
    error: str | None = None


class RecoveryResult(BaseModel):
    action: str  # NONE / DISCARDED / COMPLETED / REVERTED
    current_version: str | None = None
    detail: str = ""
    improvement_id: str | None = None  # the improvement whose interrupted promotion was resolved
    release_version: str | None = None
    interrupted_validations: list[str] = Field(default_factory=list)  # runs found mid-validation and failed safely


class ImprovementRun(BaseModel):
    """Everything persisted about one improvement (metadata only — no source
    content, no raw logs, no secrets)."""

    id: uuid.UUID
    state: ImprovementState
    request: ImprovementRequest
    evaluation: EvaluationResult | None = None
    plan: EngineeringPlan | None = None
    proposal: ImprovementProposal | None = None
    candidate: ImprovementCandidate | None = None
    validation: ValidationSummary | None = None
    approval: ApprovalDecision | None = None
    promotion: PromotionResult | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    promoted_version: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    _tz = field_validator("created_at", "updated_at")(_utc)

    @property
    def risk_level(self) -> RiskLevel | None:
        return self.proposal.risk_level if self.proposal else (self.evaluation.risk_level if self.evaluation else None)


def check_transition(current: ImprovementState, new: ImprovementState) -> None:
    from app.improvement.errors import InvalidTransitionError

    if new not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransitionError(f"cannot move from {current.value} to {new.value}")

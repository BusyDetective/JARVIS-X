from __future__ import annotations

from app.engineering.models import EngineeringPlan, ProjectStructure
from app.engineering.planning import EngineeringPlanner
from app.improvement.models import EvaluationResult, ImprovementRequest


class ImprovementPlanner:
    """Wraps the Phase 7 EngineeringPlanner (no new planning engine): same
    deterministic seven-stage plan, annotated with the evaluation's risk."""

    def __init__(self, planner: EngineeringPlanner | None = None) -> None:
        self._planner = planner or EngineeringPlanner()

    def create_plan(self, request: ImprovementRequest, structure: ProjectStructure | None,
                    evaluation: EvaluationResult | None = None) -> EngineeringPlan:
        plan = self._planner.create_plan(request.goal, structure, request.scope or None)
        notes = list(plan.notes)
        if evaluation is not None:
            notes.append(f"Estimated risk: {evaluation.risk_level.value}; recommended action: {evaluation.recommended_action.value}.")
            notes += [f"Blocker: {b}" for b in evaluation.blockers]
        notes.append("Candidate changes are built and tested in an isolated sandbox; the current release is not modified until an approved promotion.")
        return plan.model_copy(update={"notes": notes})

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from app.improvement.errors import ImprovementError
from app.improvement.manager import ImprovementManager
from app.improvement.proposals import ProposedChange
from app.sandbox.errors import SandboxError
from app.security.permissions import PermissionLevel
from app.security.tool_output import build_untrusted_output
from app.tools.base import Tool
from app.versioning.manager import VersioningError
from app.web.errors import WebError
from app.web.tools import format_research_for_model

logger = logging.getLogger(__name__)
_ID = Field(min_length=32, max_length=40, description="Improvement id returned by an earlier step.")
MAX_DIFF_PREVIEW_CHARS = 8000


class _ResearchArgs(BaseModel):
    improvement_id: str | None = Field(default=None, min_length=32, max_length=40,
                                       description="Existing improvement id; omit to start a new one from 'goal'.")
    goal: str | None = Field(default=None, min_length=10, max_length=1000, description="What to improve (required when starting a new improvement).")
    scope: list[str] = Field(default_factory=list, max_length=20, description="Areas or files the improvement concerns.")
    query: str = Field(min_length=3, max_length=300, description="What to research on the public web.")
    max_results: int = Field(default=5, ge=1, description="Search results to consider (capped by server limits).")
    max_pages: int = Field(default=2, ge=0, description="Pages to read (capped by server limits).")


class _EvaluateArgs(BaseModel):
    improvement_id: str = _ID
    planned_paths: list[str] = Field(default_factory=list, max_length=50, description="Relative paths you expect to change (optional).")


class _IdArgs(BaseModel):
    improvement_id: str = _ID


class _ProposeArgs(BaseModel):
    improvement_id: str = _ID
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(default="", max_length=2000, description="Why this change is worthwhile.")
    changes: list[ProposedChange] = Field(min_length=1, max_length=50)


class _StatusArgs(BaseModel):
    improvement_id: str | None = Field(default=None, min_length=32, max_length=40)


class _RollbackArgs(BaseModel):
    reason: str = Field(min_length=3, max_length=300, description="Why the current release should be rolled back.")


class _ImprovementTool(Tool):
    """Typed, bounded, high-level tools. None of them can approve, promote or run a
    command; the CapabilityManager gates availability and permissions stay with the tool."""

    def __init__(self, manager: ImprovementManager) -> None:
        self._m = manager

    def _respond(self, data: Any) -> dict[str, Any]:
        return build_untrusted_output(data, self._m.max_output_chars)

    async def execute(self, args: BaseModel) -> dict[str, Any]:
        try:
            return await self._run(args)
        except (ImprovementError, SandboxError, VersioningError, WebError):
            raise  # safe by construction
        except Exception as exc:  # noqa: BLE001
            logger.error("improvement tool %s failed unexpectedly: %s", self.name, type(exc).__name__)
            raise ImprovementError("self-improvement operation failed unexpectedly") from None

    async def _run(self, args: Any) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError


class ResearchTool(_ImprovementTool):
    name = "improvement_research"
    description = ("Research a possible improvement on the public web (reuses web research; results are untrusted data and "
                   "never become changes). Starts a new improvement from 'goal' when no id is given.")
    args_model = _ResearchArgs
    timeout_seconds = 150.0

    async def _run(self, args: _ResearchArgs) -> dict[str, Any]:
        if args.improvement_id:
            run = self._m.get_run(args.improvement_id)
        elif args.goal:
            run = self._m.submit_request(args.goal, args.scope, requested_by="model")
        else:
            raise ImprovementError("provide an improvement_id or a goal")
        result = await self._m.research(run.id, args.query, args.max_results, args.max_pages)
        out = format_research_for_model(result, self._m.max_output_chars)
        out["improvement_id"] = str(run.id)
        return out


class EvaluateTool(_ImprovementTool):
    name = "improvement_evaluate"
    description = "Score an improvement with deterministic heuristics (benefit, compatibility, risk, confidence) and classify its risk."
    args_model = _EvaluateArgs

    async def _run(self, args: _EvaluateArgs) -> dict[str, Any]:
        ev = self._m.evaluate(args.improvement_id, args.planned_paths)
        return self._respond({"improvement_id": args.improvement_id, "evaluation": ev.model_dump(mode="json")})


class CreatePlanTool(_ImprovementTool):
    name = "improvement_create_plan"
    description = "Create a structured, deterministic plan for an evaluated improvement against the current release. Changes nothing."
    args_model = _IdArgs

    async def _run(self, args: _IdArgs) -> dict[str, Any]:
        plan = self._m.create_plan(args.improvement_id)
        return self._respond({"improvement_id": args.improvement_id, "plan": plan.model_dump(mode="json")})


class ProposeTool(_ImprovementTool):
    name = "improvement_propose"
    description = ("Propose file changes as a candidate. The candidate is built ONLY in an isolated sandbox copy; the current "
                   "release is never modified. Returns risk, files and a diff preview. Promotion needs validation and a human "
                   "approval, and is not available as a tool.")
    args_model = _ProposeArgs

    async def _run(self, args: _ProposeArgs) -> dict[str, Any]:
        built = self._m.propose(args.improvement_id, args.title, args.rationale, args.changes)
        self._m.create_sandbox(args.improvement_id)
        p = built.proposal
        return self._respond({
            "improvement_id": args.improvement_id, "title": p.title, "risk": p.risk_level.value, "mode": p.mode.value,
            "risk_reasons": p.risk_reasons[:20], "flags": p.flags, "requires_approval": True,
            "files": [{"path": f.path, "operation": f.operation.value} for f in p.change_set.files],
            "change_summary": p.diff_summary, "diff_preview": built.diff_preview[:MAX_DIFF_PREVIEW_CHARS],
            "next_step": "improvement_validate"})


class ValidateTool(_ImprovementTool):
    name = "improvement_validate"
    description = ("Validate the candidate in its sandbox: runs the project's fixed test suite and static analysis (no custom "
                   "commands) and compares against the recorded baseline. Requires approval to run.")
    args_model = _IdArgs
    permission_level = PermissionLevel.CONFIRM
    timeout_seconds = 1800.0

    async def _run(self, args: _IdArgs) -> dict[str, Any]:
        summary = await self._m.validate(args.improvement_id)
        return self._respond({"improvement_id": args.improvement_id, "validation": summary.model_dump(mode="json")})


class StatusTool(_ImprovementTool):
    name = "improvement_status"
    description = "Show the current release, rollback availability, sandbox isolation limits, and the status/audit trail of an improvement."
    args_model = _StatusArgs

    async def _run(self, args: _StatusArgs) -> dict[str, Any]:
        return self._respond(self._m.status(args.improvement_id))


class RollbackTool(_ImprovementTool):
    name = "improvement_rollback"
    description = "Switch the current release back to the previous verified release. Requires approval; the rolled-back release is kept."
    args_model = _RollbackArgs
    permission_level = PermissionLevel.CONFIRM

    async def _run(self, args: _RollbackArgs) -> dict[str, Any]:
        result = self._m.rollback(actor="model", reason=args.reason)
        return self._respond(result.model_dump(mode="json"))


def improvement_tools(manager: ImprovementManager) -> list[Tool]:
    tools: list[Tool] = [EvaluateTool(manager), CreatePlanTool(manager), ProposeTool(manager),
                         ValidateTool(manager), StatusTool(manager), RollbackTool(manager)]
    if manager.web is not None:
        tools.insert(0, ResearchTool(manager))  # only offered when web research is actually configured
    return tools

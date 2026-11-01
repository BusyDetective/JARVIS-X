from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.engineering.analysis import ProjectInspector
from app.engineering.diff import DiffGenerator
from app.engineering.errors import EngineeringError, InvalidPatchError
from app.engineering.models import FileChange
from app.engineering.planning import EngineeringPlanner
from app.security.tool_output import build_untrusted_output
from app.tools.base import Tool
from app.workspace.errors import WorkspaceError
from app.workspace.manager import WorkspaceManager

logger = logging.getLogger(__name__)


class _InspectArgs(BaseModel):
    path: str = Field(default="", max_length=1024, description="Sub-directory to inspect ('' for the whole workspace).")


class _ChangeArgs(BaseModel):
    path: str = Field(min_length=1, max_length=1024, description="File path relative to the workspace.")
    original_hash: str | None = Field(
        default=None, max_length=64,
        description="SHA-256 of the current file (from workspace_read_file); omit only for a new file.")
    new_content: str = Field(max_length=500_000, description="Complete proposed content of the file.")
    reason: str = Field(min_length=1, max_length=500, description="Why this change is proposed.")


class _DiffArgs(BaseModel):
    changes: list[_ChangeArgs] = Field(min_length=1, max_length=50)


class _PlanArgs(BaseModel):
    goal: str = Field(min_length=1, max_length=1000, description="What the engineering task should achieve.")
    relevant_files: list[str] = Field(default_factory=list, max_length=50, description="Files you already know are relevant.")


class _EngineeringTool(Tool):
    def __init__(self, workspace: WorkspaceManager) -> None:
        self._workspace = workspace

    def _respond(self, data: Any, **extra: Any) -> dict[str, Any]:
        return build_untrusted_output(data, self._workspace.limits.max_output_chars, **extra)

    async def execute(self, args: BaseModel) -> dict[str, Any]:
        try:
            return self._run(args)
        except (EngineeringError, WorkspaceError):
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("engineering tool %s failed unexpectedly: %s", self.name, type(exc).__name__)
            raise EngineeringError("engineering operation failed unexpectedly") from None

    def _run(self, args: Any) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError


class InspectProjectTool(_EngineeringTool):
    name = "engineering_inspect_project"
    description = ("Summarize the project workspace (read-only): files, folders, detected languages, "
                   "configuration files and likely entry points. Detection is by file name only; no code is run.")
    args_model = _InspectArgs

    def _run(self, args: _InspectArgs) -> dict[str, Any]:
        return self._respond(ProjectInspector(self._workspace).inspect(args.path).model_dump(mode="json"))


class ProposeDiffTool(_EngineeringTool):
    name = "engineering_propose_diff"
    description = ("Turn proposed file changes into a unified diff for review. PROPOSAL ONLY: nothing is written "
                   "or applied. Existing files need their current SHA-256 as original_hash.")
    args_model = _DiffArgs

    def _run(self, args: _DiffArgs) -> dict[str, Any]:
        try:
            changes = [FileChange(**c.model_dump()) for c in args.changes]
        except ValidationError as exc:
            raise InvalidPatchError(
                "invalid change in proposal: " + "; ".join(str(e["msg"]) for e in exc.errors())[:200]
            ) from None
        diff = DiffGenerator(self._workspace).generate(changes)
        return self._respond(diff.model_dump(mode="json"))


class CreatePlanTool(_EngineeringTool):
    name = "engineering_create_plan"
    description = ("Create a structured, deterministic engineering plan for a goal (inspect, identify files, "
                   "propose, patch, validate, approval). Planning only; it changes nothing.")
    args_model = _PlanArgs

    def _run(self, args: _PlanArgs) -> dict[str, Any]:
        structure = None if args.relevant_files else ProjectInspector(self._workspace).inspect("")
        plan = EngineeringPlanner().create_plan(args.goal, structure, args.relevant_files)
        return self._respond(plan.model_dump(mode="json"))


def engineering_tools(workspace: WorkspaceManager) -> list[Tool]:
    return [InspectProjectTool(workspace), ProposeDiffTool(workspace), CreatePlanTool(workspace)]

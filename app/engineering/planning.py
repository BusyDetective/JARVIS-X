from __future__ import annotations

import re
from typing import Sequence

from app.engineering.errors import EngineeringError
from app.engineering.models import EngineeringPlan, EngineeringTask, PlanStage, ProjectStructure

_STOPWORDS = {"the", "and", "for", "with", "that", "this", "from", "into", "add", "fix", "make", "use",
              "new", "all", "are", "not", "can", "should", "when", "where", "which", "how", "why"}
MAX_GOAL_CHARS = 1000
MAX_FILES = 10

_STEPS: list[tuple[PlanStage, str, str]] = [
    (PlanStage.INSPECT_PROJECT, "Inspect the project",
     "Review the project structure, languages, configuration and entry points."),
    (PlanStage.IDENTIFY_FILES, "Identify relevant files",
     "Locate the files that relate to the goal using listings and text search."),
    (PlanStage.UNDERSTAND_DEPENDENCIES, "Understand dependencies",
     "Read the relevant files and note what they import or depend on."),
    (PlanStage.PROPOSE_CHANGES, "Propose changes",
     "Describe the intended edits file by file, with reasons."),
    (PlanStage.GENERATE_PATCH, "Generate a patch",
     "Produce a unified diff for the proposed changes (nothing is written)."),
    (PlanStage.VALIDATE, "Validate",
     "Check the proposal against the existing code and tests before any change is applied."),
    (PlanStage.APPROVAL, "Request approval",
     "Present the diff and validation results for explicit human approval."),
]


def select_relevant_files(goal: str, structure: ProjectStructure, limit: int = MAX_FILES) -> list[str]:
    """Deterministic keyword match of goal words against file paths."""
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", goal.lower()) if t not in _STOPWORDS}
    scored = []
    for path in structure.files:
        low = path.lower()
        score = sum(1 for t in tokens if t in low)
        if score:
            scored.append((-score, path))
    return [p for _, p in sorted(scored)[:limit]]


class EngineeringPlanner:
    """Builds a typed, deterministic engineering plan. No LLM, no I/O, no
    execution — it only organizes the standard flow
    inspect -> identify -> understand -> propose -> patch -> validate -> approve."""

    def create_plan(
        self, goal: str, structure: ProjectStructure | None = None, relevant_files: Sequence[str] | None = None
    ) -> EngineeringPlan:
        goal = " ".join((goal or "").split())
        if not goal:
            raise EngineeringError("a goal is required")
        if len(goal) > MAX_GOAL_CHARS:
            raise EngineeringError(f"goal is too long (max {MAX_GOAL_CHARS} characters)")
        notes: list[str] = ["This is a proposal. No files are modified without a later, explicitly approved step."]
        if relevant_files:
            files = list(dict.fromkeys(f.strip() for f in relevant_files if f and f.strip()))[:MAX_FILES]
        elif structure is not None:
            files = select_relevant_files(goal, structure)
            if not files:
                notes.append("No files matched the goal by name; identify them with a code search.")
        else:
            files = []
        tasks: list[EngineeringTask] = []
        for i, (stage, title, description) in enumerate(_STEPS, 1):
            task_files: list[str] = []
            if stage == PlanStage.INSPECT_PROJECT and structure is not None:
                task_files = structure.config_files[:MAX_FILES]
            elif stage in (PlanStage.IDENTIFY_FILES, PlanStage.UNDERSTAND_DEPENDENCIES,
                           PlanStage.PROPOSE_CHANGES, PlanStage.GENERATE_PATCH):
                task_files = files
            tasks.append(EngineeringTask(
                id=f"step-{i}", stage=stage, title=title, description=description, files=list(task_files),
                depends_on=[f"step-{i - 1}"] if i > 1 else [],
            ))
        return EngineeringPlan(goal=goal, tasks=tasks, notes=notes)

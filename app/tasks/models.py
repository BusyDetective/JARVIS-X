from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TaskStatus(str, Enum):
    """Life-cycle status of a PERSISTED Task.

    NOTE: this is a different concept from `app.core.orchestrator.TaskStatus`,
    which describes the *outcome of a single orchestrator run*
    (COMPLETED / FAILED / MAX_ITERATIONS_REACHED / MAX_TOOL_CALLS_REACHED).
    That one is finer-grained and purely in-memory. This one is the
    coarser, persisted life-cycle a Task moves through from creation to a
    terminal state. `TaskManager`/`Orchestrator` map an orchestrator run's
    outcome onto one of these — COMPLETED stays COMPLETED, but every
    non-success outcome (FAILED, MAX_ITERATIONS_REACHED,
    MAX_TOOL_CALLS_REACHED) maps to this enum's FAILED, since none of them
    represent a completed task and this life-cycle has no "partial"
    terminal state.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Allowed transitions. Enforced by TaskManager — this mapping is the single
# source of truth for what counts as valid, so the rule lives in one place.
_ALLOWED_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLED}),
    TaskStatus.RUNNING: frozenset(
        {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def is_valid_transition(current: TaskStatus, target: TaskStatus) -> bool:
    """True if moving from `current` to `target` is an allowed life-cycle
    transition. COMPLETED/FAILED/CANCELLED are all terminal — nothing
    transitions out of them."""
    return target in _ALLOWED_TRANSITIONS.get(current, frozenset())


def _require_utc(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


class Task(BaseModel):
    """A persisted unit of work: one `user_request` run through the
    orchestrator, tracked from creation through to a terminal state.

    Deliberately holds only scalar/serializable fields — no arbitrary
    Python objects — so it can round-trip through SQLite cleanly (see
    `app.tasks.repository` for the TEXT/JSON mapping).
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    user_request: str
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: str | None = None
    error: str | None = None

    @field_validator("created_at", "started_at", "completed_at")
    @classmethod
    def _validate_utc(cls, v: datetime | None) -> datetime | None:
        return _require_utc(v)


class TaskRunStatus(str, Enum):
    """Status of a single TaskRun — one orchestrator iteration/model
    round-trip. Deliberately just three values with no transition table:
    a run is created RUNNING, then moves exactly once to a terminal state
    (COMPLETED or FAILED) when that iteration's model call finishes. There
    are no sub-states and nothing transitions out of a terminal one, so
    (unlike TaskStatus) no `is_valid_transition`-style enforcement is
    needed here — the orchestrator only ever calls
    `TaskManager.start_task_run()` once per iteration followed by exactly
    one of `complete_task_run()` / `fail_task_run()`.
    """

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskRun(BaseModel):
    """One execution round within a Task's orchestrator run — one
    iteration of the agent loop (one model round-trip).

    Preserves execution history SEPARATELY from the Task's own final
    result/error, which reflects only the overall outcome.

    Lifecycle: created with status=RUNNING and `started_at` set
    immediately before the model call for that iteration; updated exactly
    once afterward to COMPLETED (model call succeeded) or FAILED (it
    raised), with `completed_at` set at that point. A tool call failing
    during the SAME iteration, after the model call already succeeded,
    does NOT retroactively change this run back to FAILED — only the
    model round-trip itself determines this run's outcome; see
    `app.core.orchestrator` for how tool failures are handled separately.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    task_id: uuid.UUID
    iteration: int
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None
    status: TaskRunStatus = TaskRunStatus.RUNNING
    provider: str | None = None
    model: str | None = None
    error: str | None = None

    @field_validator("started_at", "completed_at")
    @classmethod
    def _validate_utc(cls, v: datetime | None) -> datetime | None:
        return _require_utc(v)

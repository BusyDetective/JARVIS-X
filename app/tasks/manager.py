from __future__ import annotations

import logging
import uuid

from app.providers.schemas import ToolResult
from app.tasks.models import Task, TaskRun, TaskRunStatus, TaskStatus, is_valid_transition, utcnow
from app.tasks.repository import TaskRepository

logger = logging.getLogger(__name__)


class InvalidTaskTransitionError(Exception):
    """Raised when asked to move a Task to a status its current status
    cannot legally transition to (e.g. COMPLETED -> RUNNING)."""

    def __init__(self, task_id: uuid.UUID, current: TaskStatus, target: TaskStatus) -> None:
        self.task_id = task_id
        self.current = current
        self.target = target
        super().__init__(
            f"Task {task_id}: cannot transition from {current.value} to {target.value}"
        )


class TaskManager:
    """Owns task LIFECYCLE and enforces valid state transitions.

    Sits above `TaskRepository`, which owns raw database access — this
    class contains no SQL. Valid transitions (see `app.tasks.models`):

        PENDING   -> RUNNING, CANCELLED
        RUNNING   -> COMPLETED, FAILED, CANCELLED
        COMPLETED -> (terminal, nothing)
        FAILED    -> (terminal, nothing)
        CANCELLED -> (terminal, nothing)

    Any other transition raises `InvalidTaskTransitionError` rather than
    silently applying it.
    """

    def __init__(self, repository: TaskRepository) -> None:
        self.repository = repository

    # --- Task life-cycle --------------------------------------------------

    def create_task(self, user_request: str) -> Task:
        return self.repository.create_task(Task(user_request=user_request))

    def get_task(self, task_id: uuid.UUID) -> Task:
        return self.repository.get_task(task_id)

    def list_tasks(self) -> list[Task]:
        return self.repository.list_tasks()

    def start_task(self, task_id: uuid.UUID) -> Task:
        return self._transition(task_id, TaskStatus.RUNNING, started_at=utcnow())

    def complete_task(self, task_id: uuid.UUID, result: str | None = None) -> Task:
        return self._transition(
            task_id, TaskStatus.COMPLETED, completed_at=utcnow(), result=result
        )

    def fail_task(self, task_id: uuid.UUID, error: str) -> Task:
        return self._transition(task_id, TaskStatus.FAILED, completed_at=utcnow(), error=error)

    def cancel_task(self, task_id: uuid.UUID) -> Task:
        return self._transition(task_id, TaskStatus.CANCELLED, completed_at=utcnow())

    def _transition(self, task_id: uuid.UUID, target: TaskStatus, **field_updates) -> Task:
        task = self.repository.get_task(task_id)
        if not is_valid_transition(task.status, target):
            raise InvalidTaskTransitionError(task_id, task.status, target)
        updated = task.model_copy(update={"status": target, **field_updates})
        return self.repository.update_task(updated)

    # --- Task runs (execution history) -------------------------------------
    #
    # Lifecycle: start_task_run() creates exactly one TaskRun per
    # iteration, status=RUNNING, started_at set immediately. Exactly one
    # of complete_task_run() / fail_task_run() follows it, moving that
    # SAME run to a terminal state with completed_at set. Neither method
    # creates a new row — both call TaskRepository.update_task_run on the
    # run object the caller already holds, so there is never more than one
    # TaskRun per iteration.

    def start_task_run(self, task_id: uuid.UUID, iteration: int) -> TaskRun:
        run = TaskRun(
            task_id=task_id,
            iteration=iteration,
            status=TaskRunStatus.RUNNING,
            started_at=utcnow(),
        )
        return self.repository.create_task_run(run)

    def complete_task_run(
        self,
        run: TaskRun,
        provider: str | None = None,
        model: str | None = None,
    ) -> TaskRun:
        updated = run.model_copy(
            update={
                "status": TaskRunStatus.COMPLETED,
                "completed_at": utcnow(),
                "provider": provider if provider is not None else run.provider,
                "model": model if model is not None else run.model,
            }
        )
        return self.repository.update_task_run(updated)

    def fail_task_run(self, run: TaskRun, error: str) -> TaskRun:
        updated = run.model_copy(
            update={"status": TaskRunStatus.FAILED, "completed_at": utcnow(), "error": error}
        )
        return self.repository.update_task_run(updated)

    def get_task_runs(self, task_id: uuid.UUID) -> list[TaskRun]:
        return self.repository.get_task_runs(task_id)

    # --- Tool results --------------------------------------------------

    def record_tool_result(
        self,
        task_id: uuid.UUID,
        result: ToolResult,
        task_run_id: uuid.UUID | None = None,
    ) -> None:
        self.repository.store_tool_result(task_id, result, task_run_id=task_run_id)

    def get_tool_results(self, task_id: uuid.UUID) -> list[ToolResult]:
        return self.repository.get_tool_results(task_id)

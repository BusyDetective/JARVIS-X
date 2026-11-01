from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.providers.schemas import ToolResult
from app.storage.database import connection_scope
from app.tasks.models import Task, TaskRun, TaskRunStatus, TaskStatus


class RepositoryError(Exception):
    """Raised for unexpected database failures. Database errors are never
    silently swallowed — every repository method either returns a typed
    result or raises this (or a subclass)."""


class TaskNotFoundError(RepositoryError):
    def __init__(self, task_id: uuid.UUID) -> None:
        self.task_id = task_id
        super().__init__(f"Task {task_id} not found")


class TaskRunNotFoundError(RepositoryError):
    def __init__(self, task_run_id: uuid.UUID) -> None:
        self.task_run_id = task_run_id
        super().__init__(f"TaskRun {task_run_id} not found")


# --- Serialization helpers (the ONE place that converts to/from SQLite's
# TEXT-only storage — nothing outside this module does json.dumps/loads or
# datetime<->str conversion for task data). ---------------------------------


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware (UTC) to persist")
    return dt.astimezone(timezone.utc).isoformat()


def _iso_to_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _row_to_task(row: sqlite3.Row) -> Task:
    return Task(
        id=uuid.UUID(row["id"]),
        user_request=row["user_request"],
        status=TaskStatus(row["status"]),
        created_at=_iso_to_dt(row["created_at"]),
        started_at=_iso_to_dt(row["started_at"]),
        completed_at=_iso_to_dt(row["completed_at"]),
        result=row["result"],
        error=row["error"],
    )


def _row_to_task_run(row: sqlite3.Row) -> TaskRun:
    return TaskRun(
        id=uuid.UUID(row["id"]),
        task_id=uuid.UUID(row["task_id"]),
        iteration=row["iteration"],
        started_at=_iso_to_dt(row["started_at"]),
        completed_at=_iso_to_dt(row["completed_at"]),
        status=TaskRunStatus(row["status"]),
        provider=row["provider"],
        model=row["model"],
        error=row["error"],
    )


def _row_to_tool_result(row: sqlite3.Row) -> ToolResult:
    return ToolResult(
        tool_call_id=row["tool_call_id"],
        name=row["name"],
        success=bool(row["success"]),
        result=json.loads(row["result_json"]) if row["result_json"] is not None else None,
        error=row["error"],
        arguments=json.loads(row["arguments_json"]) if row["arguments_json"] else {},
    )


class TaskRepository:
    """Owns ALL database access for tasks, task runs, and tool results.

    Every public method opens its own short-lived connection via
    `connection_scope` rather than holding one open across calls — see the
    concurrency note in `app.storage.database`. Returns typed Pydantic
    models (`Task`/`TaskRun`) or the canonical `ToolResult` dataclass,
    never raw `sqlite3.Row` objects — callers never touch SQL-shaped data.

    `db_path=None` (the default) uses the project's configured database
    (`settings.resolved_db_path`); tests pass an explicit temporary path.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = db_path

    def _connect(self):
        return connection_scope(self._db_path)

    # --- Task ---------------------------------------------------------

    def create_task(self, task: Task) -> Task:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO tasks
                        (id, user_request, status, created_at, started_at, completed_at, result, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(task.id),
                        task.user_request,
                        task.status.value,
                        _dt_to_iso(task.created_at),
                        _dt_to_iso(task.started_at),
                        _dt_to_iso(task.completed_at),
                        task.result,
                        task.error,
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to create task {task.id}: {exc}") from exc
        return task

    def get_task(self, task_id: uuid.UUID) -> Task:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE id = ?", (str(task_id),)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get task {task_id}: {exc}") from exc
        if row is None:
            raise TaskNotFoundError(task_id)
        return _row_to_task(row)

    def update_task(self, task: Task) -> Task:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    UPDATE tasks
                    SET user_request = ?, status = ?, created_at = ?, started_at = ?,
                        completed_at = ?, result = ?, error = ?
                    WHERE id = ?
                    """,
                    (
                        task.user_request,
                        task.status.value,
                        _dt_to_iso(task.created_at),
                        _dt_to_iso(task.started_at),
                        _dt_to_iso(task.completed_at),
                        task.result,
                        task.error,
                        str(task.id),
                    ),
                )
                if cur.rowcount == 0:
                    raise TaskNotFoundError(task.id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to update task {task.id}: {exc}") from exc
        return task

    def delete_task(self, task_id: uuid.UUID) -> None:
        try:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM tasks WHERE id = ?", (str(task_id),))
                if cur.rowcount == 0:
                    raise TaskNotFoundError(task_id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to delete task {task_id}: {exc}") from exc

    def list_tasks(self) -> list[Task]:
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM tasks ORDER BY created_at ASC").fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to list tasks: {exc}") from exc
        return [_row_to_task(row) for row in rows]

    # --- TaskRun --------------------------------------------------------

    def create_task_run(self, run: TaskRun) -> TaskRun:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO task_runs
                        (id, task_id, iteration, started_at, completed_at, status, provider, model, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(run.id),
                        str(run.task_id),
                        run.iteration,
                        _dt_to_iso(run.started_at),
                        _dt_to_iso(run.completed_at),
                        run.status.value,
                        run.provider,
                        run.model,
                        run.error,
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to create task run {run.id}: {exc}") from exc
        return run

    def update_task_run(self, run: TaskRun) -> TaskRun:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    UPDATE task_runs
                    SET iteration = ?, started_at = ?, completed_at = ?, status = ?,
                        provider = ?, model = ?, error = ?
                    WHERE id = ?
                    """,
                    (
                        run.iteration,
                        _dt_to_iso(run.started_at),
                        _dt_to_iso(run.completed_at),
                        run.status.value,
                        run.provider,
                        run.model,
                        run.error,
                        str(run.id),
                    ),
                )
                if cur.rowcount == 0:
                    raise TaskRunNotFoundError(run.id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to update task run {run.id}: {exc}") from exc
        return run

    def get_task_runs(self, task_id: uuid.UUID) -> list[TaskRun]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM task_runs WHERE task_id = ? ORDER BY iteration ASC",
                    (str(task_id),),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get task runs for task {task_id}: {exc}") from exc
        return [_row_to_task_run(row) for row in rows]

    # --- Tool results -----------------------------------------------------

    def store_tool_result(
        self,
        task_id: uuid.UUID,
        result: ToolResult,
        task_run_id: uuid.UUID | None = None,
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO tool_results
                        (id, task_id, task_run_id, created_at, tool_call_id, name,
                         success, result_json, error, arguments_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        str(task_id),
                        str(task_run_id) if task_run_id is not None else None,
                        _dt_to_iso(datetime.now(timezone.utc)),
                        result.tool_call_id,
                        result.name,
                        1 if result.success else 0,
                        json.dumps(result.result, default=str),
                        result.error,
                        json.dumps(result.arguments, default=str),
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(
                f"Failed to store tool result for task {task_id}: {exc}"
            ) from exc

    def get_tool_results(self, task_id: uuid.UUID) -> list[ToolResult]:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM tool_results WHERE task_id = ? ORDER BY created_at ASC",
                    (str(task_id),),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(
                f"Failed to get tool results for task {task_id}: {exc}"
            ) from exc
        return [_row_to_tool_result(row) for row in rows]

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.tasks.models import Task, TaskRun, TaskRunStatus, TaskStatus, is_valid_transition


# --- Task ------------------------------------------------------------------


def test_task_creation_has_sensible_defaults():
    task = Task(user_request="do something")
    assert isinstance(task.id, uuid.UUID)
    assert task.user_request == "do something"
    assert task.status == TaskStatus.PENDING
    assert task.started_at is None
    assert task.completed_at is None
    assert task.result is None
    assert task.error is None


def test_task_ids_are_unique():
    a = Task(user_request="a")
    b = Task(user_request="b")
    assert a.id != b.id


def test_task_created_at_is_timezone_aware_utc():
    task = Task(user_request="x")
    assert task.created_at.tzinfo is not None
    assert task.created_at.utcoffset() == timezone.utc.utcoffset(None)


def test_task_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        Task(user_request="x", started_at=datetime(2026, 1, 1))  # no tzinfo


def test_task_accepts_explicit_timezone_aware_datetime():
    dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    task = Task(user_request="x", started_at=dt)
    assert task.started_at == dt


def test_task_status_round_trips_through_json_mode_dump():
    task = Task(user_request="x", status=TaskStatus.RUNNING)
    assert task.model_dump()["status"] == TaskStatus.RUNNING
    assert task.model_dump(mode="json")["status"] == "running"


def test_task_missing_required_field_raises_validation_error():
    with pytest.raises(ValidationError):
        Task()  # user_request is required


# --- TaskRun -----------------------------------------------------------------


def test_task_run_requires_task_id_and_iteration():
    run = TaskRun(task_id=uuid.uuid4(), iteration=1, status=TaskRunStatus.COMPLETED)
    assert run.iteration == 1
    assert run.status == TaskRunStatus.COMPLETED
    assert run.started_at.tzinfo is not None
    assert run.completed_at is None


def test_task_run_defaults_to_running_status():
    run = TaskRun(task_id=uuid.uuid4(), iteration=1)
    assert run.status == TaskRunStatus.RUNNING
    assert run.completed_at is None
    assert run.error is None


def test_task_run_accepts_plain_string_status_value():
    # Pydantic coerces a matching plain string into the enum — repository
    # rows and older call sites that pass a string keep working.
    run = TaskRun(task_id=uuid.uuid4(), iteration=1, status="failed")
    assert run.status == TaskRunStatus.FAILED
    assert isinstance(run.status, TaskRunStatus)


def test_task_run_status_round_trips_through_json_mode_dump():
    run = TaskRun(task_id=uuid.uuid4(), iteration=1, status=TaskRunStatus.FAILED)
    assert run.model_dump()["status"] == TaskRunStatus.FAILED
    assert run.model_dump(mode="json")["status"] == "failed"


def test_task_run_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        TaskRun(
            task_id=uuid.uuid4(),
            iteration=1,
            status="completed",
            completed_at=datetime(2026, 1, 1),
        )


def test_task_run_missing_required_field_raises_validation_error():
    with pytest.raises(ValidationError):
        TaskRun(task_id=uuid.uuid4())  # missing iteration (status now defaults to RUNNING)


# --- Life-cycle transition table ---------------------------------------------


@pytest.mark.parametrize(
    "current,target,expected",
    [
        (TaskStatus.PENDING, TaskStatus.RUNNING, True),
        (TaskStatus.PENDING, TaskStatus.CANCELLED, True),
        (TaskStatus.RUNNING, TaskStatus.COMPLETED, True),
        (TaskStatus.RUNNING, TaskStatus.FAILED, True),
        (TaskStatus.RUNNING, TaskStatus.CANCELLED, True),
        (TaskStatus.PENDING, TaskStatus.COMPLETED, False),
        (TaskStatus.PENDING, TaskStatus.FAILED, False),
        (TaskStatus.COMPLETED, TaskStatus.RUNNING, False),
        (TaskStatus.COMPLETED, TaskStatus.FAILED, False),
        (TaskStatus.FAILED, TaskStatus.RUNNING, False),
        (TaskStatus.FAILED, TaskStatus.COMPLETED, False),
        (TaskStatus.CANCELLED, TaskStatus.COMPLETED, False),
        (TaskStatus.CANCELLED, TaskStatus.RUNNING, False),
    ],
)
def test_is_valid_transition(current, target, expected):
    assert is_valid_transition(current, target) is expected

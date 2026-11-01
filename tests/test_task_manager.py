from __future__ import annotations

import pytest

from app.providers.schemas import ToolResult
from app.tasks.manager import InvalidTaskTransitionError, TaskManager
from app.tasks.models import TaskRunStatus, TaskStatus
from app.tasks.repository import TaskRepository


@pytest.fixture
def manager(tmp_path):
    return TaskManager(TaskRepository(db_path=tmp_path / "manager_test.db"))


# --- Creation / retrieval --------------------------------------------------


def test_create_task_starts_pending(manager):
    task = manager.create_task("do something")
    assert task.status == TaskStatus.PENDING
    assert task.user_request == "do something"


def test_get_task_retrieves_persisted_task(manager):
    task = manager.create_task("find me")
    fetched = manager.get_task(task.id)
    assert fetched.id == task.id
    assert fetched.user_request == "find me"


def test_list_tasks(manager):
    manager.create_task("a")
    manager.create_task("b")
    tasks = manager.list_tasks()
    assert len(tasks) == 2


# --- Valid transitions -------------------------------------------------------


def test_start_task_transitions_to_running(manager):
    task = manager.create_task("x")
    started = manager.start_task(task.id)
    assert started.status == TaskStatus.RUNNING
    assert started.started_at is not None


def test_complete_task_from_running(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    completed = manager.complete_task(task.id, result="42")
    assert completed.status == TaskStatus.COMPLETED
    assert completed.result == "42"
    assert completed.completed_at is not None


def test_fail_task_from_running(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    failed = manager.fail_task(task.id, "boom")
    assert failed.status == TaskStatus.FAILED
    assert failed.error == "boom"


def test_cancel_task_from_pending(manager):
    task = manager.create_task("x")
    cancelled = manager.cancel_task(task.id)
    assert cancelled.status == TaskStatus.CANCELLED


def test_cancel_task_from_running(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    cancelled = manager.cancel_task(task.id)
    assert cancelled.status == TaskStatus.CANCELLED


# --- Invalid transitions -----------------------------------------------------


def test_cannot_start_a_completed_task(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    manager.complete_task(task.id)
    with pytest.raises(InvalidTaskTransitionError):
        manager.start_task(task.id)


def test_cannot_start_a_failed_task(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    manager.fail_task(task.id, "err")
    with pytest.raises(InvalidTaskTransitionError):
        manager.start_task(task.id)


def test_cannot_complete_a_cancelled_task(manager):
    task = manager.create_task("x")
    manager.cancel_task(task.id)
    with pytest.raises(InvalidTaskTransitionError):
        manager.complete_task(task.id)


def test_cannot_complete_a_pending_task_directly(manager):
    task = manager.create_task("x")
    with pytest.raises(InvalidTaskTransitionError):
        manager.complete_task(task.id)


def test_cannot_fail_a_pending_task_directly(manager):
    task = manager.create_task("x")
    with pytest.raises(InvalidTaskTransitionError):
        manager.fail_task(task.id, "err")


def test_invalid_transition_error_carries_task_id_and_statuses(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    manager.complete_task(task.id)
    with pytest.raises(InvalidTaskTransitionError) as exc_info:
        manager.start_task(task.id)
    assert exc_info.value.task_id == task.id
    assert exc_info.value.current == TaskStatus.COMPLETED
    assert exc_info.value.target == TaskStatus.RUNNING


# --- Task runs: start -> complete / fail lifecycle -----------------------------


def test_start_task_run_creates_a_running_run(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    run = manager.start_task_run(task.id, iteration=1)

    assert run.iteration == 1
    assert run.status == TaskRunStatus.RUNNING
    assert run.started_at is not None
    assert run.completed_at is None

    runs = manager.get_task_runs(task.id)
    assert len(runs) == 1
    assert runs[0].id == run.id
    assert runs[0].status == TaskRunStatus.RUNNING


def test_complete_task_run_transitions_to_completed(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    run = manager.start_task_run(task.id, iteration=1)

    completed = manager.complete_task_run(run, provider="fake", model="m1")

    assert completed.id == run.id
    assert completed.status == TaskRunStatus.COMPLETED
    assert completed.completed_at is not None
    assert completed.provider == "fake"
    assert completed.model == "m1"

    runs = manager.get_task_runs(task.id)
    assert len(runs) == 1  # updated in place, not duplicated
    assert runs[0].status == TaskRunStatus.COMPLETED


def test_fail_task_run_transitions_to_failed_with_error(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    run = manager.start_task_run(task.id, iteration=1)

    failed = manager.fail_task_run(run, "model call exploded")

    assert failed.status == TaskRunStatus.FAILED
    assert failed.completed_at is not None
    assert failed.error == "model call exploded"

    runs = manager.get_task_runs(task.id)
    assert len(runs) == 1  # updated in place, not duplicated
    assert runs[0].status == TaskRunStatus.FAILED
    assert runs[0].error == "model call exploded"


def test_multiple_iterations_create_one_run_each_in_order(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)

    run1 = manager.start_task_run(task.id, iteration=1)
    manager.complete_task_run(run1, provider="fake", model="m1")
    run2 = manager.start_task_run(task.id, iteration=2)
    manager.complete_task_run(run2, provider="fake", model="m1")

    runs = manager.get_task_runs(task.id)
    assert [r.iteration for r in runs] == [1, 2]
    assert all(r.status == TaskRunStatus.COMPLETED for r in runs)


# --- Tool results --------------------------------------------------------------


def test_record_tool_result(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    result = ToolResult(tool_call_id="call_1", name="calculator", success=True, result=4)
    manager.record_tool_result(task.id, result)

    stored = manager.get_tool_results(task.id)
    assert len(stored) == 1
    assert stored[0].result == 4


def test_record_tool_result_linked_to_a_task_run(manager):
    task = manager.create_task("x")
    manager.start_task(task.id)
    run = manager.start_task_run(task.id, iteration=1)
    manager.complete_task_run(run, provider="fake", model="m1")
    result = ToolResult(tool_call_id="call_1", name="calculator", success=True, result=9)
    manager.record_tool_result(task.id, result, task_run_id=run.id)

    stored = manager.get_tool_results(task.id)
    assert stored[0].result == 9

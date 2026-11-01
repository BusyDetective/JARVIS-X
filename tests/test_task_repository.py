from __future__ import annotations

import uuid

import pytest

from app.providers.schemas import ToolResult
from app.tasks.models import Task, TaskRun, TaskRunStatus, TaskStatus
from app.tasks.repository import (
    RepositoryError,
    TaskNotFoundError,
    TaskRepository,
    TaskRunNotFoundError,
)


@pytest.fixture
def repo(tmp_path):
    # Always a temporary, test-local database — never the real project db.
    return TaskRepository(db_path=tmp_path / "test.db")


# --- Task CRUD -----------------------------------------------------------


def test_create_and_get_task(repo):
    task = Task(user_request="hello")
    repo.create_task(task)

    fetched = repo.get_task(task.id)
    assert fetched.id == task.id
    assert fetched.user_request == "hello"
    assert fetched.status == TaskStatus.PENDING
    assert fetched.created_at == task.created_at


def test_get_task_not_found_raises(repo):
    with pytest.raises(TaskNotFoundError):
        repo.get_task(uuid.uuid4())


def test_update_task(repo):
    task = Task(user_request="hello")
    repo.create_task(task)

    task.status = TaskStatus.RUNNING
    repo.update_task(task)

    fetched = repo.get_task(task.id)
    assert fetched.status == TaskStatus.RUNNING


def test_update_nonexistent_task_raises(repo):
    task = Task(user_request="ghost")
    with pytest.raises(TaskNotFoundError):
        repo.update_task(task)


def test_list_tasks_returns_all_in_creation_order(repo):
    t1 = Task(user_request="first")
    t2 = Task(user_request="second")
    repo.create_task(t1)
    repo.create_task(t2)

    tasks = repo.list_tasks()
    assert [t.user_request for t in tasks] == ["first", "second"]


def test_list_tasks_empty_database_returns_empty_list(repo):
    assert repo.list_tasks() == []


def test_delete_task(repo):
    task = Task(user_request="to delete")
    repo.create_task(task)
    repo.delete_task(task.id)

    with pytest.raises(TaskNotFoundError):
        repo.get_task(task.id)


def test_delete_nonexistent_task_raises(repo):
    with pytest.raises(TaskNotFoundError):
        repo.delete_task(uuid.uuid4())


# --- TaskRun ---------------------------------------------------------------


def test_create_and_get_task_runs(repo):
    task = Task(user_request="run me")
    repo.create_task(task)

    run1 = TaskRun(task_id=task.id, iteration=1, status=TaskRunStatus.COMPLETED, provider="fake", model="m1")
    run2 = TaskRun(task_id=task.id, iteration=2, status=TaskRunStatus.COMPLETED, provider="fake", model="m1")
    repo.create_task_run(run1)
    repo.create_task_run(run2)

    runs = repo.get_task_runs(task.id)
    assert [r.iteration for r in runs] == [1, 2]
    assert runs[0].provider == "fake"
    assert runs[0].task_id == task.id


def test_get_task_runs_for_task_with_none_returns_empty_list(repo):
    task = Task(user_request="no runs yet")
    repo.create_task(task)
    assert repo.get_task_runs(task.id) == []


def test_update_task_run(repo):
    task = Task(user_request="run me")
    repo.create_task(task)
    run = TaskRun(task_id=task.id, iteration=1, status=TaskRunStatus.COMPLETED)
    repo.create_task_run(run)

    run.status = TaskRunStatus.FAILED
    run.error = "boom"
    repo.update_task_run(run)

    fetched = repo.get_task_runs(task.id)[0]
    assert fetched.status == TaskRunStatus.FAILED
    assert fetched.error == "boom"


def test_update_nonexistent_task_run_raises(repo):
    run = TaskRun(task_id=uuid.uuid4(), iteration=1, status=TaskRunStatus.COMPLETED)
    with pytest.raises(TaskRunNotFoundError):
        repo.update_task_run(run)


# --- Tool results ------------------------------------------------------------


def test_store_and_get_tool_results(repo):
    task = Task(user_request="use a tool")
    repo.create_task(task)

    result = ToolResult(
        tool_call_id="call_abc",
        name="calculator",
        success=True,
        result=7,
        arguments={"a": 3.0, "b": 4.0},
    )
    repo.store_tool_result(task.id, result)

    stored = repo.get_tool_results(task.id)
    assert len(stored) == 1
    fetched = stored[0]
    assert fetched.tool_call_id == "call_abc"
    assert fetched.name == "calculator"
    assert fetched.success is True
    assert fetched.result == 7
    assert fetched.arguments == {"a": 3.0, "b": 4.0}
    assert fetched.error is None


def test_store_tool_result_with_task_run_link(repo):
    task = Task(user_request="use a tool")
    repo.create_task(task)
    run = TaskRun(task_id=task.id, iteration=1, status=TaskRunStatus.COMPLETED)
    repo.create_task_run(run)

    result = ToolResult(tool_call_id="call_x", name="echo", success=True, result="ok")
    repo.store_tool_result(task.id, result, task_run_id=run.id)

    stored = repo.get_tool_results(task.id)
    assert len(stored) == 1
    assert stored[0].result == "ok"


@pytest.mark.parametrize("value", ["a string", {"k": "v"}, [1, 2, 3], 42, 3.14, None])
def test_store_tool_result_serializes_various_result_types(repo, value):
    task = Task(user_request="echo various")
    repo.create_task(task)

    repo.store_tool_result(
        task.id,
        ToolResult(tool_call_id="call_echo", name="echo", success=True, result=value),
    )

    stored = repo.get_tool_results(task.id)
    assert stored[0].result == value


def test_failed_tool_result_preserves_error_and_null_result(repo):
    task = Task(user_request="fail a tool")
    repo.create_task(task)

    repo.store_tool_result(
        task.id,
        ToolResult(tool_call_id="call_fail", name="broken", success=False, error="boom"),
    )
    fetched = repo.get_tool_results(task.id)[0]
    assert fetched.success is False
    assert fetched.error == "boom"
    assert fetched.result is None


def test_get_tool_results_for_task_with_none_returns_empty_list(repo):
    task = Task(user_request="no tools used")
    repo.create_task(task)
    assert repo.get_tool_results(task.id) == []


# --- Persistence across re-instantiation --------------------------------------


def test_database_survives_repository_reinstantiation(tmp_path):
    db_path = tmp_path / "persist.db"
    repo1 = TaskRepository(db_path=db_path)
    task = Task(user_request="persist me")
    repo1.create_task(task)

    repo2 = TaskRepository(db_path=db_path)  # fresh instance, same file
    fetched = repo2.get_task(task.id)
    assert fetched.user_request == "persist me"


def test_repository_error_is_the_base_of_not_found_errors():
    assert issubclass(TaskNotFoundError, RepositoryError)
    assert issubclass(TaskRunNotFoundError, RepositoryError)

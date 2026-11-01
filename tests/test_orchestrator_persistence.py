"""Integration tests: Orchestrator + TaskManager (SQLite-backed).

Reuses the same ScriptedRouter/dummy-Tool pattern as test_orchestrator.py,
but injects a real TaskManager backed by a temporary SQLite database, to
prove the persistence integration end-to-end without changing the
orchestrator's core control flow. test_orchestrator.py's existing tests
(no task_manager) continue to pass unmodified — see
test_orchestrator_without_task_manager_touches_no_database below for an
explicit check of that default behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import BaseModel

from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as OrchestratorRunStatus
from app.providers.schemas import ModelResponse, ProviderError, ProviderErrorType, ToolCall
from app.security.approval import AutoApproveHandler
from app.security.permissions import PermissionLevel
from app.tasks.manager import TaskManager
from app.tasks.models import TaskRunStatus, TaskStatus
from app.tasks.repository import TaskRepository
from app.tools.base import Tool
from app.tools.registry import ToolRegistry


class ScriptedRouter:
    def __init__(self, outcomes: list):
        self._outcomes = list(outcomes)
        self.calls: list = []

    async def _next(self, messages):
        self.calls.append(messages)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def generate(self, messages):
        return await self._next(messages)

    async def generate_with_tools(self, messages, tools):
        return await self._next(messages)


def _response(text=None, tool_calls=None, provider="fake", model="fake-model") -> ModelResponse:
    return ModelResponse(text=text, tool_calls=tool_calls or [], provider=provider, model=model)


class NumberArgs(BaseModel):
    a: float
    b: float


class CalculatorTool(Tool):
    name = "calculator"
    description = "Adds two numbers"
    args_model = NumberArgs
    permission_level = PermissionLevel.SAFE

    async def execute(self, args: NumberArgs) -> float:
        return args.a + args.b


class RaisingTool(Tool):
    name = "raising_tool"
    description = "Always raises"
    args_model = NumberArgs
    permission_level = PermissionLevel.SAFE

    async def execute(self, args: NumberArgs) -> str:
        raise RuntimeError("tool boom")


class ExplodingApprovalHandler:
    """Simulates a genuinely unexpected failure inside the orchestrator's
    own machinery (NOT a provider error, NOT a tool failure) to exercise
    the 'mark FAILED before re-raising' crash path. Duck-typed rather than
    subclassing ApprovalHandler — the orchestrator never does isinstance
    checks on it."""

    async def approve(self, tool_name, arguments, level):
        raise RuntimeError("approval handler crashed unexpectedly")


class RunStateCheckingRouter:
    """On every call, asserts a TaskRun already exists in RUNNING state
    (started_at set, completed_at still None) for the task currently being
    run — proving the TaskRun is created, with started_at set, BEFORE the
    model call happens, not after. Records the observed run for the test
    to inspect further."""

    def __init__(self, task_manager: TaskManager, outcomes: list):
        self.task_manager = task_manager
        self._outcomes = list(outcomes)
        self.observed_running_runs: list = []

    async def _next(self, messages):
        tasks = self.task_manager.list_tasks()
        assert len(tasks) == 1
        task = tasks[0]
        runs = self.task_manager.get_task_runs(task.id)
        current = runs[-1]
        assert current.status == TaskRunStatus.RUNNING
        assert current.started_at is not None
        assert current.completed_at is None
        self.observed_running_runs.append(current)

        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def generate(self, messages):
        return await self._next(messages)

    async def generate_with_tools(self, messages, tools):
        return await self._next(messages)


class CrashingRouter:
    """Raises a bare (non-ProviderError) exception directly from the model
    call itself — distinct from a crash during tool execution/approval.
    Exercises the 'mark the active TaskRun FAILED' path inside the
    iteration loop, not just the Task-level wrapper in run()."""

    async def generate(self, messages):
        raise RuntimeError("router itself crashed")

    async def generate_with_tools(self, messages, tools):
        raise RuntimeError("router itself crashed")


@pytest.fixture
def task_manager(tmp_path):
    return TaskManager(TaskRepository(db_path=tmp_path / "orchestrator_test.db"))


# --- Successful run -----------------------------------------------------------


async def test_successful_run_persists_task_as_completed(task_manager):
    router = ScriptedRouter([_response(text="Hello!")])
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler(), task_manager=task_manager)

    result = await orch.run("hi")

    assert result.status == OrchestratorRunStatus.COMPLETED
    tasks = task_manager.list_tasks()
    assert len(tasks) == 1
    persisted = tasks[0]
    assert persisted.status == TaskStatus.COMPLETED
    assert persisted.result == "Hello!"
    assert persisted.started_at is not None
    assert persisted.completed_at is not None

    runs = task_manager.get_task_runs(persisted.id)
    assert len(runs) == 1
    assert runs[0].status == TaskRunStatus.COMPLETED
    assert runs[0].provider == "fake"
    assert runs[0].model == "fake-model"
    assert runs[0].completed_at is not None


# --- TaskRun lifecycle: RUNNING during the call, then terminal ------------------


async def test_task_run_exists_in_running_state_during_the_model_call(task_manager):
    """Proves requirements 1/2/7 of the TaskRun lifecycle correction: the
    TaskRun is created (status=RUNNING, started_at set) BEFORE the model
    call, not after it succeeds — and the SAME run is updated in place
    afterward, never duplicated."""
    router = RunStateCheckingRouter(task_manager, [_response(text="done")])
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler(), task_manager=task_manager)

    before = datetime.now(timezone.utc)
    result = await orch.run("hi")
    after = datetime.now(timezone.utc)

    assert result.status == OrchestratorRunStatus.COMPLETED
    assert len(router.observed_running_runs) == 1
    observed = router.observed_running_runs[0]
    # started_at was already set, and set before this assertion ran inside
    # the router call — i.e. strictly before the model call completed.
    assert before <= observed.started_at <= after

    persisted = task_manager.list_tasks()[0]
    runs = task_manager.get_task_runs(persisted.id)
    assert len(runs) == 1  # the RUNNING run became COMPLETED, not a second row
    assert runs[0].id == observed.id
    assert runs[0].status == TaskRunStatus.COMPLETED
    assert runs[0].completed_at is not None


# --- Tool round trip persists tool result --------------------------------------


async def test_tool_round_trip_persists_tool_result(task_manager):
    call = ToolCall.new("calculator", {"a": 3, "b": 4})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="7")])
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    orch = Orchestrator(router, registry, AutoApproveHandler(), task_manager=task_manager)

    result = await orch.run("3+4?")

    assert result.status == OrchestratorRunStatus.COMPLETED
    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.COMPLETED

    tool_results = task_manager.get_tool_results(persisted.id)
    assert len(tool_results) == 1
    assert tool_results[0].tool_call_id == call.id
    assert tool_results[0].result == 7.0

    # Exactly one TaskRun for the tool-requesting iteration, one for the
    # final-text iteration — both COMPLETED, since the tool call happening
    # inside an iteration doesn't affect that iteration's own run status.
    runs = task_manager.get_task_runs(persisted.id)
    assert [r.iteration for r in runs] == [1, 2]
    assert all(r.status == TaskRunStatus.COMPLETED for r in runs)


# --- Provider error -> FAILED ------------------------------------------------


async def test_provider_error_persists_task_and_task_run_as_failed(task_manager):
    router = ScriptedRouter([ProviderError(ProviderErrorType.NETWORK, "down", "fake")])
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler(), task_manager=task_manager)

    result = await orch.run("hi")

    assert result.status == OrchestratorRunStatus.FAILED
    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.FAILED
    assert persisted.error is not None and "down" in persisted.error

    runs = task_manager.get_task_runs(persisted.id)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == TaskRunStatus.FAILED
    assert run.completed_at is not None
    assert run.error is not None and "down" in run.error


# --- Tool failure handled by orchestrator does NOT fail the task ---------------


async def test_tool_failure_handled_by_orchestrator_does_not_fail_the_task(task_manager):
    """A tool raising an exception becomes a CONTROLLED ToolResult failure,
    not an orchestration-level failure — the task still completes since
    the orchestrator goes on to produce a final answer."""
    call = ToolCall.new("raising_tool", {"a": 1, "b": 1})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="handled it")])
    registry = ToolRegistry()
    registry.register(RaisingTool())
    orch = Orchestrator(router, registry, AutoApproveHandler(), task_manager=task_manager)

    result = await orch.run("do something that fails")

    assert result.status == OrchestratorRunStatus.COMPLETED
    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.COMPLETED  # NOT failed

    tool_results = task_manager.get_tool_results(persisted.id)
    assert tool_results[0].success is False
    assert "tool boom" in tool_results[0].error

    # The iteration that requested the failing tool still has a COMPLETED
    # TaskRun — the model call itself succeeded; only the tool failed, and
    # that must not retroactively flip this run's status.
    runs = task_manager.get_task_runs(persisted.id)
    assert all(r.status == TaskRunStatus.COMPLETED for r in runs)


# --- MAX_TOOL_CALLS / MAX_ITERATIONS map to FAILED -----------------------------


async def test_max_tool_calls_reached_persists_task_as_failed(task_manager):
    calls = [ToolCall.new("calculator", {"a": i, "b": i}) for i in range(5)]
    router = ScriptedRouter([_response(tool_calls=calls)])
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    orch = Orchestrator(
        router, registry, AutoApproveHandler(), task_manager=task_manager, max_tool_calls=2
    )

    result = await orch.run("spam tools")

    assert result.status == OrchestratorRunStatus.MAX_TOOL_CALLS_REACHED
    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.FAILED


async def test_max_iterations_reached_persists_task_as_failed(task_manager):
    def looping_response():
        call = ToolCall.new("calculator", {"a": 1, "b": 1})
        return _response(tool_calls=[call])

    router = ScriptedRouter([looping_response() for _ in range(5)])
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    orch = Orchestrator(
        router,
        registry,
        AutoApproveHandler(),
        task_manager=task_manager,
        max_iterations=2,
        max_tool_calls=100,
    )

    result = await orch.run("loop forever")

    assert result.status == OrchestratorRunStatus.MAX_ITERATIONS_REACHED
    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.FAILED


# --- Unexpected exception marks FAILED, then re-raises unchanged --------------


async def test_unexpected_exception_during_tool_approval_marks_task_failed_then_reraises(
    task_manager,
):
    """Crash happens AFTER the model call already succeeded (TaskRun
    already COMPLETED) — during tool approval. Only the Task-level
    wrapper in run() has anything left to mark FAILED; the TaskRun for
    this iteration correctly stays COMPLETED, since the model round-trip
    itself did succeed. See the test below for the TaskRun-level crash
    path (an exception during the model call itself, while its TaskRun is
    still RUNNING)."""
    call = ToolCall.new("calculator", {"a": 1, "b": 1})
    router = ScriptedRouter([_response(tool_calls=[call])])

    class ConfirmCalculator(Tool):
        name = "calculator"
        description = "Adds two numbers, requires confirmation"
        args_model = NumberArgs
        permission_level = PermissionLevel.CONFIRM

        async def execute(self, args: NumberArgs) -> float:
            return args.a + args.b

    registry = ToolRegistry()
    registry.register(ConfirmCalculator())
    orch = Orchestrator(router, registry, ExplodingApprovalHandler(), task_manager=task_manager)

    with pytest.raises(RuntimeError, match="approval handler crashed unexpectedly"):
        await orch.run("do it")

    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.FAILED
    assert "Unexpected error" in (persisted.error or "")
    assert "approval handler crashed unexpectedly" in (persisted.error or "")

    # The TaskRun for this iteration's model call isn't retroactively
    # touched — it already completed successfully before the crash.
    runs = task_manager.get_task_runs(persisted.id)
    assert len(runs) == 1
    assert runs[0].status == TaskRunStatus.COMPLETED


async def test_unexpected_exception_during_model_call_marks_the_active_task_run_failed(
    task_manager,
):
    """Crash happens INSIDE the model call itself, while its TaskRun is
    still RUNNING — the active TaskRun must be marked FAILED (not left
    RUNNING forever), in addition to the Task-level FAILED marking."""
    router = CrashingRouter()
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler(), task_manager=task_manager)

    with pytest.raises(RuntimeError, match="router itself crashed"):
        await orch.run("hi")

    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.FAILED
    assert "router itself crashed" in (persisted.error or "")

    runs = task_manager.get_task_runs(persisted.id)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == TaskRunStatus.FAILED
    assert run.completed_at is not None
    assert "router itself crashed" in (run.error or "")


# --- No task_manager => no persistence at all, unchanged behavior -------------


async def test_orchestrator_without_task_manager_touches_no_database():
    router = ScriptedRouter([_response(text="no persistence here")])
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler())

    result = await orch.run("hi")

    assert result.status == OrchestratorRunStatus.COMPLETED
    assert result.final_response == "no persistence here"
    assert orch.task_manager is None

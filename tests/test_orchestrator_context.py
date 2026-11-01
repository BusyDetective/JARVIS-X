"""Integration tests: Orchestrator + ContextManager (and, via it, MemoryManager).

Mirrors the ScriptedRouter test-double pattern from
test_orchestrator_persistence.py. Proves:
  - Orchestrator behaves exactly as before with no context_manager.
  - With one, the SEED messages come from a built ContextBundle, while the
    tool-call loop and TaskRun persistence remain fully functional.
  - Memory, selected via an injected MemoryManager, reaches the model
    call through the context bundle.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from app.context.manager import ContextManager
from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as OrchestratorRunStatus
from app.memory.manager import MemoryManager
from app.memory.models import MemoryType
from app.memory.repository import MemoryRepository
from app.providers.schemas import ModelResponse, ToolCall
from app.security.approval import AutoApproveHandler
from app.security.permissions import PermissionLevel
from app.tasks.manager import TaskManager
from app.tasks.models import TaskStatus
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


@pytest.fixture
def memory_manager(tmp_path):
    return MemoryManager(MemoryRepository(db_path=tmp_path / "ctx_orch_memory.db"))


@pytest.fixture
def task_manager(tmp_path):
    return TaskManager(TaskRepository(db_path=tmp_path / "ctx_orch_tasks.db"))


# --- No context_manager => unchanged behavior --------------------------------


async def test_orchestrator_without_context_manager_is_unchanged():
    router = ScriptedRouter([_response(text="Hello!")])
    orch = Orchestrator(router, ToolRegistry(), AutoApproveHandler())

    result = await orch.run("hi")

    assert orch.context_manager is None
    assert result.status == OrchestratorRunStatus.COMPLETED
    assert result.final_response == "Hello!"
    sent = router.calls[0]
    assert [m.role for m in sent] == ["user"]
    assert sent[0].content == "hi"


# --- With context_manager: seed messages come from the bundle -----------------


async def test_orchestrator_with_context_manager_builds_seed_from_bundle():
    router = ScriptedRouter([_response(text="ok")])
    orch = Orchestrator(
        router,
        ToolRegistry(),
        AutoApproveHandler(),
        system_prompt="You are JARVIS-X.",
        context_manager=ContextManager(),
    )

    result = await orch.run("what's 2+2?")

    assert result.status == OrchestratorRunStatus.COMPLETED
    sent = router.calls[0]
    assert [m.role for m in sent] == ["system", "user"]
    assert sent[0].content == "You are JARVIS-X."
    assert sent[1].content == "what's 2+2?"


# --- Tool loop + TaskRun persistence remain intact with a context_manager -----


async def test_orchestrator_with_context_manager_preserves_tool_loop_and_persistence(
    task_manager,
):
    call = ToolCall.new("calculator", {"a": 3, "b": 4})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="7")])
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    orch = Orchestrator(
        router,
        registry,
        AutoApproveHandler(),
        context_manager=ContextManager(),
        task_manager=task_manager,
    )

    result = await orch.run("3+4?")

    assert result.status == OrchestratorRunStatus.COMPLETED
    assert result.final_response == "7"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].result == 7.0

    persisted = task_manager.list_tasks()[0]
    assert persisted.status == TaskStatus.COMPLETED
    tool_results = task_manager.get_tool_results(persisted.id)
    assert len(tool_results) == 1
    assert tool_results[0].tool_call_id == call.id


# --- Memory, via ContextManager, reaches the model call ------------------------


async def test_orchestrator_with_context_manager_surfaces_relevant_memory(memory_manager):
    memory_manager.create_memory(
        "the user prefers concise answers", MemoryType.PREFERENCE, importance=0.9
    )
    router = ScriptedRouter([_response(text="ok")])
    orch = Orchestrator(
        router,
        ToolRegistry(),
        AutoApproveHandler(),
        system_prompt="You are JARVIS-X.",
        context_manager=ContextManager(memory_manager=memory_manager),
    )

    await orch.run("what does the user prefer for answers?")

    sent = router.calls[0]
    memory_messages = [m for m in sent if m.content and m.content.startswith("[Memory] ")]
    assert len(memory_messages) == 1
    assert "concise answers" in memory_messages[0].content
    assert memory_messages[0].role == "system"


async def test_orchestrator_context_manager_without_relevant_memory_has_no_memory_message(
    memory_manager,
):
    memory_manager.create_memory("a fact about volcanoes", MemoryType.FACT, importance=0.9)
    router = ScriptedRouter([_response(text="ok")])
    orch = Orchestrator(
        router,
        ToolRegistry(),
        AutoApproveHandler(),
        context_manager=ContextManager(memory_manager=memory_manager),
    )

    await orch.run("zzz_completely_unrelated_zzz")

    sent = router.calls[0]
    memory_messages = [m for m in sent if m.content and m.content.startswith("[Memory] ")]
    assert memory_messages == []

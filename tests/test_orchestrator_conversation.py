"""Orchestrator + ConversationManager integration (temporary SQLite)."""
from __future__ import annotations

import uuid

import pytest

from app.context.manager import ContextManager
from app.core.orchestrator import Orchestrator
from app.core.orchestrator import TaskStatus as RunStatus
from app.providers.schemas import ProviderError, ProviderErrorType, ToolCall
from app.security.approval import AutoApproveHandler
from app.sessions.manager import SessionInactiveError, build_session_services
from app.sessions.models import MessageRole
from app.sessions.repository import ConversationNotFoundError
from app.tasks.manager import TaskManager
from app.tasks.models import TaskRunStatus, TaskStatus
from app.tasks.repository import TaskRepository
from app.tools.registry import ToolRegistry
from tests.test_orchestrator_persistence import (
    CalculatorTool,
    RaisingTool,
    ScriptedRouter,
    _response,
)


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "t.db"
    sm, cm = build_session_services(db)
    conv = sm.create_conversation(sm.create_session().id)
    tm = TaskManager(TaskRepository(db_path=db))
    return sm, cm, conv, tm


def _registry():
    r = ToolRegistry()
    r.register(CalculatorTool())
    r.register(RaisingTool())
    return r


def _orch(router, cm, tm=None, registry=None, **kw):
    return Orchestrator(
        router, registry or ToolRegistry(), AutoApproveHandler(),
        task_manager=tm, conversation_manager=cm, **kw,
    )


def _shape(cm, conv):
    return [(m.role.value, m.content) for m in cm.get_history(conv.id)]


async def test_works_without_conversation_manager():
    router = ScriptedRouter([_response(text="hi")])
    result = await Orchestrator(router, ToolRegistry(), AutoApproveHandler()).run("yo")
    assert result.status == RunStatus.COMPLETED


async def test_conversation_id_without_manager_is_rejected():
    orch = Orchestrator(ScriptedRouter([]), ToolRegistry(), AutoApproveHandler())
    with pytest.raises(ValueError):
        await orch.run("x", conversation_id=uuid.uuid4())


async def test_manager_requires_conversation_id(env):
    _, cm, _, _ = env
    with pytest.raises(ValueError):
        await _orch(ScriptedRouter([]), cm).run("x")


async def test_unknown_conversation_fails_fast_without_creating_task(env):
    _, cm, _, tm = env
    with pytest.raises(ConversationNotFoundError):
        await _orch(ScriptedRouter([]), cm, tm).run("x", conversation_id=uuid.uuid4())
    assert tm.list_tasks() == []


async def test_inactive_session_fails_fast(env):
    sm, cm, conv, tm = env
    sm.deactivate_session(conv.session_id)
    with pytest.raises(SessionInactiveError):
        await _orch(ScriptedRouter([]), cm, tm).run("x", conversation_id=conv.id)
    assert tm.list_tasks() == []


async def test_user_and_assistant_persisted_once_and_session_titled(env):
    sm, cm, conv, tm = env
    router = ScriptedRouter([_response(text="Hello!")])
    result = await _orch(router, cm, tm).run("hi there", conversation_id=conv.id)
    assert result.status == RunStatus.COMPLETED
    assert _shape(cm, conv) == [("user", "hi there"), ("assistant", "Hello!")]
    assert sm.get_session(conv.session_id).title == "hi there"
    # Model saw the user message exactly once.
    sent = router.calls[0]
    assert [m.content for m in sent].count("hi there") == 1


async def test_messages_link_to_task_and_record_provider(env):
    _, cm, conv, tm = env
    await _orch(ScriptedRouter([_response(text="ok")]), cm, tm).run("q", conversation_id=conv.id)
    task = tm.list_tasks()[0]
    user, assistant = cm.get_history(conv.id)
    assert user.metadata["task_id"] == str(task.id) == assistant.metadata["task_id"]
    assert assistant.metadata["provider"] == "fake" and assistant.metadata["model"] == "fake-model"


async def test_history_is_supplied_on_following_runs_without_duplication(env):
    _, cm, conv, _ = env
    router = ScriptedRouter([_response(text="a1"), _response(text="a2")])
    orch = _orch(router, cm)
    await orch.run("first", conversation_id=conv.id)
    await orch.run("second", conversation_id=conv.id)
    contents = [m.content for m in router.calls[1]]
    assert [c for c in contents if c in ("first", "a1", "second")] == ["first", "a1", "second"]
    assert _shape(cm, conv) == [("user", "first"), ("assistant", "a1"),
                                ("user", "second"), ("assistant", "a2")]


async def test_tool_loop_persisted_in_order(env):
    _, cm, conv, tm = env
    call = ToolCall(id="call_1", name="calculator", arguments={"a": 3, "b": 4})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="7")])
    result = await _orch(router, cm, tm, _registry()).run("3+4?", conversation_id=conv.id)
    assert result.status == RunStatus.COMPLETED
    hist = cm.get_history(conv.id)
    assert [m.role for m in hist] == [MessageRole.USER, MessageRole.ASSISTANT,
                                      MessageRole.TOOL, MessageRole.ASSISTANT]
    assert hist[1].content == "" and hist[1].metadata["tool_calls"][0]["id"] == "call_1"
    assert hist[2].metadata["tool_call_id"] == "call_1"
    assert hist[2].metadata["tool_name"] == "calculator" and hist[2].metadata["success"] is True
    assert hist[3].content == "7"
    # TaskRun / ToolResult persistence unchanged.
    task = tm.list_tasks()[0]
    assert task.status == TaskStatus.COMPLETED
    assert len(tm.get_tool_results(task.id)) == 1
    assert [r.status for r in tm.get_task_runs(task.id)] == [TaskRunStatus.COMPLETED] * 2


async def test_multiple_tool_calls_preserve_order(env):
    _, cm, conv, _ = env
    calls = [ToolCall(id=f"c{i}", name="calculator", arguments={"a": i, "b": 1}) for i in range(3)]
    router = ScriptedRouter([_response(tool_calls=calls), _response(text="done")])
    await _orch(router, cm, registry=_registry()).run("go", conversation_id=conv.id)
    hist = cm.get_history(conv.id)
    assert [m.role.value for m in hist] == ["user", "assistant", "tool", "tool", "tool", "assistant"]
    assert [m.metadata["tool_call_id"] for m in hist[2:5]] == ["c0", "c1", "c2"]
    assert [m.sequence for m in hist] == [1, 2, 3, 4, 5, 6]


async def test_tool_exchange_from_earlier_run_is_replayed_with_linkage(env):
    _, cm, conv, _ = env
    call = ToolCall(id="call_1", name="calculator", arguments={"a": 1, "b": 2})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="3"), _response(text="ok")])
    orch = _orch(router, cm, registry=_registry())
    await orch.run("1+2?", conversation_id=conv.id)
    await orch.run("thanks", conversation_id=conv.id)
    replay = router.calls[2]
    roles = [m.role for m in replay]
    assert roles.index("tool") == roles.index("assistant") + 1
    tool_msg = replay[roles.index("tool")]
    assert tool_msg.tool_call_id == "call_1" and tool_msg.name == "calculator"
    assert replay[roles.index("assistant")].tool_calls[0].id == "call_1"


async def test_tool_failure_is_recorded_as_failed_tool_message(env):
    _, cm, conv, tm = env
    call = ToolCall(id="c1", name="raising_tool", arguments={"a": 1, "b": 2})
    router = ScriptedRouter([_response(tool_calls=[call]), _response(text="it failed")])
    result = await _orch(router, cm, tm, _registry()).run("try", conversation_id=conv.id)
    assert result.status == RunStatus.COMPLETED
    hist = cm.get_history(conv.id)
    assert [m.role.value for m in hist] == ["user", "assistant", "tool", "assistant"]
    assert hist[2].metadata["success"] is False and "tool boom" in hist[2].content
    assert hist[3].content == "it failed"


async def test_provider_failure_keeps_user_message_and_fabricates_nothing(env):
    _, cm, conv, tm = env
    router = ScriptedRouter([ProviderError(ProviderErrorType.NETWORK, "down", "fake")])
    result = await _orch(router, cm, tm).run("hello?", conversation_id=conv.id)
    assert result.status == RunStatus.FAILED
    assert _shape(cm, conv) == [("user", "hello?")]
    task = tm.list_tasks()[0]
    assert task.status == TaskStatus.FAILED  # TaskRun semantics unchanged
    assert tm.get_task_runs(task.id)[0].status == TaskRunStatus.FAILED


async def test_provider_failure_after_tool_keeps_genuine_events(env):
    _, cm, conv, _ = env
    call = ToolCall(id="c1", name="calculator", arguments={"a": 1, "b": 1})
    router = ScriptedRouter([_response(tool_calls=[call]),
                             ProviderError(ProviderErrorType.NETWORK, "down", "fake")])
    result = await _orch(router, cm, registry=_registry()).run("x", conversation_id=conv.id)
    assert result.status == RunStatus.FAILED
    assert [m.role.value for m in cm.get_history(conv.id)] == ["user", "assistant", "tool"]


async def test_next_run_after_interrupted_exchange_sends_valid_history(env):
    _, cm, conv, _ = env
    call = ToolCall(id="c1", name="calculator", arguments={"a": 1, "b": 1})
    router = ScriptedRouter([_response(tool_calls=[call]),
                             ProviderError(ProviderErrorType.NETWORK, "down", "fake"),
                             _response(text="recovered")])
    orch = _orch(router, cm, registry=_registry())
    await orch.run("x", conversation_id=conv.id)
    result = await orch.run("again", conversation_id=conv.id)
    assert result.status == RunStatus.COMPLETED
    roles = [m.role for m in router.calls[2]]
    assert roles.count("tool") == 1 and roles.index("tool") == roles.index("assistant") + 1


async def test_empty_final_response_persists_nothing_extra(env):
    _, cm, conv, _ = env
    await _orch(ScriptedRouter([_response(text=None)]), cm).run("hm", conversation_id=conv.id)
    assert _shape(cm, conv) == [("user", "hm")]


async def test_system_prompt_is_not_persisted(env):
    _, cm, conv, _ = env
    await _orch(ScriptedRouter([_response(text="ok")]), cm).run("q", conversation_id=conv.id)
    assert all(m.role != MessageRole.SYSTEM for m in cm.get_history(conv.id))


async def test_supplied_context_manager_is_wired_to_conversation_manager(env):
    _, cm, conv, _ = env
    ctx = ContextManager()
    router = ScriptedRouter([_response(text="ok")])
    await _orch(router, cm, context_manager=ctx).run("q", conversation_id=conv.id)
    assert ctx.conversation_manager is cm
    assert "q" in [m.content for m in router.calls[0]]


def test_mismatched_conversation_managers_rejected(env, tmp_path):
    _, cm, _, _ = env
    _, other = build_session_services(tmp_path / "other.db")
    with pytest.raises(ValueError):
        _orch(ScriptedRouter([]), cm, context_manager=ContextManager(conversation_manager=other))

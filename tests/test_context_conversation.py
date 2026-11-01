"""ContextManager consuming persisted conversation history (via ConversationManager)."""
from __future__ import annotations

import pytest

from app.context.manager import ContextManager, context_bundle_to_messages
from app.context.models import ContextItem, ContextSource
from app.memory.manager import MemoryManager
from app.memory.models import MemoryType
from app.memory.repository import MemoryRepository
from app.providers.schemas import ToolCall
from app.sessions.manager import build_session_services


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "t.db"
    sm, cm = build_session_services(db)
    conv = sm.create_conversation(sm.create_session().id)
    return db, cm, conv


def _texts(msgs):
    return [m.content for m in msgs]


def test_history_reaches_context_in_order(env):
    _, cm, conv = env
    for i in range(3):
        cm.append_user_message(conv.id, f"u{i}")
        cm.append_assistant_message(conv.id, f"a{i}")
    bundle = ContextManager(conversation_manager=cm).build_context(
        system_instructions="sys", conversation_id=conv.id
    )
    msgs = context_bundle_to_messages(bundle)
    assert _texts(msgs) == ["sys", "u0", "a0", "u1", "a1", "u2", "a2"]
    assert [m.role for m in msgs][:3] == ["system", "user", "assistant"]


def test_limit_respected_keeps_most_recent_oldest_first(env):
    _, cm, conv = env
    for i in range(10):
        cm.append_user_message(conv.id, f"m{i}")
    bundle = ContextManager(conversation_manager=cm, max_conversation_items=4).build_context(
        conversation_id=conv.id
    )
    assert _texts(context_bundle_to_messages(bundle)) == ["m6", "m7", "m8", "m9"]


def test_identical_turns_are_not_deduplicated(env):
    _, cm, conv = env
    cm.append_user_message(conv.id, "ok")
    cm.append_assistant_message(conv.id, "sure")
    cm.append_user_message(conv.id, "ok")
    msgs = context_bundle_to_messages(
        ContextManager(conversation_manager=cm).build_context(conversation_id=conv.id)
    )
    assert _texts(msgs) == ["ok", "sure", "ok"]


def test_conversation_id_requires_manager(env):
    _, _, conv = env
    with pytest.raises(ValueError):
        ContextManager().build_context(conversation_id=conv.id)


def test_tool_exchange_roundtrips_with_linkage(env):
    _, cm, conv = env
    tc = ToolCall(id="c1", name="calc", arguments={"a": 1}, provider_call_id="p1")
    cm.append_user_message(conv.id, "add")
    cm.append_assistant_message(conv.id, None, tool_calls=[tc])
    cm.append_tool_message(conv.id, '{"result": 2}', "c1", "calc")
    cm.append_assistant_message(conv.id, "it is 2")
    msgs = context_bundle_to_messages(
        ContextManager(conversation_manager=cm).build_context(conversation_id=conv.id)
    )
    assert [m.role for m in msgs] == ["user", "assistant", "tool", "assistant"]
    assert msgs[1].content is None and msgs[1].tool_calls[0].id == "c1"
    assert msgs[1].tool_calls[0].provider_call_id == "p1"
    assert msgs[2].tool_call_id == "c1" and msgs[2].name == "calc"


def test_orphan_tool_message_from_window_cut_is_dropped(env):
    _, cm, conv = env
    tc = ToolCall(id="c1", name="calc", arguments={})
    cm.append_user_message(conv.id, "q")
    cm.append_assistant_message(conv.id, None, tool_calls=[tc])
    cm.append_tool_message(conv.id, "r", "c1", "calc")
    cm.append_assistant_message(conv.id, "final")
    msgs = context_bundle_to_messages(
        ContextManager(conversation_manager=cm, max_conversation_items=2).build_context(
            conversation_id=conv.id
        )
    )
    assert [m.role for m in msgs] == ["assistant"] and msgs[0].content == "final"


def test_unanswered_tool_calls_are_stripped(env):
    _, cm, conv = env
    calls = [ToolCall(id="c1", name="calc", arguments={}), ToolCall(id="c2", name="calc", arguments={})]
    cm.append_user_message(conv.id, "q")
    cm.append_assistant_message(conv.id, None, tool_calls=calls)
    cm.append_tool_message(conv.id, "r1", "c1", "calc")  # c2 never ran
    msgs = context_bundle_to_messages(
        ContextManager(conversation_manager=cm).build_context(conversation_id=conv.id)
    )
    assert [m.role for m in msgs] == ["user", "assistant", "tool"]
    assert [tc.id for tc in msgs[1].tool_calls] == ["c1"]


def test_fully_unanswered_empty_assistant_turn_is_dropped(env):
    _, cm, conv = env
    cm.append_user_message(conv.id, "q")
    cm.append_assistant_message(conv.id, None, tool_calls=[ToolCall(id="c1", name="x", arguments={})])
    msgs = context_bundle_to_messages(
        ContextManager(conversation_manager=cm).build_context(conversation_id=conv.id)
    )
    assert [m.role for m in msgs] == ["user"]


def test_memory_task_and_tool_context_still_work_and_stay_distinct(env):
    db, cm, conv = env
    mm = MemoryManager(MemoryRepository(db))
    mm.create_memory("user likes green tea", MemoryType.PREFERENCE, importance=0.9)
    cm.append_user_message(conv.id, "what tea do I like?")
    ctx = ContextManager(memory_manager=mm, conversation_manager=cm)
    bundle = ctx.build_context(
        system_instructions="sys",
        conversation_id=conv.id,
        task_items=[ContextItem(content="task goal", source=ContextSource.TASK)],
        tool_items=[ContextItem(content="tool out", source=ContextSource.TOOL)],
        memory_query="tea",
    )
    by_source = {}
    for item in bundle.items:
        by_source.setdefault(item.source, []).append(item.content)
    assert by_source[ContextSource.USER] == ["what tea do I like?"]
    assert by_source[ContextSource.TASK] == ["task goal"]
    assert by_source[ContextSource.TOOL] == ["tool out"]
    assert any("green tea" in c for c in by_source[ContextSource.MEMORY])
    # Plain (non-linked) TOOL context keeps the old labelled-system rendering.
    msgs = context_bundle_to_messages(bundle)
    assert not any(m.role == "tool" for m in msgs)

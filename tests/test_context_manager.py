from __future__ import annotations

import inspect

import pytest

from app.context.manager import ContextManager, context_bundle_to_messages
from app.context.models import ContextBundle, ContextItem, ContextPriority, ContextSource
from app.memory.manager import MemoryManager
from app.memory.models import MemoryType
from app.memory.repository import MemoryRepository


def _item(content, source=ContextSource.USER, priority=ContextPriority.NORMAL):
    return ContextItem(content=content, source=source, priority=priority)


@pytest.fixture
def memory_manager(tmp_path):
    return MemoryManager(MemoryRepository(db_path=tmp_path / "context_test.db"))


# --- Basic assembly / ordering -----------------------------------------------


def test_build_context_includes_system_first_as_critical():
    cm = ContextManager()
    bundle = cm.build_context(system_instructions="be helpful", conversation_items=[_item("hi")])
    assert bundle.items[0].source == ContextSource.SYSTEM
    assert bundle.items[0].priority == ContextPriority.CRITICAL
    assert bundle.items[0].content == "be helpful"


def test_build_context_with_no_system_instructions_has_no_system_item():
    cm = ContextManager()
    bundle = cm.build_context(conversation_items=[_item("hi")])
    assert bundle.items_from(ContextSource.SYSTEM) == []


def test_build_context_preserves_block_order_system_conversation_task_tool():
    cm = ContextManager()
    bundle = cm.build_context(
        system_instructions="sys",
        conversation_items=[_item("conv")],
        task_items=[_item("task", source=ContextSource.TASK)],
        tool_items=[_item("tool", source=ContextSource.TOOL)],
    )
    sources = [item.source for item in bundle.items]
    assert sources == [
        ContextSource.SYSTEM,
        ContextSource.USER,
        ContextSource.TASK,
        ContextSource.TOOL,
    ]


def test_build_context_preserves_within_block_ordering():
    cm = ContextManager()
    items = [_item(f"turn-{i}") for i in range(5)]
    bundle = cm.build_context(conversation_items=items)
    assert [i.content for i in bundle.items] == [f"turn-{i}" for i in range(5)]


# --- Limits -------------------------------------------------------------------


def test_build_context_respects_conversation_limit_keeping_most_recent():
    cm = ContextManager(max_conversation_items=2)
    items = [_item(f"turn-{i}") for i in range(5)]
    bundle = cm.build_context(conversation_items=items)
    assert [i.content for i in bundle.items] == ["turn-3", "turn-4"]


def test_build_context_respects_task_context_limit():
    cm = ContextManager(max_task_context_items=1)
    items = [_item(f"task-{i}", source=ContextSource.TASK) for i in range(3)]
    bundle = cm.build_context(task_items=items)
    assert [i.content for i in bundle.items] == ["task-2"]


def test_build_context_respects_memory_limit(memory_manager):
    for i in range(5):
        memory_manager.create_memory(
            f"remembered fact number {i} about python", MemoryType.FACT, importance=0.9
        )
    cm = ContextManager(memory_manager=memory_manager, max_memory_items=2)
    bundle = cm.build_context(memory_query="python fact")
    assert len(bundle.items_from(ContextSource.MEMORY)) == 2


def test_build_context_respects_total_limit_and_preserves_system():
    cm = ContextManager(max_total_items=3)
    items = [_item(f"turn-{i}") for i in range(10)]
    bundle = cm.build_context(system_instructions="sys", conversation_items=items)
    assert len(bundle.items) == 3
    assert bundle.items[0].source == ContextSource.SYSTEM


def test_trim_drops_low_priority_items_before_higher_priority_ones():
    cm = ContextManager(max_total_items=2)
    low = ContextItem(content="low", source=ContextSource.MEMORY, priority=ContextPriority.LOW)
    high = ContextItem(content="high", source=ContextSource.USER, priority=ContextPriority.HIGH)
    normal = ContextItem(content="normal", source=ContextSource.USER, priority=ContextPriority.NORMAL)

    trimmed = cm._trim_to_total([low, high, normal])

    assert len(trimmed) == 2
    assert low not in trimmed
    assert high in trimmed
    assert normal in trimmed


def test_trim_leaves_items_unchanged_when_under_the_limit():
    cm = ContextManager(max_total_items=10)
    items = [_item(f"turn-{i}") for i in range(3)]
    trimmed = cm._trim_to_total(items)
    assert trimmed == items


# --- Deduplication --------------------------------------------------------------


def test_build_context_deduplicates_identical_source_and_content():
    cm = ContextManager()
    dup_a = _item("same content")
    dup_b = _item("same content")
    distinct = _item("different content")
    bundle = cm.build_context(conversation_items=[dup_a, dup_b, distinct])
    assert len(bundle.items) == 2


def test_build_context_does_not_deduplicate_same_content_different_source():
    cm = ContextManager()
    user_item = _item("shared text", source=ContextSource.USER)
    task_item = _item("shared text", source=ContextSource.TASK)
    bundle = cm.build_context(conversation_items=[user_item], task_items=[task_item])
    assert len(bundle.items) == 2


# --- Tool items stay structurally distinct ---------------------------------------


def test_tool_items_remain_tagged_as_tool_source():
    cm = ContextManager()
    bundle = cm.build_context(
        system_instructions="sys",
        tool_items=[_item("tool output here", source=ContextSource.TOOL)],
    )
    tool_items = bundle.items_from(ContextSource.TOOL)
    assert len(tool_items) == 1
    assert tool_items[0].content == "tool output here"


# --- Memory integration -----------------------------------------------------------


def test_build_context_retrieves_relevant_memories_through_memory_manager(memory_manager):
    memory_manager.create_memory(
        "the user prefers dark mode", MemoryType.PREFERENCE, importance=0.9
    )
    memory_manager.create_memory(
        "completely unrelated fact about volcanoes", MemoryType.FACT, importance=0.9
    )
    cm = ContextManager(memory_manager=memory_manager)

    bundle = cm.build_context(memory_query="what are the user's preferences for dark mode?")

    memory_items = bundle.items_from(ContextSource.MEMORY)
    assert any("dark mode" in item.content for item in memory_items)


def test_build_context_with_no_memory_manager_has_no_memory_items():
    cm = ContextManager()
    bundle = cm.build_context(memory_query="anything")
    assert bundle.items_from(ContextSource.MEMORY) == []


def test_build_context_with_memory_manager_but_no_query_has_no_memory_items(memory_manager):
    memory_manager.create_memory("a fact", MemoryType.FACT, importance=0.9)
    cm = ContextManager(memory_manager=memory_manager)
    bundle = cm.build_context()
    assert bundle.items_from(ContextSource.MEMORY) == []


def test_build_context_memory_items_carry_priority_from_importance(memory_manager):
    memory_manager.create_memory("high importance fact", MemoryType.FACT, importance=0.95)
    memory_manager.create_memory("low importance fact", MemoryType.FACT, importance=0.1)
    cm = ContextManager(memory_manager=memory_manager)

    bundle = cm.build_context(memory_query="fact")

    priorities = {item.content: item.priority for item in bundle.items_from(ContextSource.MEMORY)}
    assert priorities["high importance fact"] == ContextPriority.HIGH
    assert priorities["low importance fact"] == ContextPriority.LOW


def test_build_context_marks_selected_memories_as_accessed(memory_manager):
    m = memory_manager.create_memory("a memorable fact", MemoryType.FACT, importance=0.9)
    assert memory_manager.get_memory(m.id).last_accessed_at is None

    cm = ContextManager(memory_manager=memory_manager)
    cm.build_context(memory_query="memorable fact")

    assert memory_manager.get_memory(m.id).last_accessed_at is not None


def test_context_manager_does_not_access_sqlite_directly():
    import app.context.manager as cm_module

    source = inspect.getsource(cm_module)
    assert "sqlite3" not in source
    assert "connection_scope" not in source


# --- context_bundle_to_messages ---------------------------------------------------


def test_context_bundle_to_messages_maps_sources_to_roles():
    bundle = ContextBundle(
        items=[
            ContextItem(content="sys", source=ContextSource.SYSTEM, priority=ContextPriority.CRITICAL),
            ContextItem(content="hi", source=ContextSource.USER),
            ContextItem(content="hello back", source=ContextSource.ASSISTANT),
            ContextItem(content="a fact", source=ContextSource.MEMORY),
        ]
    )
    messages = context_bundle_to_messages(bundle)

    assert [m.role for m in messages] == ["system", "user", "assistant", "system"]
    assert messages[3].content == "[Memory] a fact"
    assert messages[1].content == "hi"  # USER items are not labeled

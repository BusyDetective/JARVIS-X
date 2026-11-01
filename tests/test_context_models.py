from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.context.models import ContextBundle, ContextItem, ContextPriority, ContextSource


def test_valid_context_item():
    item = ContextItem(content="hello", source=ContextSource.USER)
    assert isinstance(item.id, uuid.UUID)
    assert item.content == "hello"
    assert item.source == ContextSource.USER
    assert item.priority == ContextPriority.NORMAL
    assert item.created_at.tzinfo is not None
    assert item.metadata == {}


def test_context_item_rejects_empty_content():
    with pytest.raises(ValidationError):
        ContextItem(content="   ", source=ContextSource.USER)


def test_context_item_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        ContextItem(content="hi", source=ContextSource.USER, created_at=datetime(2026, 1, 1))


def test_context_item_invalid_source_raises():
    with pytest.raises(ValidationError):
        ContextItem(content="x", source="not-a-real-source")


def test_context_source_enum_values():
    assert {s.value for s in ContextSource} == {
        "system",
        "user",
        "assistant",
        "task",
        "memory",
        "tool",
    }


def test_context_priority_enum_values():
    assert {p.value for p in ContextPriority} == {"critical", "high", "normal", "low"}


def test_context_bundle_default_empty():
    bundle = ContextBundle()
    assert bundle.items == []
    assert bundle.created_at.tzinfo is not None


def test_context_bundle_serializes_and_round_trips():
    item = ContextItem(content="x", source=ContextSource.SYSTEM, priority=ContextPriority.CRITICAL)
    bundle = ContextBundle(items=[item])

    dumped = bundle.model_dump(mode="json")
    assert dumped["items"][0]["source"] == "system"
    assert dumped["items"][0]["priority"] == "critical"

    restored = ContextBundle.model_validate(dumped)
    assert restored.items[0].content == "x"
    assert restored.items[0].source == ContextSource.SYSTEM


def test_context_bundle_items_from_filters_by_source():
    sys_item = ContextItem(content="sys", source=ContextSource.SYSTEM)
    user_item = ContextItem(content="usr", source=ContextSource.USER)
    bundle = ContextBundle(items=[sys_item, user_item])
    assert bundle.items_from(ContextSource.USER) == [user_item]
    assert bundle.items_from(ContextSource.TOOL) == []

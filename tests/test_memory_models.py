from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.memory.models import Memory, MemoryType


def test_valid_memory_creation():
    m = Memory(content="the user likes tea", memory_type=MemoryType.PREFERENCE)
    assert isinstance(m.id, uuid.UUID)
    assert m.content == "the user likes tea"
    assert m.memory_type == MemoryType.PREFERENCE
    assert m.importance == 0.5
    assert m.active is True
    assert m.last_accessed_at is None


def test_memory_ids_are_unique():
    a = Memory(content="a", memory_type=MemoryType.FACT)
    b = Memory(content="b", memory_type=MemoryType.FACT)
    assert a.id != b.id


def test_memory_timestamps_are_timezone_aware_utc():
    m = Memory(content="x", memory_type=MemoryType.FACT)
    assert m.created_at.tzinfo is not None
    assert m.updated_at.tzinfo is not None


def test_memory_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        Memory(content="x", memory_type=MemoryType.FACT, last_accessed_at=datetime(2026, 1, 1))


def test_memory_type_enum_serializes_as_plain_string():
    m = Memory(content="x", memory_type=MemoryType.GOAL)
    assert m.model_dump(mode="json")["memory_type"] == "goal"


def test_memory_rejects_empty_content():
    with pytest.raises(ValidationError):
        Memory(content="   ", memory_type=MemoryType.FACT)


@pytest.mark.parametrize("importance", [-0.1, 1.1, 5.0])
def test_memory_rejects_out_of_bounds_importance(importance):
    with pytest.raises(ValidationError):
        Memory(content="x", memory_type=MemoryType.FACT, importance=importance)


@pytest.mark.parametrize("importance", [0.0, 0.5, 1.0])
def test_memory_accepts_bounded_importance(importance):
    m = Memory(content="x", memory_type=MemoryType.FACT, importance=importance)
    assert m.importance == importance


def test_memory_type_values_are_the_expected_small_set():
    assert {t.value for t in MemoryType} == {
        "fact",
        "preference",
        "decision",
        "project",
        "goal",
        "instruction",
    }


def test_memory_invalid_type_raises():
    with pytest.raises(ValidationError):
        Memory(content="x", memory_type="not-a-real-type")


def test_memory_missing_required_fields_raises():
    with pytest.raises(ValidationError):
        Memory()  # content and memory_type are required

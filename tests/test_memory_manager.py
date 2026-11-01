from __future__ import annotations

import uuid

import pytest

from app.memory.manager import MemoryManager, MemoryValidationError, SecretDetectedError
from app.memory.models import MemoryType
from app.memory.repository import MemoryNotFoundError, MemoryRepository


@pytest.fixture
def manager(tmp_path):
    return MemoryManager(MemoryRepository(db_path=tmp_path / "manager_test.db"))


# --- Creation / retrieval ---------------------------------------------------


def test_create_memory(manager):
    m = manager.create_memory("the user prefers Python", MemoryType.PREFERENCE, importance=0.8)
    assert m.content == "the user prefers Python"
    assert m.memory_type == MemoryType.PREFERENCE
    assert m.importance == 0.8


def test_create_memory_persists(manager):
    m = manager.create_memory("a fact", MemoryType.FACT)
    fetched = manager.get_memory(m.id)
    assert fetched.content == "a fact"


def test_get_nonexistent_memory_raises(manager):
    with pytest.raises(MemoryNotFoundError):
        manager.get_memory(uuid.uuid4())


# --- Update / deactivate -----------------------------------------------------


def test_update_memory_preserves_id_and_created_at(manager):
    m = manager.create_memory("original", MemoryType.FACT)
    updated = manager.update_memory(m.id, content="revised")

    assert updated.id == m.id
    assert updated.created_at == m.created_at
    assert updated.content == "revised"
    assert updated.updated_at >= m.updated_at


def test_update_memory_only_changes_given_fields(manager):
    m = manager.create_memory("content", MemoryType.FACT, importance=0.3, metadata={"k": "v"})
    updated = manager.update_memory(m.id, importance=0.9)

    assert updated.content == "content"  # unchanged
    assert updated.importance == 0.9
    assert updated.metadata == {"k": "v"}  # unchanged


def test_deactivate_memory_sets_inactive_and_preserves_record(manager):
    m = manager.create_memory("to deactivate", MemoryType.FACT)
    deactivated = manager.deactivate_memory(m.id)

    assert deactivated.active is False
    assert deactivated.content == "to deactivate"
    assert manager.get_memory(m.id).active is False


def test_deactivated_memory_excluded_from_default_listing(manager):
    m = manager.create_memory("to deactivate", MemoryType.FACT)
    manager.deactivate_memory(m.id)

    assert manager.list_memories() == []
    assert len(manager.list_memories(active_only=False)) == 1


def test_mark_accessed_updates_last_accessed_at_only(manager):
    m = manager.create_memory("x", MemoryType.FACT)
    original_updated_at = m.updated_at

    accessed = manager.mark_accessed(m.id)

    assert accessed.last_accessed_at is not None
    assert accessed.updated_at == original_updated_at  # untouched


# --- Secret rejection ---------------------------------------------------------


def test_create_memory_rejects_api_key_like_content(manager):
    with pytest.raises(SecretDetectedError):
        manager.create_memory("api_key: sk_live_abcdef1234567890", MemoryType.FACT)


def test_create_memory_rejects_aws_access_key(manager):
    with pytest.raises(SecretDetectedError):
        manager.create_memory("here it is: AKIAABCDEFGHIJKLMNOP", MemoryType.FACT)


def test_create_memory_rejects_private_key_block(manager):
    with pytest.raises(SecretDetectedError):
        manager.create_memory("-----BEGIN RSA PRIVATE KEY-----\nMIIB...", MemoryType.FACT)


def test_create_memory_rejects_bearer_token(manager):
    with pytest.raises(SecretDetectedError):
        manager.create_memory(
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", MemoryType.FACT
        )


def test_rejected_secret_memory_is_not_persisted(manager):
    with pytest.raises(SecretDetectedError):
        manager.create_memory("password: hunter2345", MemoryType.FACT)
    assert manager.list_memories(active_only=False) == []


def test_create_memory_allows_ordinary_content(manager):
    m = manager.create_memory("the user's favorite color is blue", MemoryType.PREFERENCE)
    assert m.content == "the user's favorite color is blue"


def test_update_memory_rechecks_secrets_on_content_change(manager):
    m = manager.create_memory("safe content", MemoryType.FACT)
    with pytest.raises(SecretDetectedError):
        manager.update_memory(m.id, content="AKIAABCDEFGHIJKLMNOP")
    assert manager.get_memory(m.id).content == "safe content"  # original untouched


def test_secret_detected_error_is_a_memory_validation_error():
    assert issubclass(SecretDetectedError, MemoryValidationError)


# --- Relevance scoring / selection --------------------------------------------


def test_select_relevant_memories_ranks_keyword_match_higher(manager):
    manager.create_memory(
        "the user's favorite programming language is Python", MemoryType.FACT, importance=0.5
    )
    manager.create_memory("the weather today is sunny", MemoryType.FACT, importance=0.5)

    results = manager.select_relevant_memories("what programming language does the user like?")

    assert results[0].content.startswith("the user's favorite programming language")


def test_select_relevant_memories_respects_limit(manager):
    for i in range(10):
        manager.create_memory(f"python fact number {i}", MemoryType.FACT, importance=0.5)

    results = manager.select_relevant_memories("python", limit=3)
    assert len(results) == 3


def test_select_relevant_memories_excludes_inactive(manager):
    m = manager.create_memory("python fact", MemoryType.FACT)
    manager.deactivate_memory(m.id)

    results = manager.select_relevant_memories("python")
    assert results == []


def test_select_relevant_memories_filters_by_type(manager):
    manager.create_memory("python preference", MemoryType.PREFERENCE, importance=0.9)
    manager.create_memory("python fact", MemoryType.FACT, importance=0.9)

    results = manager.select_relevant_memories("python", memory_type=MemoryType.FACT)
    assert all(m.memory_type == MemoryType.FACT for m in results)


def test_select_relevant_memories_combines_importance_with_keyword_overlap(manager):
    manager.create_memory("python is nice", MemoryType.FACT, importance=0.2)
    manager.create_memory("python is great", MemoryType.FACT, importance=0.9)

    results = manager.select_relevant_memories("python")
    assert results[0].content == "python is great"


def test_select_relevant_memories_is_deterministic(manager):
    manager.create_memory("python fact one", MemoryType.FACT, importance=0.6)
    manager.create_memory("python fact two", MemoryType.FACT, importance=0.6)

    first = manager.select_relevant_memories("python")
    second = manager.select_relevant_memories("python")
    assert [m.id for m in first] == [m.id for m in second]


def test_select_relevant_memories_does_not_mark_accessed(manager):
    m = manager.create_memory("python fact", MemoryType.FACT)
    manager.select_relevant_memories("python")
    fetched = manager.get_memory(m.id)
    assert fetched.last_accessed_at is None


def test_select_relevant_memories_deduplicates_by_id(manager):
    manager.create_memory("python fact", MemoryType.FACT)
    results = manager.select_relevant_memories("python")
    ids = [r.id for r in results]
    assert len(ids) == len(set(ids))


def test_select_relevant_memories_with_empty_query_falls_back_to_importance_and_recency(manager):
    manager.create_memory("low importance", MemoryType.FACT, importance=0.1)
    manager.create_memory("high importance", MemoryType.FACT, importance=0.9)

    results = manager.select_relevant_memories("")
    assert results[0].content == "high importance"


def test_select_relevant_memories_with_no_matches_returns_empty_list(manager):
    manager.create_memory("something about cats", MemoryType.FACT)
    results = manager.select_relevant_memories("zzz_no_such_keyword_zzz")
    assert results == []

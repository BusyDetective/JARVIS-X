from __future__ import annotations

import uuid

import pytest

from app.memory.models import Memory, MemoryType
from app.memory.repository import MemoryNotFoundError, MemoryRepository, RepositoryError


@pytest.fixture
def repo(tmp_path):
    return MemoryRepository(db_path=tmp_path / "memory_test.db")


# --- CRUD ----------------------------------------------------------------


def test_create_and_get_memory(repo):
    m = Memory(content="likes tea", memory_type=MemoryType.PREFERENCE)
    repo.create_memory(m)

    fetched = repo.get_memory(m.id)
    assert fetched.content == "likes tea"
    assert fetched.memory_type == MemoryType.PREFERENCE
    assert fetched.active is True


def test_get_memory_not_found_raises(repo):
    with pytest.raises(MemoryNotFoundError):
        repo.get_memory(uuid.uuid4())


def test_update_memory(repo):
    m = Memory(content="old content", memory_type=MemoryType.FACT)
    repo.create_memory(m)

    m.content = "new content"
    repo.update_memory(m)

    fetched = repo.get_memory(m.id)
    assert fetched.content == "new content"


def test_update_nonexistent_memory_raises(repo):
    m = Memory(content="ghost", memory_type=MemoryType.FACT)
    with pytest.raises(MemoryNotFoundError):
        repo.update_memory(m)


def test_deactivate_preserves_record(repo):
    m = Memory(content="to deactivate", memory_type=MemoryType.FACT)
    repo.create_memory(m)

    m.active = False
    repo.update_memory(m)

    fetched = repo.get_memory(m.id)  # still retrievable directly by id
    assert fetched.active is False
    assert fetched.content == "to deactivate"  # record preserved, not deleted


# --- Listing / filtering ---------------------------------------------------


def test_list_memories_active_only_by_default(repo):
    active = Memory(content="active one", memory_type=MemoryType.FACT)
    inactive = Memory(content="inactive one", memory_type=MemoryType.FACT, active=False)
    repo.create_memory(active)
    repo.create_memory(inactive)

    memories = repo.list_memories()
    assert [m.content for m in memories] == ["active one"]


def test_list_memories_can_include_inactive(repo):
    active = Memory(content="active one", memory_type=MemoryType.FACT)
    inactive = Memory(content="inactive one", memory_type=MemoryType.FACT, active=False)
    repo.create_memory(active)
    repo.create_memory(inactive)

    memories = repo.list_memories(active_only=False)
    assert len(memories) == 2


def test_list_memories_filters_by_type(repo):
    fact = Memory(content="a fact", memory_type=MemoryType.FACT)
    pref = Memory(content="a preference", memory_type=MemoryType.PREFERENCE)
    repo.create_memory(fact)
    repo.create_memory(pref)

    memories = repo.list_memories(memory_type=MemoryType.PREFERENCE)
    assert [m.content for m in memories] == ["a preference"]


def test_list_memories_orders_by_importance_then_recency(repo):
    low = Memory(content="low importance", memory_type=MemoryType.FACT, importance=0.2)
    high = Memory(content="high importance", memory_type=MemoryType.FACT, importance=0.9)
    repo.create_memory(low)
    repo.create_memory(high)

    memories = repo.list_memories()
    assert [m.content for m in memories] == ["high importance", "low importance"]


def test_list_memories_empty_database_returns_empty_list(repo):
    assert repo.list_memories() == []


# --- Search ----------------------------------------------------------------


def test_search_memories_matches_keyword(repo):
    repo.create_memory(
        Memory(content="the user likes espresso coffee", memory_type=MemoryType.PREFERENCE)
    )
    repo.create_memory(Memory(content="unrelated content about hiking", memory_type=MemoryType.FACT))

    results = repo.search_memories(keywords=["coffee"])
    assert len(results) == 1
    assert "espresso" in results[0].content


def test_search_memories_matches_any_keyword(repo):
    repo.create_memory(Memory(content="likes coffee", memory_type=MemoryType.PREFERENCE))
    repo.create_memory(Memory(content="likes tea", memory_type=MemoryType.PREFERENCE))
    repo.create_memory(Memory(content="likes neither", memory_type=MemoryType.PREFERENCE))

    results = repo.search_memories(keywords=["coffee", "tea"])
    assert {m.content for m in results} == {"likes coffee", "likes tea"}


def test_search_memories_respects_active_only(repo):
    repo.create_memory(Memory(content="active coffee lover", memory_type=MemoryType.PREFERENCE))
    repo.create_memory(
        Memory(content="inactive coffee lover", memory_type=MemoryType.PREFERENCE, active=False)
    )

    results = repo.search_memories(keywords=["coffee"])
    assert [m.content for m in results] == ["active coffee lover"]


def test_search_memories_respects_limit(repo):
    for i in range(5):
        repo.create_memory(Memory(content=f"coffee fact {i}", memory_type=MemoryType.FACT))

    results = repo.search_memories(keywords=["coffee"], limit=2)
    assert len(results) == 2


def test_search_memories_filters_by_type(repo):
    repo.create_memory(Memory(content="python preference", memory_type=MemoryType.PREFERENCE))
    repo.create_memory(Memory(content="python fact", memory_type=MemoryType.FACT))

    results = repo.search_memories(keywords=["python"], memory_type=MemoryType.FACT)
    assert [m.content for m in results] == ["python fact"]


def test_search_memories_with_no_keywords_returns_all_active(repo):
    repo.create_memory(Memory(content="one", memory_type=MemoryType.FACT))
    repo.create_memory(Memory(content="two", memory_type=MemoryType.FACT))

    results = repo.search_memories()
    assert len(results) == 2


def test_search_memories_is_case_insensitive(repo):
    repo.create_memory(Memory(content="the user likes Python", memory_type=MemoryType.FACT))
    results = repo.search_memories(keywords=["python"])
    assert len(results) == 1


# --- Persistence across re-instantiation -----------------------------------


def test_database_survives_repository_reinstantiation(tmp_path):
    db_path = tmp_path / "persist.db"
    repo1 = MemoryRepository(db_path=db_path)
    m = Memory(content="persist me", memory_type=MemoryType.FACT)
    repo1.create_memory(m)

    repo2 = MemoryRepository(db_path=db_path)  # fresh instance, same file
    fetched = repo2.get_memory(m.id)
    assert fetched.content == "persist me"


def test_repository_error_is_the_base_of_not_found_error():
    assert issubclass(MemoryNotFoundError, RepositoryError)

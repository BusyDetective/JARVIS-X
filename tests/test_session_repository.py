from __future__ import annotations

import sqlite3
import threading
import uuid

import pytest

from app.sessions.models import Conversation, MessageRole, Session
from app.sessions.repository import (
    ConversationNotFoundError,
    ConversationRepository,
    MessageNotFoundError,
    MessageRepository,
    SessionNotFoundError,
    SessionRepository,
)


@pytest.fixture
def db(tmp_path):
    return tmp_path / "t.db"


@pytest.fixture
def conv(db):
    s = SessionRepository(db).create_session(Session(title="t"))
    return ConversationRepository(db).create_conversation(Conversation(session_id=s.id))


# --- sessions ---------------------------------------------------------------


def test_session_create_get_and_persists_across_instances(db):
    s = SessionRepository(db).create_session(Session(title="Hello", metadata={"a": 1}))
    got = SessionRepository(db).get_session(s.id)
    assert got == s and got.metadata == {"a": 1} and got.created_at.tzinfo is not None


def test_session_get_missing(db):
    with pytest.raises(SessionNotFoundError):
        SessionRepository(db).get_session(uuid.uuid4())


def test_session_update(db):
    repo = SessionRepository(db)
    s = repo.create_session(Session())
    repo.update_session(s.model_copy(update={"title": "New", "metadata": {"x": 2}}))
    got = repo.get_session(s.id)
    assert got.title == "New" and got.metadata == {"x": 2}
    with pytest.raises(SessionNotFoundError):
        repo.update_session(Session())


def test_session_deactivate(db):
    repo = SessionRepository(db)
    s = repo.create_session(Session())
    out = repo.deactivate_session(s.id)
    assert out.active is False and out.updated_at >= s.updated_at
    assert repo.get_session(s.id).active is False
    with pytest.raises(SessionNotFoundError):
        repo.deactivate_session(uuid.uuid4())


def test_session_list_order_and_filters(db):
    repo = SessionRepository(db)
    a, b, c = (repo.create_session(Session(title=t)) for t in "abc")
    repo.deactivate_session(a.id)  # a becomes most recently updated
    assert [s.title for s in repo.list_sessions()] == ["a", "c", "b"]
    assert {s.title for s in repo.list_sessions(active_only=True)} == {"b", "c"}
    assert len(repo.list_sessions(limit=2)) == 2


# --- conversations ----------------------------------------------------------


def test_conversation_create_get_persist(db):
    s = SessionRepository(db).create_session(Session())
    c = ConversationRepository(db).create_conversation(
        Conversation(session_id=s.id, metadata={"m": 1})
    )
    got = ConversationRepository(db).get_conversation(c.id)
    assert got == c and got.session_id == s.id


def test_conversation_requires_existing_session(db):
    with pytest.raises(SessionNotFoundError):
        ConversationRepository(db).create_conversation(Conversation(session_id=uuid.uuid4()))


def test_conversation_get_missing_and_update(db, conv):
    repo = ConversationRepository(db)
    with pytest.raises(ConversationNotFoundError):
        repo.get_conversation(uuid.uuid4())
    repo.update_conversation(conv.model_copy(update={"metadata": {"z": 1}}))
    assert repo.get_conversation(conv.id).metadata == {"z": 1}
    with pytest.raises(ConversationNotFoundError):
        repo.update_conversation(Conversation(session_id=conv.session_id))


def test_conversation_list_by_session(db):
    sessions = SessionRepository(db)
    s1, s2 = sessions.create_session(Session()), sessions.create_session(Session())
    repo = ConversationRepository(db)
    a = repo.create_conversation(Conversation(session_id=s1.id))
    b = repo.create_conversation(Conversation(session_id=s1.id))
    repo.create_conversation(Conversation(session_id=s2.id))
    assert [c.id for c in repo.list_conversations(s1.id)] == [a.id, b.id]
    assert len(repo.list_conversations(s2.id)) == 1


# --- messages ---------------------------------------------------------------


def test_append_assigns_sequences_and_persists(db, conv):
    repo = MessageRepository(db)
    m1 = repo.append_message(conv.id, MessageRole.USER, "one")
    m2 = repo.append_message(conv.id, MessageRole.ASSISTANT, "two", {"k": "v"})
    assert (m1.sequence, m2.sequence) == (1, 2)
    again = MessageRepository(db)
    assert again.get_message(m2.id) == m2 and again.get_message(m2.id).metadata == {"k": "v"}
    assert [m.content for m in again.list_messages(conv.id)] == ["one", "two"]


def test_sequences_are_per_conversation(db, conv):
    other = ConversationRepository(db).create_conversation(Conversation(session_id=conv.session_id))
    repo = MessageRepository(db)
    repo.append_message(conv.id, MessageRole.USER, "a")
    repo.append_message(conv.id, MessageRole.USER, "b")
    assert repo.append_message(other.id, MessageRole.USER, "c").sequence == 1


def test_ordering_uses_sequence_not_timestamps(db, conv):
    repo = MessageRepository(db)
    ids = [repo.append_message(conv.id, MessageRole.USER, f"m{i}").id for i in range(3)]
    c = sqlite3.connect(db)  # scramble timestamps; order must not change
    c.execute("UPDATE messages SET created_at = '2000-01-01T00:00:00.000000+00:00' WHERE content='m2'")
    c.commit()
    c.close()
    assert [m.id for m in repo.list_messages(conv.id)] == ids


def test_recent_messages_oldest_to_newest(db, conv):
    repo = MessageRepository(db)
    for i in range(1, 6):
        repo.append_message(conv.id, MessageRole.USER, f"m{i}")
    assert [m.content for m in repo.get_recent_messages(conv.id, 3)] == ["m3", "m4", "m5"]
    assert len(repo.get_recent_messages(conv.id, 99)) == 5
    with pytest.raises(ValueError):
        repo.get_recent_messages(conv.id, 0)


def test_count(db, conv):
    repo = MessageRepository(db)
    assert repo.count_messages(conv.id) == 0
    repo.append_message(conv.id, MessageRole.USER, "x")
    assert repo.count_messages(conv.id) == 1


def test_append_unknown_conversation_and_get_missing(db):
    repo = MessageRepository(db)
    with pytest.raises(ConversationNotFoundError):
        repo.append_message(uuid.uuid4(), MessageRole.USER, "x")
    with pytest.raises(MessageNotFoundError):
        repo.get_message(uuid.uuid4())


def test_append_validates_tool_metadata_before_writing(db, conv):
    repo = MessageRepository(db)
    with pytest.raises(ValueError):
        repo.append_message(conv.id, MessageRole.TOOL, "x")
    assert repo.count_messages(conv.id) == 0


def test_append_touches_conversation_and_session_updated_at(db, conv):
    MessageRepository(db).append_message(conv.id, MessageRole.USER, "x")
    assert ConversationRepository(db).get_conversation(conv.id).updated_at > conv.updated_at
    assert SessionRepository(db).get_session(conv.session_id).updated_at > conv.created_at


def test_concurrent_appends_get_unique_contiguous_sequences(db, conv):
    errors: list[Exception] = []

    def worker():
        repo = MessageRepository(db)
        try:
            for _ in range(15):
                repo.append_message(conv.id, MessageRole.USER, "x")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert [m.sequence for m in MessageRepository(db).list_messages(conv.id)] == list(range(1, 91))

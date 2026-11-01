from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.sessions.models import Conversation, ConversationMessage, MessageRole, Session


def test_session_defaults():
    s = Session()
    assert isinstance(s.id, uuid.UUID)
    assert s.title is None and s.active is True and s.metadata == {}
    assert s.created_at.tzinfo is not None and s.updated_at.tzinfo is not None
    assert s.created_at.utcoffset() == timezone.utc.utcoffset(None)


def test_session_unique_ids_and_metadata():
    a, b = Session(metadata={"k": 1}), Session()
    assert a.id != b.id and a.metadata == {"k": 1} and b.metadata == {}


def test_session_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        Session(created_at=datetime(2026, 1, 1))


@pytest.mark.parametrize("title", ["", "   "])
def test_session_rejects_blank_title(title):
    with pytest.raises(ValidationError):
        Session(title=title)


def test_session_rejects_invalid_id():
    with pytest.raises(ValidationError):
        Session(id="not-a-uuid")


def test_conversation_valid_and_relationship():
    sid = uuid.uuid4()
    c = Conversation(session_id=sid)
    assert c.session_id == sid and isinstance(c.id, uuid.UUID)
    assert c.created_at.tzinfo is not None and c.updated_at.tzinfo is not None
    assert Conversation(session_id=sid).id != c.id


def test_conversation_requires_session_id_and_utc():
    with pytest.raises(ValidationError):
        Conversation()
    with pytest.raises(ValidationError):
        Conversation(session_id=uuid.uuid4(), updated_at=datetime(2026, 1, 1))


def _msg(**kw):
    base = dict(conversation_id=uuid.uuid4(), role=MessageRole.USER, content="hi", sequence=1)
    base.update(kw)
    return ConversationMessage(**base)


def test_message_valid():
    m = _msg()
    assert isinstance(m.id, uuid.UUID) and m.created_at.tzinfo is not None
    assert m.role is MessageRole.USER and m.metadata == {}


def test_message_roles_enum():
    assert {r.value for r in MessageRole} == {"system", "user", "assistant", "tool"}
    assert _msg(role="assistant").role is MessageRole.ASSISTANT
    with pytest.raises(ValidationError):
        _msg(role="robot")


@pytest.mark.parametrize("seq", [0, -1])
def test_message_sequence_must_be_positive(seq):
    with pytest.raises(ValidationError):
        _msg(sequence=seq)


def test_message_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        _msg(created_at=datetime(2026, 1, 1))


def test_message_metadata_roundtrip():
    assert _msg(metadata={"a": [1, 2]}).metadata == {"a": [1, 2]}


def test_tool_message_requires_linkage_metadata():
    with pytest.raises(ValidationError):
        _msg(role=MessageRole.TOOL)
    with pytest.raises(ValidationError):
        _msg(role=MessageRole.TOOL, metadata={"tool_call_id": "c1"})
    with pytest.raises(ValidationError):
        _msg(role=MessageRole.TOOL, metadata={"tool_call_id": " ", "tool_name": "x"})
    m = _msg(role=MessageRole.TOOL, metadata={"tool_call_id": "c1", "tool_name": "calc"})
    assert m.metadata["tool_name"] == "calc"

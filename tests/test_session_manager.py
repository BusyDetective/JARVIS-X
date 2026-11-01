from __future__ import annotations

import uuid

import pytest

from app.providers.schemas import ToolCall
from app.sessions.manager import (
    ConversationValidationError,
    SessionInactiveError,
    build_session_services,
    derive_session_title,
)
from app.sessions.models import MessageRole
from app.sessions.repository import ConversationNotFoundError, SessionNotFoundError


@pytest.fixture
def svc(tmp_path):
    return build_session_services(tmp_path / "t.db")


@pytest.fixture
def sm(svc):
    return svc[0]


@pytest.fixture
def cm(svc):
    return svc[1]


@pytest.fixture
def conv(sm):
    return sm.create_conversation(sm.create_session(title="T").id)


# --- SessionManager ---------------------------------------------------------


def test_create_retrieve_rename_deactivate_list(sm):
    s = sm.create_session(title="First", metadata={"a": 1})
    assert sm.get_session(s.id).title == "First"
    assert sm.rename_session(s.id, "  Renamed ").title == "Renamed"
    with pytest.raises(ConversationValidationError):
        sm.rename_session(s.id, "  ")
    sm.deactivate_session(s.id)
    assert sm.get_session(s.id).active is False
    other = sm.create_session()
    assert [x.id for x in sm.list_sessions(active_only=True)] == [other.id]
    assert len(sm.list_sessions()) == 2
    with pytest.raises(SessionNotFoundError):
        sm.get_session(uuid.uuid4())


def test_conversation_creation_and_listing(sm):
    s = sm.create_session()
    a, b = sm.create_conversation(s.id), sm.create_conversation(s.id, {"m": 1})
    assert [c.id for c in sm.list_conversations(s.id)] == [a.id, b.id]
    assert sm.get_conversation(b.id).metadata == {"m": 1}
    with pytest.raises(SessionNotFoundError):
        sm.create_conversation(uuid.uuid4())


def test_cannot_create_conversation_in_inactive_session(sm):
    s = sm.create_session()
    sm.deactivate_session(s.id)
    with pytest.raises(SessionInactiveError):
        sm.create_conversation(s.id)


# --- ConversationManager ----------------------------------------------------


def test_append_all_message_kinds_in_order(cm, conv):
    tc = ToolCall(id="call_1", name="calc", arguments={"a": 1}, provider_call_id="p1")
    cm.append_user_message(conv.id, "hi")
    a = cm.append_assistant_message(conv.id, None, tool_calls=[tc])
    t = cm.append_tool_message(conv.id, '{"ok":1}', "call_1", "calc")
    cm.append_assistant_message(conv.id, "done")
    hist = cm.get_history(conv.id)
    assert [m.role for m in hist] == [
        MessageRole.USER, MessageRole.ASSISTANT, MessageRole.TOOL, MessageRole.ASSISTANT,
    ]
    assert [m.sequence for m in hist] == [1, 2, 3, 4]
    assert a.content == "" and a.metadata["tool_calls"][0]["id"] == "call_1"
    assert a.metadata["tool_calls"][0]["provider_call_id"] == "p1"
    assert t.metadata["tool_call_id"] == "call_1" and t.metadata["tool_name"] == "calc"


def test_system_message_explicit_only(cm, conv):
    m = cm.append_system_message(conv.id, "note")
    assert m.role is MessageRole.SYSTEM


def test_recent_and_count(cm, conv):
    for i in range(5):
        cm.append_user_message(conv.id, f"m{i}")
    assert [m.content for m in cm.get_recent_messages(conv.id, 2)] == ["m3", "m4"]
    assert cm.count_messages(conv.id) == 5


def test_default_recent_window_comes_from_config(svc, conv):
    _, cm = svc
    cm.max_recent_messages = 2
    for i in range(4):
        cm.append_user_message(conv.id, f"m{i}")
    assert [m.content for m in cm.get_recent_messages(conv.id)] == ["m2", "m3"]


def test_validation(cm, conv):
    for bad in ("", "   "):
        with pytest.raises(ConversationValidationError):
            cm.append_user_message(conv.id, bad)
        with pytest.raises(ConversationValidationError):
            cm.append_system_message(conv.id, bad)
    with pytest.raises(ConversationValidationError):
        cm.append_assistant_message(conv.id, "  ")
    with pytest.raises(ConversationValidationError):
        cm.append_tool_message(conv.id, "x", "", "calc")
    with pytest.raises(ConversationValidationError):
        cm.append_tool_message(conv.id, "x", "c1", " ")
    assert cm.count_messages(conv.id) == 0


def test_reserved_metadata_cannot_be_overridden(cm, conv):
    m = cm.append_tool_message(conv.id, "x", "real", "calc", metadata={"tool_call_id": "fake"})
    assert m.metadata["tool_call_id"] == "real"


def test_unknown_conversation(cm):
    with pytest.raises(ConversationNotFoundError):
        cm.append_user_message(uuid.uuid4(), "x")
    with pytest.raises(ConversationNotFoundError):
        cm.get_history(uuid.uuid4())


def test_inactive_session_blocks_writes_but_not_reads(sm, cm, conv):
    cm.append_user_message(conv.id, "before")
    sm.deactivate_session(conv.session_id)
    with pytest.raises(SessionInactiveError):
        cm.append_user_message(conv.id, "after")
    assert [m.content for m in cm.get_history(conv.id)] == ["before"]


# --- titles -----------------------------------------------------------------


def test_title_derived_from_first_user_message_only(sm, cm):
    s = sm.create_session()
    c = sm.create_conversation(s.id)
    cm.append_user_message(c.id, "  Plan my\n week please ")
    assert sm.get_session(s.id).title == "Plan my week please"
    cm.append_user_message(c.id, "something else")
    assert sm.get_session(s.id).title == "Plan my week please"


def test_explicit_title_is_never_overwritten(sm, cm):
    s = sm.create_session(title="Mine")
    cm.append_user_message(sm.create_conversation(s.id).id, "hello")
    assert sm.get_session(s.id).title == "Mine"


def test_derive_title_truncation():
    assert derive_session_title("short") == "short"
    t = derive_session_title("word " * 50, max_length=20)
    assert len(t) <= 20 and t.endswith("…") and "  " not in t
    assert len(derive_session_title("x" * 500, max_length=10)) <= 10
    with pytest.raises(ValueError):
        derive_session_title("   ")

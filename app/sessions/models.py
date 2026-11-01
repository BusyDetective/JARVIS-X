from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


class Session(BaseModel):
    """A user's ongoing interaction container. NOT a Task (one unit of
    work) and NOT a Conversation (an ordered message history) — a Session
    groups one or more Conversations. `active=False` means closed: its
    conversations stay readable but accept no new messages."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    title: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("title")
    @classmethod
    def _title_not_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not v.strip():
            raise ValueError("Session title cannot be blank (use None for untitled)")
        return v

    @field_validator("created_at", "updated_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _require_utc(v)


class Conversation(BaseModel):
    """An ordered message history belonging to exactly one Session."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    session_id: uuid.UUID
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _require_utc(v)


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ConversationMessage(BaseModel):
    """One persisted, provider-neutral conversation turn.

    Named `ConversationMessage` (not `Message`) deliberately: the project
    already has `app.providers.schemas.Message`, the in-flight dataclass
    handed to providers. That one is a transport shape; this one is the
    durable record. They share role strings but are separate types.

    No provider SDK objects live here — only scalars and JSON-safe
    metadata. Conventions for `metadata`:
      - ASSISTANT turns that requested tools: `tool_calls` = list of
        {id, name, arguments, provider_call_id}.
      - TOOL turns (REQUIRED): `tool_call_id` and `tool_name`.
    ToolResult remains the canonical tool-execution record (in
    tool_results); a TOOL message is only its conversational rendering.

    `sequence` is 1-based and assigned by MessageRepository on append;
    it is the sole source of ordering truth (never timestamps).
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    conversation_id: uuid.UUID
    role: MessageRole
    content: str
    created_at: datetime = Field(default_factory=utcnow)
    sequence: int = Field(ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _require_utc(v)

    @model_validator(mode="after")
    def _tool_messages_are_linkable(self) -> "ConversationMessage":
        if self.role == MessageRole.TOOL:
            for key in ("tool_call_id", "tool_name"):
                value = self.metadata.get(key)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"TOOL messages require non-empty metadata['{key}']")
        return self

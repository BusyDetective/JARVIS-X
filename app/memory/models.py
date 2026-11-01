from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MemoryType(str, Enum):
    """Kept deliberately small — a handful of categories cover what
    JARVIS-X needs to remember intentionally, without becoming a
    free-form tagging system."""

    FACT = "fact"
    PREFERENCE = "preference"
    DECISION = "decision"
    PROJECT = "project"
    GOAL = "goal"
    INSTRUCTION = "instruction"


class Memory(BaseModel):
    """One piece of intentionally persisted long-term memory.

    Memory is NEVER written automatically from raw conversation — see
    `app.memory.manager.MemoryManager`, which is the only place a Memory
    gets created, and which requires an explicit `memory_type` and runs a
    conservative secret-detection check before persisting anything (see
    `app.memory.secrets`).

    Holds only scalar/serializable fields — no arbitrary Python objects —
    so it round-trips through SQLite cleanly (see `app.memory.repository`
    for the TEXT/JSON mapping), the same convention `app.tasks.models`
    uses for `Task`/`TaskRun`.

    Updating a memory (`MemoryManager.update_memory`) preserves `id` and
    `created_at`, and refreshes `updated_at`. Deactivating one
    (`MemoryManager.deactivate_memory`) sets `active=False` rather than
    deleting the row, so the record remains available for future
    auditing.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    content: str
    memory_type: MemoryType
    importance: float = 0.5
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_accessed_at: datetime | None = None
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True

    @field_validator("content")
    @classmethod
    def _content_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Memory content cannot be empty")
        return v

    @field_validator("importance")
    @classmethod
    def _importance_bounded(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("Memory importance must be between 0.0 and 1.0")
        return v

    @field_validator("created_at", "updated_at", "last_accessed_at")
    @classmethod
    def _require_utc(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
        return v

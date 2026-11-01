from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ContextSource(str, Enum):
    """Where one piece of context originated. Kept structurally distinct
    so, e.g., TOOL output is never confused with SYSTEM instructions or
    USER input downstream — see `app.context.manager` for how this drives
    both priority defaults and (in the optional orchestrator integration)
    message-role mapping."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TASK = "task"
    MEMORY = "memory"
    TOOL = "tool"


class ContextPriority(str, Enum):
    """Deterministic priority tiers used when a ContextBundle must be
    trimmed to fit `max_total_context_items`. CRITICAL (system
    instructions) is preserved first; LOW is dropped first. See
    `app.context.manager.ContextManager._trim_to_total` for the exact
    trimming rule."""

    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


# Ordinal ranking for sorting/trimming — lower rank is dropped first.
# A plain dict (not IntEnum) to keep ContextPriority a clean str Enum for
# serialization, matching this project's existing convention
# (TaskStatus/TaskRunStatus use the same str-Enum-plus-separate-ranking
# pattern rather than IntEnum).
PRIORITY_RANK: dict[ContextPriority, int] = {
    ContextPriority.LOW: 0,
    ContextPriority.NORMAL: 1,
    ContextPriority.HIGH: 2,
    ContextPriority.CRITICAL: 3,
}


class ContextItem(BaseModel):
    """One unit of context: a single piece of information that may be
    included in a model invocation. Holds only scalar/serializable
    fields — no provider-specific message objects — so this layer stays
    provider-agnostic (see app.context.manager's module docstring)."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    content: str
    source: ContextSource
    priority: ContextPriority = ContextPriority.NORMAL
    created_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content")
    @classmethod
    def _content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ContextItem content cannot be empty")
        return v

    @field_validator("created_at")
    @classmethod
    def _require_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (UTC), not naive")
        return v


class ConversationContext(BaseModel):
    """The current conversation's turns, as ContextItems (source is
    typically USER/ASSISTANT). Ordering is chronological — oldest first —
    the same convention the orchestrator's own `messages` list uses."""

    items: list[ContextItem] = Field(default_factory=list)


class TaskContext(BaseModel):
    """Context specific to the current task (e.g. what's known about the
    in-progress Task/TaskRun), as ContextItems (source is typically
    TASK)."""

    items: list[ContextItem] = Field(default_factory=list)


class ContextBundle(BaseModel):
    """The final, assembled set of ContextItems selected for ONE model
    invocation — what `ContextManager.build_context` produces. This is
    the provider-neutral representation section 14 requires: the
    provider layer (app.providers.*) remains solely responsible for
    turning this (or the Message list derived from it — see
    `app.context.manager.context_bundle_to_messages`) into a provider's
    actual API request shape.
    """

    items: list[ContextItem] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at")
    @classmethod
    def _require_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (UTC), not naive")
        return v

    def items_from(self, source: ContextSource) -> list[ContextItem]:
        return [item for item in self.items if item.source == source]

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from app.memory.models import Memory, MemoryType, utcnow
from app.memory.repository import MemoryRepository
from app.memory.secrets import find_secret

logger = logging.getLogger(__name__)

_WORD_RE = re.compile(r"[a-z0-9]+")

# Relevance-scoring weights (see select_relevant_memories' docstring).
# Deliberately simple, transparent, and summing to 1.0 so the combined
# score stays within [0, 1] when every component is.
_KEYWORD_WEIGHT = 0.5
_IMPORTANCE_WEIGHT = 0.3
_RECENCY_WEIGHT = 0.2

# A memory's recency contribution decays linearly to 0 over this many days
# since it was last touched (created, or accessed if that's more recent),
# then stays at 0 — not negative — for anything older.
_RECENCY_WINDOW_DAYS = 30.0


class MemoryValidationError(Exception):
    """Raised when memory content/fields fail MemoryManager's own
    validation (distinct from Pydantic's schema-level validation on
    `Memory` itself — e.g. this covers the secret-detection boundary)."""


class SecretDetectedError(MemoryValidationError):
    """Raised when candidate memory content matches a secret-like pattern
    (see `app.memory.secrets`). The memory is NOT persisted."""

    def __init__(self, label: str) -> None:
        self.label = label
        super().__init__(
            f"Refusing to store this as memory: content matches a pattern "
            f"that looks like a {label}. If this isn't actually a secret, "
            f"rephrase it without the matched pattern."
        )


def _tokenize(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


class MemoryManager:
    """Owns memory BEHAVIOR and validation. Sits above `MemoryRepository`,
    which owns raw database access — this class contains no SQL.

    Memory is never written automatically from conversation — every
    `create_memory` call is an explicit, intentional request to persist
    something, and runs a conservative secret-detection check first (see
    `app.memory.secrets.find_secret`) that rejects the write outright
    rather than silently redacting or storing it anyway.
    """

    def __init__(self, repository: MemoryRepository) -> None:
        self.repository = repository

    # --- Creation / validation --------------------------------------------

    def create_memory(
        self,
        content: str,
        memory_type: MemoryType,
        importance: float = 0.5,
        source: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Memory:
        self._check_for_secrets(content)
        memory = Memory(
            content=content,
            memory_type=memory_type,
            importance=importance,
            source=source,
            metadata=metadata or {},
        )
        return self.repository.create_memory(memory)

    def update_memory(
        self,
        memory_id: uuid.UUID,
        content: str | None = None,
        importance: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Memory:
        """Preserves `id` and `created_at`; refreshes `updated_at`. Only
        the fields explicitly passed are changed. Re-runs the
        secret-detection check if `content` is being changed."""
        existing = self.repository.get_memory(memory_id)
        if content is not None:
            self._check_for_secrets(content)
        updated = existing.model_copy(
            update={
                "content": content if content is not None else existing.content,
                "importance": importance if importance is not None else existing.importance,
                "metadata": metadata if metadata is not None else existing.metadata,
                "updated_at": utcnow(),
            }
        )
        return self.repository.update_memory(updated)

    def deactivate_memory(self, memory_id: uuid.UUID) -> Memory:
        """Soft delete: sets active=False and bumps updated_at. The record
        is preserved (never physically deleted) for future auditing."""
        existing = self.repository.get_memory(memory_id)
        updated = existing.model_copy(update={"active": False, "updated_at": utcnow()})
        return self.repository.update_memory(updated)

    def get_memory(self, memory_id: uuid.UUID) -> Memory:
        return self.repository.get_memory(memory_id)

    def list_memories(
        self, active_only: bool = True, memory_type: MemoryType | None = None
    ) -> list[Memory]:
        return self.repository.list_memories(active_only=active_only, memory_type=memory_type)

    def mark_accessed(self, memory_id: uuid.UUID) -> Memory:
        """Updates ONLY `last_accessed_at` — deliberately does not touch
        `updated_at`, which reflects content/metadata changes, not reads."""
        existing = self.repository.get_memory(memory_id)
        updated = existing.model_copy(update={"last_accessed_at": utcnow()})
        return self.repository.update_memory(updated)

    def _check_for_secrets(self, content: str) -> None:
        label = find_secret(content)
        if label is not None:
            logger.warning("memory: rejected candidate memory — matched %s pattern", label)
            raise SecretDetectedError(label)

    # --- Selection / relevance scoring -------------------------------------

    def select_relevant_memories(
        self,
        query: str,
        memory_type: MemoryType | None = None,
        limit: int = 5,
    ) -> list[Memory]:
        """Deterministic memory selection for a given query/context.

        Pipeline (see module docstring for the exact weights):
            1. retrieve candidates — active memories, optionally filtered by
               memory_type, matching ANY query keyword
               (MemoryRepository.search_memories — basic, not scored)
            2. score each candidate:
                 score = 0.5 * keyword_overlap + 0.3 * importance + 0.2 * recency
               - keyword_overlap: |query tokens ∩ content tokens| / |query tokens|
                 (0 if the query has no tokens)
               - importance: the memory's own importance, already in [0, 1]
               - recency: linear decay from 1.0 (touched today) to 0.0 at
                 _RECENCY_WINDOW_DAYS days since created_at (or
                 last_accessed_at, whichever is more recent), floored at 0.0
                 for anything older
            3. deduplicate by id (candidates are already unique rows, but
               this guards against any future candidate source that isn't)
            4. sort by score descending; ties broken by importance, then by
               created_at descending (newer first)
            5. return the top `limit`

            This is deliberately simple and keyword-based — no embeddings,
            no vector search, no LLM-based relevance judgment. It does NOT
            mark the returned memories as accessed; callers (e.g.
            ContextManager, once it actually uses a memory in a built
            ContextBundle) are responsible for calling `mark_accessed`
            themselves, so that scoring stays a pure, side-effect-free,
            and fully deterministic/testable operation.
        """
        query_tokens = _tokenize(query)
        candidates = self.repository.search_memories(
            keywords=sorted(query_tokens) if query_tokens else None,
            memory_type=memory_type,
            active_only=True,
            limit=None,
        )

        seen_ids: set[uuid.UUID] = set()
        scored: list[tuple[float, Memory]] = []
        now = datetime.now(timezone.utc)
        for memory in candidates:
            if memory.id in seen_ids:
                continue
            seen_ids.add(memory.id)
            scored.append((self._score(memory, query_tokens, now), memory))

        scored.sort(key=lambda pair: (pair[0], pair[1].importance, pair[1].created_at), reverse=True)
        return [memory for _, memory in scored[:limit]]

    @staticmethod
    def _score(memory: Memory, query_tokens: set[str], now: datetime) -> float:
        content_tokens = _tokenize(memory.content)
        if query_tokens:
            overlap = len(query_tokens & content_tokens) / len(query_tokens)
        else:
            overlap = 0.0

        anchor = memory.last_accessed_at or memory.created_at
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (now - anchor).total_seconds() / 86400.0)
        recency = max(0.0, 1.0 - (age_days / _RECENCY_WINDOW_DAYS))

        return (
            _KEYWORD_WEIGHT * overlap
            + _IMPORTANCE_WEIGHT * memory.importance
            + _RECENCY_WEIGHT * recency
        )

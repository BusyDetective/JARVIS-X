from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.memory.models import Memory, MemoryType
from app.storage.database import connection_scope


class RepositoryError(Exception):
    """Raised for unexpected database failures. Database errors are never
    silently swallowed — every repository method either returns a typed
    result or raises this (or a subclass)."""


class MemoryNotFoundError(RepositoryError):
    def __init__(self, memory_id: uuid.UUID) -> None:
        self.memory_id = memory_id
        super().__init__(f"Memory {memory_id} not found")


# --- Serialization helpers (the ONE place that converts to/from SQLite's
# TEXT-only storage for memory data — mirrors app.tasks.repository's
# convention of keeping this in one place). --------------------------------


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware (UTC) to persist")
    return dt.astimezone(timezone.utc).isoformat()


def _iso_to_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _row_to_memory(row: sqlite3.Row) -> Memory:
    return Memory(
        id=uuid.UUID(row["id"]),
        content=row["content"],
        memory_type=MemoryType(row["memory_type"]),
        importance=row["importance"],
        created_at=_iso_to_dt(row["created_at"]),
        updated_at=_iso_to_dt(row["updated_at"]),
        last_accessed_at=_iso_to_dt(row["last_accessed_at"]),
        source=row["source"],
        metadata=json.loads(row["metadata_json"]) if row["metadata_json"] else {},
        active=bool(row["active"]),
    )


class MemoryRepository:
    """Owns ALL database access for memories.

    Every public method opens its own short-lived connection via
    `connection_scope` rather than holding one open across calls — same
    convention as `TaskRepository`, see the concurrency note in
    `app.storage.database`. Returns typed `Memory` models, never raw
    `sqlite3.Row` objects.

    `search_memories` is deliberately simple: active/type filtering plus
    basic keyword `LIKE` matching, ordered by importance then recency.
    This is the "deterministic/basic retrieval" this phase calls for —
    not relevance scoring (that combines this with recency/importance
    weighting in `MemoryManager.select_relevant_memories`) and not vector
    search. The interface (keywords in, candidate Memories out) is kept
    narrow enough that a future semantic/vector implementation could
    replace this method's body without changing callers.

    `db_path=None` (the default) uses the project's configured database
    (`settings.resolved_db_path`); tests pass an explicit temporary path.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = db_path

    def _connect(self):
        return connection_scope(self._db_path)

    def create_memory(self, memory: Memory) -> Memory:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO memories
                        (id, content, memory_type, importance, created_at, updated_at,
                         last_accessed_at, source, metadata_json, active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(memory.id),
                        memory.content,
                        memory.memory_type.value,
                        memory.importance,
                        _dt_to_iso(memory.created_at),
                        _dt_to_iso(memory.updated_at),
                        _dt_to_iso(memory.last_accessed_at),
                        memory.source,
                        json.dumps(memory.metadata, default=str),
                        1 if memory.active else 0,
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to create memory {memory.id}: {exc}") from exc
        return memory

    def get_memory(self, memory_id: uuid.UUID) -> Memory:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM memories WHERE id = ?", (str(memory_id),)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get memory {memory_id}: {exc}") from exc
        if row is None:
            raise MemoryNotFoundError(memory_id)
        return _row_to_memory(row)

    def update_memory(self, memory: Memory) -> Memory:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    UPDATE memories
                    SET content = ?, memory_type = ?, importance = ?, created_at = ?,
                        updated_at = ?, last_accessed_at = ?, source = ?,
                        metadata_json = ?, active = ?
                    WHERE id = ?
                    """,
                    (
                        memory.content,
                        memory.memory_type.value,
                        memory.importance,
                        _dt_to_iso(memory.created_at),
                        _dt_to_iso(memory.updated_at),
                        _dt_to_iso(memory.last_accessed_at),
                        memory.source,
                        json.dumps(memory.metadata, default=str),
                        1 if memory.active else 0,
                        str(memory.id),
                    ),
                )
                if cur.rowcount == 0:
                    raise MemoryNotFoundError(memory.id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to update memory {memory.id}: {exc}") from exc
        return memory

    def list_memories(
        self,
        active_only: bool = True,
        memory_type: MemoryType | None = None,
    ) -> list[Memory]:
        query = "SELECT * FROM memories WHERE 1=1"
        params: list[object] = []
        if active_only:
            query += " AND active = 1"
        if memory_type is not None:
            query += " AND memory_type = ?"
            params.append(memory_type.value)
        query += " ORDER BY importance DESC, created_at DESC"

        try:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to list memories: {exc}") from exc
        return [_row_to_memory(row) for row in rows]

    def search_memories(
        self,
        keywords: list[str] | None = None,
        memory_type: MemoryType | None = None,
        active_only: bool = True,
        limit: int | None = None,
    ) -> list[Memory]:
        """Basic deterministic candidate retrieval: optional active/type
        filtering plus a case-insensitive `LIKE` match against any of
        `keywords` (OR'd together — a memory matching ANY keyword is a
        candidate). No relevance scoring here; see the class docstring.
        """
        query = "SELECT * FROM memories WHERE 1=1"
        params: list[object] = []
        if active_only:
            query += " AND active = 1"
        if memory_type is not None:
            query += " AND memory_type = ?"
            params.append(memory_type.value)
        if keywords:
            clean = [kw.strip() for kw in keywords if kw and kw.strip()]
            if clean:
                query += " AND (" + " OR ".join("content LIKE ?" for _ in clean) + ")"
                params.extend(f"%{kw}%" for kw in clean)
        query += " ORDER BY importance DESC, created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        try:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to search memories: {exc}") from exc
        return [_row_to_memory(row) for row in rows]

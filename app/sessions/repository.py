from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.sessions.models import (
    Conversation,
    ConversationMessage,
    MessageRole,
    Session,
    utcnow,
)
from app.storage.database import connection_scope


class RepositoryError(Exception):
    """Unexpected database failure; never silently swallowed."""


class SessionNotFoundError(RepositoryError):
    def __init__(self, session_id: uuid.UUID) -> None:
        self.session_id = session_id
        super().__init__(f"Session {session_id} not found")


class ConversationNotFoundError(RepositoryError):
    def __init__(self, conversation_id: uuid.UUID) -> None:
        self.conversation_id = conversation_id
        super().__init__(f"Conversation {conversation_id} not found")


class MessageNotFoundError(RepositoryError):
    def __init__(self, message_id: uuid.UUID) -> None:
        self.message_id = message_id
        super().__init__(f"Message {message_id} not found")


# --- Serialization helpers (the one place TEXT/JSON conversion happens) -----


def _dt_to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware (UTC) to persist")
    # Fixed-width microseconds so lexicographic order == chronological order.
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _iso_to_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _dump(metadata: dict[str, Any]) -> str:
    return json.dumps(metadata, default=str)


def _load(raw: str | None) -> dict[str, Any]:
    return json.loads(raw) if raw else {}


def _row_to_session(row: sqlite3.Row) -> Session:
    return Session(
        id=uuid.UUID(row["id"]),
        title=row["title"],
        created_at=_iso_to_dt(row["created_at"]),
        updated_at=_iso_to_dt(row["updated_at"]),
        active=bool(row["active"]),
        metadata=_load(row["metadata_json"]),
    )


def _row_to_conversation(row: sqlite3.Row) -> Conversation:
    return Conversation(
        id=uuid.UUID(row["id"]),
        session_id=uuid.UUID(row["session_id"]),
        created_at=_iso_to_dt(row["created_at"]),
        updated_at=_iso_to_dt(row["updated_at"]),
        metadata=_load(row["metadata_json"]),
    )


def _row_to_message(row: sqlite3.Row) -> ConversationMessage:
    return ConversationMessage(
        id=uuid.UUID(row["id"]),
        conversation_id=uuid.UUID(row["conversation_id"]),
        role=MessageRole(row["role"]),
        content=row["content"],
        sequence=row["sequence"],
        created_at=_iso_to_dt(row["created_at"]),
        metadata=_load(row["metadata_json"]),
    )


class _BaseRepository:
    """`db_path=None` uses the configured project database; tests pass a
    temporary path. Every operation opens a short-lived connection via
    `connection_scope` (see app.storage.database)."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = db_path

    def _connect(self):
        return connection_scope(self._db_path)


class SessionRepository(_BaseRepository):
    def create_session(self, session: Session) -> Session:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO sessions (id, title, created_at, updated_at, active, metadata_json)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(session.id),
                        session.title,
                        _dt_to_iso(session.created_at),
                        _dt_to_iso(session.updated_at),
                        1 if session.active else 0,
                        _dump(session.metadata),
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to create session {session.id}: {exc}") from exc
        return session

    def get_session(self, session_id: uuid.UUID) -> Session:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE id = ?", (str(session_id),)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get session {session_id}: {exc}") from exc
        if row is None:
            raise SessionNotFoundError(session_id)
        return _row_to_session(row)

    def update_session(self, session: Session) -> Session:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET title = ?, created_at = ?, updated_at = ?, active = ?,"
                    " metadata_json = ? WHERE id = ?",
                    (
                        session.title,
                        _dt_to_iso(session.created_at),
                        _dt_to_iso(session.updated_at),
                        1 if session.active else 0,
                        _dump(session.metadata),
                        str(session.id),
                    ),
                )
                if cur.rowcount == 0:
                    raise SessionNotFoundError(session.id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to update session {session.id}: {exc}") from exc
        return session

    def deactivate_session(self, session_id: uuid.UUID) -> Session:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET active = 0, updated_at = ? WHERE id = ?",
                    (_dt_to_iso(utcnow()), str(session_id)),
                )
                if cur.rowcount == 0:
                    raise SessionNotFoundError(session_id)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to deactivate session {session_id}: {exc}") from exc
        return self.get_session(session_id)

    def list_sessions(self, active_only: bool = False, limit: int | None = None) -> list[Session]:
        """Most recently updated first."""
        query = "SELECT * FROM sessions"
        params: list[object] = []
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY updated_at DESC, created_at DESC, rowid DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        try:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to list sessions: {exc}") from exc
        return [_row_to_session(r) for r in rows]


class ConversationRepository(_BaseRepository):
    """Conversations are append-only history containers: there is
    deliberately no delete/deactivate here. Closing a session is what
    stops new writes (enforced by ConversationManager)."""

    def create_conversation(self, conversation: Conversation) -> Conversation:
        try:
            with self._connect() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM sessions WHERE id = ?", (str(conversation.session_id),)
                ).fetchone()
                if exists is None:
                    raise SessionNotFoundError(conversation.session_id)
                conn.execute(
                    "INSERT INTO conversations (id, session_id, created_at, updated_at, metadata_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        str(conversation.id),
                        str(conversation.session_id),
                        _dt_to_iso(conversation.created_at),
                        _dt_to_iso(conversation.updated_at),
                        _dump(conversation.metadata),
                    ),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to create conversation {conversation.id}: {exc}") from exc
        return conversation

    def get_conversation(self, conversation_id: uuid.UUID) -> Conversation:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM conversations WHERE id = ?", (str(conversation_id),)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get conversation {conversation_id}: {exc}") from exc
        if row is None:
            raise ConversationNotFoundError(conversation_id)
        return _row_to_conversation(row)

    def update_conversation(self, conversation: Conversation) -> Conversation:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE conversations SET updated_at = ?, metadata_json = ? WHERE id = ?",
                    (
                        _dt_to_iso(conversation.updated_at),
                        _dump(conversation.metadata),
                        str(conversation.id),
                    ),
                )
                if cur.rowcount == 0:
                    raise ConversationNotFoundError(conversation.id)
        except sqlite3.Error as exc:
            raise RepositoryError(
                f"Failed to update conversation {conversation.id}: {exc}"
            ) from exc
        return conversation

    def list_conversations(self, session_id: uuid.UUID) -> list[Conversation]:
        """Oldest first."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM conversations WHERE session_id = ?"
                    " ORDER BY created_at ASC, rowid ASC",
                    (str(session_id),),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to list conversations: {exc}") from exc
        return [_row_to_conversation(r) for r in rows]


class MessageRepository(_BaseRepository):
    """Ordering is by `sequence` only, assigned atomically on append."""

    def append_message(
        self,
        conversation_id: uuid.UUID,
        role: MessageRole,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> ConversationMessage:
        """Append one message and return it with its assigned sequence.

        The next sequence is computed INSIDE the INSERT statement
        (`COALESCE(MAX(sequence), 0) + 1`), so allocation is atomic with
        the write; the UNIQUE(conversation_id, sequence) index is a
        backstop. The model is validated (e.g. TOOL metadata) BEFORE any
        write. The parent conversation's and session's `updated_at` are
        touched in the same transaction.
        """
        candidate = ConversationMessage(
            conversation_id=conversation_id,
            role=role,
            content=content,
            sequence=1,  # provisional; real value assigned below
            metadata=metadata or {},
        )
        try:
            with self._connect() as conn:
                conv = conn.execute(
                    "SELECT session_id FROM conversations WHERE id = ?", (str(conversation_id),)
                ).fetchone()
                if conv is None:
                    raise ConversationNotFoundError(conversation_id)
                now = _dt_to_iso(candidate.created_at)
                conn.execute(
                    "INSERT INTO messages"
                    " (id, conversation_id, role, content, sequence, created_at, metadata_json)"
                    " SELECT ?, ?, ?, ?, COALESCE(MAX(sequence), 0) + 1, ?, ?"
                    " FROM messages WHERE conversation_id = ?",
                    (
                        str(candidate.id),
                        str(conversation_id),
                        candidate.role.value,
                        candidate.content,
                        now,
                        _dump(candidate.metadata),
                        str(conversation_id),
                    ),
                )
                seq = conn.execute(
                    "SELECT sequence FROM messages WHERE id = ?", (str(candidate.id),)
                ).fetchone()["sequence"]
                conn.execute(
                    "UPDATE conversations SET updated_at = ? WHERE id = ?",
                    (now, str(conversation_id)),
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = ? WHERE id = ?", (now, conv["session_id"])
                )
        except sqlite3.Error as exc:
            raise RepositoryError(
                f"Failed to append message to conversation {conversation_id}: {exc}"
            ) from exc
        return candidate.model_copy(update={"sequence": seq})

    def get_message(self, message_id: uuid.UUID) -> ConversationMessage:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM messages WHERE id = ?", (str(message_id),)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get message {message_id}: {exc}") from exc
        if row is None:
            raise MessageNotFoundError(message_id)
        return _row_to_message(row)

    def list_messages(self, conversation_id: uuid.UUID) -> list[ConversationMessage]:
        """Every message, oldest -> newest by sequence."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM messages WHERE conversation_id = ? ORDER BY sequence ASC",
                    (str(conversation_id),),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to list messages: {exc}") from exc
        return [_row_to_message(r) for r in rows]

    def get_recent_messages(
        self, conversation_id: uuid.UUID, limit: int
    ) -> list[ConversationMessage]:
        """The last `limit` messages, returned oldest -> newest."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM (SELECT * FROM messages WHERE conversation_id = ?"
                    " ORDER BY sequence DESC LIMIT ?) ORDER BY sequence ASC",
                    (str(conversation_id), limit),
                ).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to get recent messages: {exc}") from exc
        return [_row_to_message(r) for r in rows]

    def count_messages(self, conversation_id: uuid.UUID) -> int:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM messages WHERE conversation_id = ?",
                    (str(conversation_id),),
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryError(f"Failed to count messages: {exc}") from exc
        return int(row["n"])

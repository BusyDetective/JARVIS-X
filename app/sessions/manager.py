from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any, Sequence

from app.config.settings import settings
from app.providers.schemas import ToolCall
from app.sessions.models import (
    Conversation,
    ConversationMessage,
    MessageRole,
    Session,
    utcnow,
)
from app.sessions.repository import (
    ConversationRepository,
    MessageRepository,
    SessionRepository,
)

logger = logging.getLogger(__name__)


class ConversationValidationError(Exception):
    """Message/conversation input failed ConversationManager validation."""


class SessionInactiveError(ConversationValidationError):
    def __init__(self, session_id: uuid.UUID) -> None:
        self.session_id = session_id
        super().__init__(f"Session {session_id} is inactive; it accepts no new messages")


def derive_session_title(text: str, max_length: int | None = None) -> str:
    """Deterministic title from a message: whitespace collapsed, truncated
    at a word boundary when possible, with an ellipsis. No LLM involved
    (a later phase may replace this with generated titles)."""
    limit = max_length if max_length is not None else settings.session_title_max_length
    collapsed = " ".join(text.split())
    if not collapsed:
        raise ValueError("cannot derive a title from blank text")
    if len(collapsed) <= limit:
        return collapsed
    cut = collapsed[: max(limit - 1, 1)]
    if " " in cut and collapsed[len(cut)] != " ":
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip() + "…"


class ConversationManager:
    """Conversation behavior + validation, above the repositories (no SQL).

    SYSTEM MESSAGES: `append_system_message` exists for explicit,
    conversation-specific system notes only. Nothing calls it
    automatically — the Orchestrator's system prompt is generated per run
    and is deliberately NOT persisted, so prompts can evolve without
    polluting history.

    Messages are never turned into memories here; MemoryManager stays
    independent.

    COMPACTION BOUNDARY: model-facing code reads history only through
    `get_history` / `get_recent_messages`. A future compactor can replace
    older messages with a summary behind these methods (or in the
    ContextManager) without touching persistence.
    """

    def __init__(
        self,
        conversation_repository: ConversationRepository,
        message_repository: MessageRepository,
        session_repository: SessionRepository,
        max_recent_messages: int | None = None,
    ) -> None:
        self.conversations = conversation_repository
        self.messages = message_repository
        self.sessions = session_repository
        self.max_recent_messages = (
            max_recent_messages if max_recent_messages is not None else settings.max_recent_messages
        )
        if self.max_recent_messages < 1:
            raise ValueError("max_recent_messages must be >= 1")

    # --- Conversations -----------------------------------------------------

    def create_conversation(
        self, session_id: uuid.UUID, metadata: dict[str, Any] | None = None
    ) -> Conversation:
        session = self.sessions.get_session(session_id)  # SessionNotFoundError if missing
        if not session.active:
            raise SessionInactiveError(session_id)
        return self.conversations.create_conversation(
            Conversation(session_id=session_id, metadata=metadata or {})
        )

    def get_conversation(self, conversation_id: uuid.UUID) -> Conversation:
        return self.conversations.get_conversation(conversation_id)

    def list_conversations(self, session_id: uuid.UUID) -> list[Conversation]:
        return self.conversations.list_conversations(session_id)

    def ensure_writable(self, conversation_id: uuid.UUID) -> Conversation:
        """Raises if the conversation doesn't exist or its session is
        inactive. Lets callers fail fast before causing side effects."""
        conversation = self.conversations.get_conversation(conversation_id)
        session = self.sessions.get_session(conversation.session_id)
        if not session.active:
            raise SessionInactiveError(session.id)
        return conversation

    # --- Appending ---------------------------------------------------------

    def append_user_message(
        self, conversation_id: uuid.UUID, content: str, metadata: dict[str, Any] | None = None
    ) -> ConversationMessage:
        self._require_text(content, "user")
        conversation = self.ensure_writable(conversation_id)
        message = self.messages.append_message(
            conversation_id, MessageRole.USER, content, dict(metadata or {})
        )
        self._maybe_title_session(conversation.session_id, content)
        return message

    def append_assistant_message(
        self,
        conversation_id: uuid.UUID,
        content: str | None,
        tool_calls: Sequence[ToolCall] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ConversationMessage:
        text = content or ""
        if not text.strip() and not tool_calls:
            raise ConversationValidationError(
                "assistant message needs content unless it carries tool calls"
            )
        meta = dict(metadata or {})
        if tool_calls:
            meta["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "provider_call_id": tc.provider_call_id,
                }
                for tc in tool_calls
            ]
        self.ensure_writable(conversation_id)
        return self.messages.append_message(conversation_id, MessageRole.ASSISTANT, text, meta)

    def append_tool_message(
        self,
        conversation_id: uuid.UUID,
        content: str,
        tool_call_id: str,
        tool_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> ConversationMessage:
        if not tool_call_id or not tool_call_id.strip():
            raise ConversationValidationError("tool message requires tool_call_id")
        if not tool_name or not tool_name.strip():
            raise ConversationValidationError("tool message requires tool_name")
        if content is None:
            raise ConversationValidationError("tool message content cannot be None")
        meta = {**(metadata or {}), "tool_call_id": tool_call_id, "tool_name": tool_name}
        self.ensure_writable(conversation_id)
        return self.messages.append_message(conversation_id, MessageRole.TOOL, content, meta)

    def append_system_message(
        self, conversation_id: uuid.UUID, content: str, metadata: dict[str, Any] | None = None
    ) -> ConversationMessage:
        self._require_text(content, "system")
        self.ensure_writable(conversation_id)
        return self.messages.append_message(
            conversation_id, MessageRole.SYSTEM, content, dict(metadata or {})
        )

    # --- Reading -----------------------------------------------------------

    def get_history(self, conversation_id: uuid.UUID) -> list[ConversationMessage]:
        """Full history, oldest -> newest."""
        self.conversations.get_conversation(conversation_id)
        return self.messages.list_messages(conversation_id)

    def get_recent_messages(
        self, conversation_id: uuid.UUID, limit: int | None = None
    ) -> list[ConversationMessage]:
        """Last `limit` messages (default: `max_recent_messages`), oldest
        -> newest. Exactly the window — nothing silently dropped inside it."""
        self.conversations.get_conversation(conversation_id)
        return self.messages.get_recent_messages(
            conversation_id, limit if limit is not None else self.max_recent_messages
        )

    def count_messages(self, conversation_id: uuid.UUID) -> int:
        self.conversations.get_conversation(conversation_id)
        return self.messages.count_messages(conversation_id)

    # --- Internals ---------------------------------------------------------

    @staticmethod
    def _require_text(content: str, kind: str) -> None:
        if content is None or not content.strip():
            raise ConversationValidationError(f"{kind} message content cannot be empty")

    def _maybe_title_session(self, session_id: uuid.UUID, first_text: str) -> None:
        """Untitled session -> title from the first user message. Cosmetic,
        so a failure here never fails the (already persisted) message."""
        try:
            session = self.sessions.get_session(session_id)
            if session.title is None:
                self.sessions.update_session(
                    session.model_copy(
                        update={"title": derive_session_title(first_text), "updated_at": utcnow()}
                    )
                )
        except Exception:  # noqa: BLE001
            logger.warning("conversation_manager: could not auto-title session=%s", session_id)


class SessionManager:
    """Session behavior above SessionRepository; conversation creation and
    retrieval delegate to ConversationManager (single owner of that logic)."""

    def __init__(
        self, repository: SessionRepository, conversation_manager: ConversationManager
    ) -> None:
        self.repository = repository
        self.conversation_manager = conversation_manager

    def create_session(
        self, title: str | None = None, metadata: dict[str, Any] | None = None
    ) -> Session:
        """`title=None` leaves the session untitled until its first user
        message, which derives one deterministically."""
        return self.repository.create_session(Session(title=title, metadata=metadata or {}))

    def get_session(self, session_id: uuid.UUID) -> Session:
        return self.repository.get_session(session_id)

    def rename_session(self, session_id: uuid.UUID, title: str) -> Session:
        if not title or not title.strip():
            raise ConversationValidationError("session title cannot be blank")
        session = self.repository.get_session(session_id)
        return self.repository.update_session(
            session.model_copy(update={"title": title.strip(), "updated_at": utcnow()})
        )

    def deactivate_session(self, session_id: uuid.UUID) -> Session:
        return self.repository.deactivate_session(session_id)

    def list_sessions(self, active_only: bool = False, limit: int | None = None) -> list[Session]:
        return self.repository.list_sessions(active_only=active_only, limit=limit)

    def create_conversation(
        self, session_id: uuid.UUID, metadata: dict[str, Any] | None = None
    ) -> Conversation:
        return self.conversation_manager.create_conversation(session_id, metadata)

    def list_conversations(self, session_id: uuid.UUID) -> list[Conversation]:
        return self.conversation_manager.list_conversations(session_id)

    def get_conversation(self, conversation_id: uuid.UUID) -> Conversation:
        return self.conversation_manager.get_conversation(conversation_id)


def build_session_services(
    db_path: Path | str | None = None,
) -> tuple[SessionManager, ConversationManager]:
    """Convenience wiring: one set of repositories on the same database,
    returning (SessionManager, ConversationManager)."""
    sessions = SessionRepository(db_path)
    conversation_manager = ConversationManager(
        ConversationRepository(db_path), MessageRepository(db_path), sessions
    )
    return SessionManager(sessions, conversation_manager), conversation_manager

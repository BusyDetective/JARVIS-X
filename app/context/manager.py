from __future__ import annotations

import logging
import uuid
from typing import Any

from app.config.settings import settings
from app.context.models import ContextBundle, ContextItem, ContextPriority, ContextSource
from app.memory.manager import MemoryManager
from app.memory.models import MemoryType
from app.providers.schemas import Message, ToolCall
from app.sessions.manager import ConversationManager
from app.sessions.models import ConversationMessage, MessageRole

logger = logging.getLogger(__name__)

# Deterministic mapping from a memory's importance to a context priority
# tier. Memory is supplementary by design — even an important memory tops
# out at HIGH, never CRITICAL (system instructions own that tier), and
# "recent user/assistant conversation should generally outrank low-priority
# memories" (per the design brief) falls out naturally: conversation items
# typically carry NORMAL/HIGH priority from their caller, and the assembly
# order in build_context places conversation before memory regardless of
# tie-breaking within a priority tier.
_MEMORY_IMPORTANCE_HIGH = 0.8
_MEMORY_IMPORTANCE_LOW = 0.4


def _priority_for_memory_importance(importance: float) -> ContextPriority:
    if importance >= _MEMORY_IMPORTANCE_HIGH:
        return ContextPriority.HIGH
    if importance >= _MEMORY_IMPORTANCE_LOW:
        return ContextPriority.NORMAL
    return ContextPriority.LOW


class ContextManager:
    """Assembles a provider-agnostic ContextBundle for one model
    invocation, from conversation/task/tool context plus (optionally)
    selected long-term memory.

    Responsibilities ONLY: combine, order, assign priority to what it
    creates itself (system-instruction and memory items — everything else
    arrives already tagged by its caller), deduplicate, and enforce the
    configured item-count limits. It does NOT:

      - call any AIProvider or know any provider-specific API — it only
        ever produces ContextItem/ContextBundle (and, via the module-level
        `context_bundle_to_messages` helper, the same normalized `Message`
        type the orchestrator already uses) — never a Gemini/OpenRouter/
        Ollama-specific request object;
      - touch SQLite or any database — it depends on an injected
        `MemoryManager` for memory retrieval, never a repository directly;
      - attempt to solve prompt injection — TOOL-sourced items are kept
        structurally distinct (their own ContextSource, surfaced
        separately in the assembled order) but their content is not
        otherwise sanitized or trusted differently, consistent with the
        orchestrator's existing "data, not instructions" boundary.
    """

    def __init__(
        self,
        memory_manager: MemoryManager | None = None,
        conversation_manager: ConversationManager | None = None,
        max_conversation_items: int | None = None,
        max_memory_items: int | None = None,
        max_task_context_items: int | None = None,
        max_total_items: int | None = None,
    ) -> None:
        self.memory_manager = memory_manager
        # Optional source of persisted conversation history. ContextManager
        # reads it ONLY through ConversationManager — never SQLite.
        self.conversation_manager = conversation_manager
        self.max_conversation_items = (
            max_conversation_items
            if max_conversation_items is not None
            else settings.max_conversation_context_items
        )
        self.max_memory_items = (
            max_memory_items if max_memory_items is not None else settings.max_memory_context_items
        )
        self.max_task_context_items = (
            max_task_context_items
            if max_task_context_items is not None
            else settings.max_task_context_items
        )
        self.max_total_items = (
            max_total_items if max_total_items is not None else settings.max_total_context_items
        )

    def build_context(
        self,
        *,
        system_instructions: str | None = None,
        conversation_items: list[ContextItem] | None = None,
        task_items: list[ContextItem] | None = None,
        tool_items: list[ContextItem] | None = None,
        memory_query: str | None = None,
        memory_type: MemoryType | None = None,
        conversation_id: uuid.UUID | None = None,
    ) -> ContextBundle:
        """Build one ContextBundle.

        `conversation_id` (requires an injected ConversationManager) pulls
        the most recent `max_conversation_items` persisted messages of that
        conversation, oldest -> newest, as conversation items; any
        explicit `conversation_items` are appended after them. Callers
        must not pass an already-persisted message again (that would
        duplicate it). Persisted items keep full tool linkage in their
        metadata; see `context_bundle_to_messages`.

        Assembly order (also the tie-break order when trimming leaves
        multiple items in the same priority tier — earlier blocks are
        preferred): SYSTEM, then CONVERSATION, then TASK, then TOOL, then
        MEMORY. System instructions are always CRITICAL. Memory priority
        is derived from each memory's importance (see
        `_priority_for_memory_importance`); every other item keeps
        whatever priority its caller set (default NORMAL).
        """
        system_block: list[ContextItem] = []
        if system_instructions:
            system_block.append(
                ContextItem(
                    content=system_instructions,
                    source=ContextSource.SYSTEM,
                    priority=ContextPriority.CRITICAL,
                )
            )

        history_items: list[ContextItem] = []
        if conversation_id is not None:
            if self.conversation_manager is None:
                raise ValueError("conversation_id given but no conversation_manager is configured")
            history_items = conversation_messages_to_items(
                self.conversation_manager.get_recent_messages(
                    conversation_id, limit=self.max_conversation_items
                )
            )
        conversation_block = (history_items + list(conversation_items or []))[
            -self.max_conversation_items :
        ]
        task_block = list(task_items or [])[-self.max_task_context_items :]
        tool_block = list(tool_items or [])

        memory_block: list[ContextItem] = []
        if self.memory_manager is not None and memory_query:
            selected = self.memory_manager.select_relevant_memories(
                memory_query, memory_type=memory_type, limit=self.max_memory_items
            )
            for memory in selected:
                memory_block.append(
                    ContextItem(
                        content=memory.content,
                        source=ContextSource.MEMORY,
                        priority=_priority_for_memory_importance(memory.importance),
                        metadata={"memory_id": str(memory.id), "memory_type": memory.memory_type.value},
                    )
                )
                # Using a memory in a built context counts as accessing it.
                # Best-effort: a persistence hiccup here must not break
                # context assembly.
                try:
                    self.memory_manager.mark_accessed(memory.id)
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "context_manager: failed to mark memory=%s as accessed", memory.id
                    )

        assembled = system_block + conversation_block + task_block + tool_block + memory_block
        deduplicated = self._deduplicate(assembled)
        trimmed = self._trim_to_total(deduplicated)
        return ContextBundle(items=trimmed)

    @staticmethod
    def _deduplicate(items: list[ContextItem]) -> list[ContextItem]:
        """Drops later items whose (source, content) exactly matches an
        earlier one, keeping the first occurrence — preserves ordering.
        Items backed by a persisted message (metadata['message_id']) are
        never deduplicated: two genuine turns ("ok", "ok") or two identical
        tool outputs for different calls are distinct history."""
        seen: set[tuple[ContextSource, str]] = set()
        result: list[ContextItem] = []
        for item in items:
            if "message_id" in item.metadata:
                result.append(item)
                continue
            key = (item.source, item.content.strip())
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    def _trim_to_total(self, items: list[ContextItem]) -> list[ContextItem]:
        """If `items` exceeds `max_total_items`, drop items from the
        lowest-priority tier first (LOW, then NORMAL, then HIGH, then
        CRITICAL as an absolute last resort), removing that tier's LAST
        item each time — i.e. within a tier, earlier items are kept over
        later ones. Preserves the original relative order of whatever
        survives.
        """
        if len(items) <= self.max_total_items:
            return items

        remaining = list(items)
        drop_order = [
            ContextPriority.LOW,
            ContextPriority.NORMAL,
            ContextPriority.HIGH,
            ContextPriority.CRITICAL,
        ]
        for tier in drop_order:
            while len(remaining) > self.max_total_items:
                idx = _last_index_with_priority(remaining, tier)
                if idx is None:
                    break
                del remaining[idx]
            if len(remaining) <= self.max_total_items:
                break
        return remaining


def _last_index_with_priority(items: list[ContextItem], tier: ContextPriority) -> int | None:
    for idx in range(len(items) - 1, -1, -1):
        if items[idx].priority == tier:
            return idx
    return None


# --- Persisted ConversationMessage -> ContextItem ---------------------------

_ROLE_TO_SOURCE: dict[MessageRole, ContextSource] = {
    MessageRole.SYSTEM: ContextSource.SYSTEM,
    MessageRole.USER: ContextSource.USER,
    MessageRole.ASSISTANT: ContextSource.ASSISTANT,
    MessageRole.TOOL: ContextSource.TOOL,
}


def conversation_messages_to_items(messages: list[ConversationMessage]) -> list[ContextItem]:
    """Maps persisted messages (oldest -> newest) to ContextItems, keeping
    order and every message. Tool linkage travels in item metadata. The
    most recent USER message is HIGH priority, everything else NORMAL.
    Messages with blank content are skipped (ContextItem forbids them),
    except assistant tool-call turns, which get a placeholder flagged
    `empty_content` that `context_bundle_to_messages` turns back into
    content=None."""
    last_user_seq = max(
        (m.sequence for m in messages if m.role == MessageRole.USER), default=None
    )
    items: list[ContextItem] = []
    for m in messages:
        meta: dict[str, Any] = {
            "message_id": str(m.id),
            "message_sequence": m.sequence,
            "message_role": m.role.value,
        }
        content = m.content
        if m.role == MessageRole.TOOL:
            meta["tool_call_id"] = m.metadata["tool_call_id"]
            meta["tool_name"] = m.metadata["tool_name"]
        if m.role == MessageRole.ASSISTANT and m.metadata.get("tool_calls"):
            meta["tool_calls"] = m.metadata["tool_calls"]
            if not content.strip():
                names = ", ".join(str(c.get("name")) for c in m.metadata["tool_calls"])
                content = f"[assistant requested tools: {names}]"
                meta["empty_content"] = True
        if not content.strip():
            logger.warning("context_manager: skipping blank message=%s", m.id)
            continue
        items.append(
            ContextItem(
                content=content,
                source=_ROLE_TO_SOURCE[m.role],
                priority=(
                    ContextPriority.HIGH
                    if m.sequence == last_user_seq
                    else ContextPriority.NORMAL
                ),
                created_at=m.created_at,
                metadata=meta,
            )
        )
    return items


# --- ContextBundle -> normalized Message conversion -------------------------
#
# Lives here (not in the orchestrator) because it only ever produces the
# SAME normalized `Message` type the orchestrator already builds itself —
# never a provider-specific object — so it stays within the context
# layer's "provider-neutral representation" boundary (section 14). The
# orchestrator's OWN tool-call-loop message construction (assistant
# tool_calls / tool-result messages) is entirely separate from this and
# untouched by it — this helper only produces the SEED messages for a run,
# before the agent loop begins.

_SOURCE_TO_ROLE: dict[ContextSource, str] = {
    ContextSource.SYSTEM: "system",
    ContextSource.TASK: "system",
    ContextSource.MEMORY: "system",
    ContextSource.USER: "user",
    ContextSource.ASSISTANT: "assistant",
    # Defensive fallback only: TOOL-sourced items are not expected in a
    # SEED context bundle (the orchestrator's tool-call loop handles
    # role="tool" messages itself, with proper tool_call_id linkage, which
    # a bare ContextItem doesn't carry).
    ContextSource.TOOL: "system",
}

_SOURCE_LABEL: dict[ContextSource, str] = {
    ContextSource.TASK: "[Task context] ",
    ContextSource.MEMORY: "[Memory] ",
    ContextSource.TOOL: "[Tool output] ",
}


def _parse_tool_calls(raw: Any) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for entry in raw if isinstance(raw, list) else []:
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and isinstance(entry.get("name"), str)
            and isinstance(entry.get("arguments"), dict)
        ):
            calls.append(
                ToolCall(
                    id=entry["id"],
                    name=entry["name"],
                    arguments=entry["arguments"],
                    provider_call_id=entry.get("provider_call_id"),
                )
            )
    return calls


def _repair_tool_linkage(messages: list[Message]) -> list[Message]:
    """Providers reject tool results with no matching preceding call, and
    tool calls with no result. A history window (or an interrupted run,
    e.g. max_tool_calls hit mid-batch) can produce both, so: drop TOOL
    messages whose call wasn't declared earlier, then strip tool calls that
    never got a result (dropping the assistant turn if that leaves it
    empty). A no-op when no tool-role messages or tool calls are present.
    """
    declared: set[str] = set()
    answered: set[str] = set()
    kept: list[Message] = []
    for msg in messages:
        if msg.role == "assistant" and msg.tool_calls:
            declared.update(tc.id for tc in msg.tool_calls)
        elif msg.role == "tool":
            if msg.tool_call_id not in declared or msg.tool_call_id in answered:
                logger.warning("context_manager: dropping orphan tool message %s", msg.tool_call_id)
                continue
            answered.add(msg.tool_call_id)
        kept.append(msg)

    result: list[Message] = []
    for msg in kept:
        if msg.role == "assistant" and msg.tool_calls:
            answered_calls = [tc for tc in msg.tool_calls if tc.id in answered]
            if len(answered_calls) != len(msg.tool_calls):
                logger.warning("context_manager: stripping unanswered tool calls")
                if not answered_calls and not (msg.content or "").strip():
                    continue
                msg = Message(role="assistant", content=msg.content, tool_calls=answered_calls)
        result.append(msg)
    return result


def context_bundle_to_messages(bundle: ContextBundle) -> list[Message]:
    """Converts a ContextBundle into the normalized `Message` list a
    ModelRouter/AIProvider already understands. See the module-level
    comment above for the source->role mapping and its scope.

    Items built from persisted conversation history carry linkage metadata
    and become real tool-linked messages: TOOL items with
    tool_call_id/tool_name -> role="tool" (no label), ASSISTANT items with
    tool_calls -> assistant Messages with ToolCalls. Items without that
    metadata behave exactly as before. Tool linkage is repaired at the end
    (see `_repair_tool_linkage`)."""
    messages: list[Message] = []
    for item in bundle.items:
        meta = item.metadata
        if (
            item.source == ContextSource.TOOL
            and isinstance(meta.get("tool_call_id"), str)
            and isinstance(meta.get("tool_name"), str)
        ):
            messages.append(
                Message(
                    role="tool",
                    content=item.content,
                    tool_call_id=meta["tool_call_id"],
                    name=meta["tool_name"],
                )
            )
            continue
        if item.source == ContextSource.ASSISTANT and meta.get("tool_calls"):
            messages.append(
                Message(
                    role="assistant",
                    content=None if meta.get("empty_content") else item.content,
                    tool_calls=_parse_tool_calls(meta["tool_calls"]),
                )
            )
            continue
        role = _SOURCE_TO_ROLE[item.source]
        label = _SOURCE_LABEL.get(item.source, "")
        messages.append(Message(role=role, content=f"{label}{item.content}"))
    return _repair_tool_linkage(messages)

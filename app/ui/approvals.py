"""Web-backed ApprovalHandler. This is the SAME injection point the Orchestrator already uses for every
CONFIRM/DANGEROUS tool (including Phase 8's promote_release); the dashboard adds no second approval path.
A pending request is resolved only by an authenticated dashboard decision — never by voice, model output,
page content, or a timeout (a timeout DENIES)."""
from __future__ import annotations

import asyncio
import contextvars
import logging
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.security.approval import ApprovalHandler
from app.security.permissions import PermissionLevel
from app.security.untrusted import redact_text

logger = logging.getLogger(__name__)

current_run_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("jx_current_run_id", default=None)
MAX_VALUE_CHARS = 300


class ApprovalNotFoundError(Exception):
    pass


class ApprovalAlreadyDecidedError(Exception):
    pass


def summarize_arguments(arguments: dict[str, Any]) -> dict[str, str]:
    """Bounded, secret-redacted rendering of tool arguments for the approval card."""
    out: dict[str, str] = {}
    for k, v in list(arguments.items())[:20]:
        text = redact_text(str(v))[0]
        out[str(k)[:60]] = text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"
    return out


@dataclass
class PendingApproval:
    id: str
    run_id: str | None
    tool_name: str
    level: PermissionLevel
    arguments: dict[str, str]
    context: dict[str, Any] | None
    created_at: float
    expires_at: float
    future: asyncio.Future[bool] = field(repr=False, default=None)  # type: ignore[assignment]
    decision: str | None = None  # approved | denied | expired
    decided_at: float | None = None

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "run_id": self.run_id, "tool_name": self.tool_name, "level": self.level.value,
                "arguments": self.arguments, "context": self.context, "created_at": self.created_at,
                "expires_in": max(0, round(self.expires_at - time.time())), "decision": self.decision,
                "requires_acknowledgement": self.level == PermissionLevel.DANGEROUS}


class WebApprovalHandler(ApprovalHandler):
    def __init__(self, timeout_seconds: float = 300.0,
                 describers: dict[str, Callable[[str, dict[str, Any]], dict[str, Any] | None]] | None = None,
                 history_size: int = 50) -> None:
        self.timeout_seconds = timeout_seconds
        self.describers = describers if describers is not None else {}
        self._pending: dict[str, PendingApproval] = {}
        self._history: deque[PendingApproval] = deque(maxlen=history_size)

    def add_describer(self, tool_prefix: str, fn: Callable[[str, dict[str, Any]], dict[str, Any] | None]) -> None:
        self.describers[tool_prefix] = fn

    async def approve(self, tool_name: str, arguments: dict[str, Any], level: PermissionLevel) -> bool:
        context = None
        for prefix, fn in self.describers.items():
            if tool_name.startswith(prefix):
                try:
                    context = fn(tool_name, arguments)
                except Exception:  # noqa: BLE001
                    context = None
        now = time.time()
        item = PendingApproval(
            id=secrets.token_urlsafe(9), run_id=current_run_id.get(), tool_name=tool_name, level=level,
            arguments=summarize_arguments(arguments), context=context, created_at=now,
            expires_at=now + self.timeout_seconds, future=asyncio.get_running_loop().create_future())
        self._pending[item.id] = item
        logger.info("approval requested id=%s tool=%s level=%s", item.id, tool_name, level.value)
        try:
            approved = await asyncio.wait_for(asyncio.shield(item.future), self.timeout_seconds)
        except asyncio.TimeoutError:
            item.decision = "expired"
            approved = False
        except asyncio.CancelledError:
            item.decision = "denied"
            raise
        finally:
            if not item.future.done():
                item.future.cancel()
            item.decided_at = time.time()
            self._pending.pop(item.id, None)
            self._history.append(item)
            logger.info("approval resolved id=%s tool=%s decision=%s", item.id, tool_name, item.decision)
        return approved

    def decide(self, approval_id: str, approve: bool, acknowledged: bool = False) -> PendingApproval:
        item = self._pending.get(approval_id)
        if item is None:
            if any(h.id == approval_id for h in self._history):
                raise ApprovalAlreadyDecidedError(approval_id)
            raise ApprovalNotFoundError(approval_id)
        if approve and item.level == PermissionLevel.DANGEROUS and not acknowledged:
            raise PermissionError("DANGEROUS approvals require explicit acknowledgement")
        if item.future.done():
            raise ApprovalAlreadyDecidedError(approval_id)
        item.decision = "approved" if approve else "denied"
        item.future.set_result(approve)
        return item

    def pending(self, run_id: str | None = None) -> list[PendingApproval]:
        items = [p for p in self._pending.values() if not p.future.done()]
        return [p for p in items if run_id is None or p.run_id == run_id]

    def history(self) -> list[PendingApproval]:
        return list(self._history)

    def deny_all(self) -> None:
        for item in list(self._pending.values()):
            if not item.future.done():
                item.decision = "denied"
                item.future.set_result(False)

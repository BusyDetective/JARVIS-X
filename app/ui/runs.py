"""Runs the real Orchestrator in the background so the dashboard stays responsive and tool activity can be
read from the persisted conversation while it runs. (Orchestrator.run() has no event hooks, so there is no
token streaming; see README.)"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from app.security.untrusted import redact_text
from app.ui.approvals import WebApprovalHandler, current_run_id

logger = logging.getLogger(__name__)
MAX_ERROR_CHARS = 300
MAX_TOOL_SUMMARY = 40


class RunConflictError(Exception):
    """A run is already active in this conversation, or the concurrency limit is reached."""


@dataclass
class Run:
    id: str
    conversation_id: str
    state: str = "running"  # running | awaiting_approval | completed | failed
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    status: str | None = None  # TaskStatus value
    final_response: str | None = None
    error: str | None = None
    provider: str | None = None
    model: str | None = None
    iterations: int = 0
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class RunManager:
    def __init__(self, orchestrator: Any, approvals: WebApprovalHandler, max_concurrent: int = 4,
                 history_size: int = 100) -> None:
        self.orchestrator = orchestrator
        self.approvals = approvals
        self.max_concurrent = max_concurrent
        self._runs: "OrderedDict[str, Run]" = OrderedDict()
        self._tasks: dict[str, asyncio.Task] = {}
        self._history_size = history_size

    def active_for(self, conversation_id: str) -> Run | None:
        for r in self._runs.values():
            if r.conversation_id == conversation_id and r.finished_at is None:
                return r
        return None

    def active_count(self) -> int:
        return sum(1 for r in self._runs.values() if r.finished_at is None)

    def start(self, conversation_id: uuid.UUID, text: str) -> Run:
        cid = str(conversation_id)
        if self.active_for(cid) is not None:
            raise RunConflictError("a run is already active in this conversation")
        if self.active_count() >= self.max_concurrent:
            raise RunConflictError("too many concurrent runs")
        run = Run(id=secrets.token_urlsafe(9), conversation_id=cid)
        self._runs[run.id] = run
        while len(self._runs) > self._history_size:
            oldest_id, oldest = next(iter(self._runs.items()))
            if oldest.finished_at is None:
                break
            self._runs.pop(oldest_id)
        self._tasks[run.id] = asyncio.create_task(self._execute(run, conversation_id, text))
        return run

    async def _execute(self, run: Run, conversation_id: uuid.UUID, text: str) -> None:
        token = current_run_id.set(run.id)
        try:
            result = await self.orchestrator.run(text, conversation_id)
            run.status = getattr(result.status, "value", str(result.status))
            run.final_response = result.final_response
            run.provider, run.model, run.iterations = result.provider, result.model, result.iterations
            run.error = redact_text(result.error)[0][:MAX_ERROR_CHARS] if result.error else None
            run.tool_calls = [
                {"name": t.name, "success": t.success,
                 "error": redact_text(t.error)[0][:MAX_ERROR_CHARS] if t.error else None}
                for t in result.tool_calls[:MAX_TOOL_SUMMARY]]
            run.state = "completed" if run.status == "completed" else "failed"
        except asyncio.CancelledError:
            run.state, run.error = "failed", "run cancelled (shutdown)"
            raise
        except Exception as exc:  # noqa: BLE001 — never leak internals; details only in server logs by type
            logger.error("run %s failed: %s", run.id, type(exc).__name__)
            run.state, run.error = "failed", "the run failed due to an internal error"
        finally:
            run.finished_at = time.time()
            current_run_id.reset(token)
            self._tasks.pop(run.id, None)

    def get(self, run_id: str) -> Run | None:
        run = self._runs.get(run_id)
        if run is not None and run.finished_at is None:
            run.state = "awaiting_approval" if self.approvals.pending(run.id) else "running"
        return run

    def for_conversation(self, conversation_id: str, limit: int = 10) -> list[Run]:
        runs = [self.get(r.id) for r in self._runs.values() if r.conversation_id == conversation_id]
        return [r for r in runs if r][-limit:]

    async def shutdown(self) -> None:
        self.approvals.deny_all()
        for t in list(self._tasks.values()):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

from __future__ import annotations

import logging
import uuid

from app.improvement.repository import AuditEvent, ImprovementRepository
from app.security.untrusted import redact_text

logger = logging.getLogger(__name__)
MAX_DETAIL_CHARS = 500


class AuditLog:
    """Append-oriented audit trail of improvement lifecycle actions. Detail
    text is redacted and capped; callers pass short status strings, never
    source code, logs or credentials."""

    def __init__(self, repository: ImprovementRepository) -> None:
        self._repo = repository

    def record(
        self, improvement_id: uuid.UUID, action: str, actor: str, result: str,
        candidate_id: uuid.UUID | None = None, risk: str | None = None, detail: str | None = None,
    ) -> None:
        text = None
        if detail:
            text, _ = redact_text(" ".join(detail.split())[:MAX_DETAIL_CHARS])
        safe_actor, _ = redact_text(actor[:100])
        self._repo.append_event(AuditEvent(
            improvement_id=improvement_id, candidate_id=candidate_id, action=action[:60], actor=safe_actor,
            risk=risk, result=result[:60], detail=text))
        logger.info("improvement_audit: id=%s action=%s result=%s risk=%s", improvement_id, action, result, risk)

    def events(self, improvement_id: uuid.UUID) -> list[AuditEvent]:
        return self._repo.list_events(improvement_id)

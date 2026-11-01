from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from app.improvement.errors import ImprovementError, ImprovementNotFoundError
from app.improvement.models import ImprovementRun
from app.storage.database import connection_scope


class AuditEvent(BaseModel):
    id: int | None = None
    improvement_id: uuid.UUID
    candidate_id: uuid.UUID | None = None
    action: str
    actor: str
    risk: str | None = None
    result: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detail: str | None = None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class ImprovementRepository:
    """Persistence for improvement runs (metadata JSON) and the append-only
    audit trail. No update/delete exists for events, and database triggers
    refuse them as well. Source code, secrets and raw logs are never stored."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = db_path

    def _connect(self):
        return connection_scope(self._db_path)

    def create_run(self, run: ImprovementRun) -> ImprovementRun:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO improvement_runs (id, state, goal, requested_by, risk_level, mode, candidate_id,"
                    " base_version, created_at, updated_at, data_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    self._row(run))
        except sqlite3.Error as exc:
            raise ImprovementError(f"could not store improvement run ({type(exc).__name__})") from exc
        return run

    def update_run(self, run: ImprovementRun) -> ImprovementRun:
        row = self._row(run)
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE improvement_runs SET state=?, goal=?, requested_by=?, risk_level=?, mode=?, candidate_id=?,"
                    " base_version=?, updated_at=?, data_json=? WHERE id=?",
                    (row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[9], row[10], row[0]))
                if cur.rowcount == 0:
                    raise ImprovementNotFoundError(f"improvement {run.id} not found")
        except sqlite3.Error as exc:
            raise ImprovementError(f"could not update improvement run ({type(exc).__name__})") from exc
        return run

    def get_run(self, improvement_id: uuid.UUID) -> ImprovementRun:
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT data_json FROM improvement_runs WHERE id = ?", (str(improvement_id),)).fetchone()
        except sqlite3.Error as exc:
            raise ImprovementError(f"could not read improvement run ({type(exc).__name__})") from exc
        if row is None:
            raise ImprovementNotFoundError(f"improvement {improvement_id} not found")
        return ImprovementRun.model_validate_json(row["data_json"])

    def list_runs(self, limit: int = 50) -> list[ImprovementRun]:
        with self._connect() as conn:
            rows = conn.execute("SELECT data_json FROM improvement_runs ORDER BY created_at DESC, rowid DESC LIMIT ?",
                                (max(1, min(limit, 500)),)).fetchall()
        return [ImprovementRun.model_validate_json(r["data_json"]) for r in rows]

    def append_event(self, event: AuditEvent) -> int:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO improvement_events (improvement_id, candidate_id, action, actor, risk, result, timestamp, detail)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.improvement_id), str(event.candidate_id) if event.candidate_id else None, event.action,
                     event.actor, event.risk, event.result, _iso(event.timestamp), event.detail))
                return int(cur.lastrowid)
        except sqlite3.Error as exc:
            raise ImprovementError(f"could not append audit event ({type(exc).__name__})") from exc

    def list_events(self, improvement_id: uuid.UUID) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM improvement_events WHERE improvement_id = ? ORDER BY id ASC",
                                (str(improvement_id),)).fetchall()
        return [AuditEvent(id=r["id"], improvement_id=uuid.UUID(r["improvement_id"]),
                           candidate_id=uuid.UUID(r["candidate_id"]) if r["candidate_id"] else None,
                           action=r["action"], actor=r["actor"], risk=r["risk"], result=r["result"],
                           timestamp=datetime.fromisoformat(r["timestamp"]), detail=r["detail"]) for r in rows]

    @staticmethod
    def _row(run: ImprovementRun):
        prop = run.proposal
        return (str(run.id), run.state.value, run.request.goal, run.request.requested_by,
                run.risk_level.value if run.risk_level else None, prop.mode.value if prop else None,
                str(run.candidate.id) if run.candidate else None,
                prop.base_version if prop else None, _iso(run.created_at), _iso(run.updated_at), run.model_dump_json())

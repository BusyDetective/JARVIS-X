"""Opening a Phase 3 database must keep all data and add the new tables."""
from __future__ import annotations

import sqlite3

from app.memory.repository import MemoryRepository
from app.sessions.manager import build_session_services
from app.storage.database import connection_scope
from app.tasks.repository import TaskRepository

# Verbatim copy of the Phase 3 schema (no sessions/conversations/messages).
PHASE3_SCHEMA = """
CREATE TABLE tasks (id TEXT PRIMARY KEY, user_request TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, result TEXT, error TEXT);
CREATE TABLE task_runs (id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    iteration INTEGER NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL,
    provider TEXT, model TEXT, error TEXT);
CREATE TABLE tool_results (id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    task_run_id TEXT REFERENCES task_runs(id) ON DELETE SET NULL, created_at TEXT NOT NULL,
    tool_call_id TEXT NOT NULL, name TEXT NOT NULL, success INTEGER NOT NULL, result_json TEXT,
    error TEXT, arguments_json TEXT NOT NULL);
CREATE TABLE memories (id TEXT PRIMARY KEY, content TEXT NOT NULL, memory_type TEXT NOT NULL,
    importance REAL NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    last_accessed_at TEXT, source TEXT, metadata_json TEXT, active INTEGER NOT NULL);
"""


def _tables(path):
    c = sqlite3.connect(path)
    try:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        c.close()


def test_phase3_database_is_preserved_and_extended(tmp_path):
    db = tmp_path / "old.db"
    c = sqlite3.connect(db)
    c.executescript(PHASE3_SCHEMA)
    c.execute("INSERT INTO tasks VALUES ('00000000-0000-0000-0000-000000000001','do it','completed','2026-01-01T00:00:00+00:00',NULL,NULL,'ok',NULL)")
    c.execute("INSERT INTO task_runs VALUES ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001',1,'2026-01-01T00:00:00+00:00',NULL,'completed','p','m',NULL)")
    c.execute("INSERT INTO tool_results VALUES ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','2026-01-01T00:00:00+00:00','call_1','calc',1,'3',NULL,'{}')")
    c.execute("INSERT INTO memories VALUES ('00000000-0000-0000-0000-000000000004','likes tea','preference',0.5,'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',NULL,NULL,'{}',1)")
    c.commit()
    c.close()
    assert not {"sessions", "conversations", "messages"} & _tables(db)

    with connection_scope(db):
        pass
    with connection_scope(db):  # idempotent
        pass

    assert {"sessions", "conversations", "messages"} <= _tables(db)
    assert [t.user_request for t in TaskRepository(db).list_tasks()] == ["do it"]
    c = sqlite3.connect(db)
    assert c.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0] == 1
    assert c.execute("SELECT COUNT(*) FROM tool_results").fetchone()[0] == 1
    c.close()
    assert [m.content for m in MemoryRepository(db).list_memories()] == ["likes tea"]

    sm, cm = build_session_services(db)
    conv = sm.create_conversation(sm.create_session().id)
    cm.append_user_message(conv.id, "works on upgraded db")
    assert cm.count_messages(conv.id) == 1


def test_fresh_database_has_all_tables_and_indexes(tmp_path):
    db = tmp_path / "new.db"
    with connection_scope(db):
        pass
    assert {"tasks", "task_runs", "tool_results", "memories", "sessions",
            "conversations", "messages"} <= _tables(db)
    c = sqlite3.connect(db)
    idx = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    c.close()
    assert "idx_messages_conversation_sequence" in idx

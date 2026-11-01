from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.config.settings import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    user_request TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    result TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS task_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    iteration INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    provider TEXT,
    model TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS tool_results (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    task_run_id TEXT REFERENCES task_runs(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    name TEXT NOT NULL,
    success INTEGER NOT NULL,
    result_json TEXT,
    error TEXT,
    arguments_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    memory_type TEXT NOT NULL,
    importance REAL NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_accessed_at TEXT,
    source TEXT,
    metadata_json TEXT,
    active INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    title TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    active INTEGER NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS improvement_runs (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    goal TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    risk_level TEXT,
    mode TEXT,
    candidate_id TEXT,
    base_version TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS improvement_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    improvement_id TEXT NOT NULL,
    candidate_id TEXT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    risk TEXT,
    result TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    detail TEXT
);

CREATE TRIGGER IF NOT EXISTS improvement_events_no_update
BEFORE UPDATE ON improvement_events
BEGIN SELECT RAISE(ABORT, 'improvement_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS improvement_events_no_delete
BEFORE DELETE ON improvement_events
BEGIN SELECT RAISE(ABORT, 'improvement_events is append-only'); END;

CREATE INDEX IF NOT EXISTS idx_task_runs_task_id ON task_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_tool_results_task_id ON tool_results(task_id);
CREATE INDEX IF NOT EXISTS idx_tool_results_task_run_id ON tool_results(task_run_id);
CREATE INDEX IF NOT EXISTS idx_memories_active ON memories(active);
CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(memory_type);
CREATE INDEX IF NOT EXISTS idx_improvement_events_improvement_id ON improvement_events(improvement_id);
CREATE INDEX IF NOT EXISTS idx_improvement_runs_state ON improvement_runs(state);
CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at);
CREATE INDEX IF NOT EXISTS idx_conversations_session_id ON conversations(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_conversation_sequence
    ON messages(conversation_id, sequence);
"""


def get_default_db_path() -> Path:
    """The configured default SQLite file path (<data_dir>/jarvis.db unless
    DB_PATH overrides it). Does not create anything — see `get_connection`
    for that."""
    return settings.resolved_db_path


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a single new SQLite connection, creating the containing
    directory if needed.

    CONCURRENCY ASSUMPTIONS (current phase, single-process architecture):
    this project does NOT hold a long-lived shared connection anywhere —
    every repository operation opens its own connection via
    `connection_scope` and closes it when done (see TaskRepository). That
    avoids sharing a sqlite3.Connection object across threads/tasks, which
    is unsafe. WAL journal mode is enabled so concurrent readers don't
    block a writer. This is adequate for one JARVIS-X process; it is NOT a
    multi-process-safe design (e.g. two separate JARVIS-X processes
    writing the same file) — that would need a different approach
    (a real server process, or a database engine built for it) and is out
    of scope for this phase.
    """
    path = Path(db_path) if db_path is not None else get_default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Create every table/index if it doesn't already exist. Idempotent —
    safe to call on every connection open."""
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def connection_scope(db_path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Open a connection, ensure the schema exists, run the `with` block in
    one transaction, and always close the connection afterward.

    On success, commits. On any exception, rolls back and re-raises the
    original exception unchanged — callers (TaskRepository) are
    responsible for wrapping specific `sqlite3.Error`s into the project's
    own exception types where that adds useful context; this function
    itself never swallows or re-labels an error.
    """
    conn = get_connection(db_path)
    try:
        initialize_schema(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

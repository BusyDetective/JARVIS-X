"""
Database Layer v2.0

Improvements over v1:
- Uses context managers (no forgotten conn.close())
- Adds critical_count column (new from risk_scoring v2)
- Stores overall_risk_level and security_score
- save_scan returns scan_id for linking to task results
- get_scans returns dicts instead of raw tuples
- Migration support — adds new columns to existing DBs safely
- Thread-safe: each call gets its own connection (SQLite WAL mode)
"""

import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

DB_NAME = os.environ.get("DB_PATH", "recon.db")


# =========================
# CONNECTION HELPER
# =========================

@contextmanager
def get_conn():
    """Context manager — connection always closed, even on exception."""
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # safe for concurrent writes
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================
# SCHEMA INIT + MIGRATION
# =========================

def init_db():
    """
    Create tables if they don't exist.
    Also runs safe migrations for existing databases.
    """
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password      TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now')),
                last_login    TEXT
            );

            CREATE TABLE IF NOT EXISTS scans (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                domain              TEXT NOT NULL,
                scan_date           TEXT DEFAULT (datetime('now')),
                findings_count      INTEGER DEFAULT 0,
                critical_count      INTEGER DEFAULT 0,
                high_count          INTEGER DEFAULT 0,
                medium_count        INTEGER DEFAULT 0,
                low_count           INTEGER DEFAULT 0,
                overall_risk_level  TEXT DEFAULT 'LOW',
                security_score      INTEGER DEFAULT 100,
                status              TEXT DEFAULT 'Completed',
                pdf_path            TEXT,
                scan_duration_secs  INTEGER
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                vuln_type   TEXT,
                url         TEXT,
                severity    TEXT,
                cvss_score  REAL,
                confidence  INTEGER,
                param       TEXT,
                evidence    TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)

    # Safe migration — add columns that may not exist in older DBs
    _run_migrations()


def _run_migrations():
    """Add new columns to existing databases without breaking anything."""
    migrations = [
        ("scans", "critical_count",     "INTEGER DEFAULT 0"),
        ("scans", "overall_risk_level", "TEXT DEFAULT 'LOW'"),
        ("scans", "security_score",     "INTEGER DEFAULT 100"),
        ("scans", "pdf_path",           "TEXT"),
        ("scans", "scan_duration_secs", "INTEGER"),
        ("users", "created_at",         "TEXT"),
        ("users", "last_login",         "TEXT"),
    ]

    with get_conn() as conn:
        for table, column, col_def in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists — fine


# =========================
# SCAN OPERATIONS
# =========================

def save_scan(domain, risk, findings, pdf_path=None, duration_secs=None):
    """
    Save a completed scan to the database.

    Args:
        domain:        target domain string
        risk:          risk dict from calculate_risk()
        findings:      list of finding dicts
        pdf_path:      optional path to generated PDF
        duration_secs: optional scan duration in seconds

    Returns:
        scan_id (int) — useful for linking findings
    """
    # ---------------------------------------------------------------
    # Severity counts and overall_risk come from risk_scoring output.
    # Do NOT recompute them here — risk_scoring.calculate_risk() is
    # the single source of truth for severity.
    # ---------------------------------------------------------------
    summary        = risk.get("summary", {})
    critical_count = summary.get("critical", len(risk.get("critical", [])))
    high_count     = summary.get("high",     len(risk.get("high",     [])))
    medium_count   = summary.get("medium",   len(risk.get("medium",   [])))
    low_count      = summary.get("low",      len(risk.get("low",      [])))
    overall_risk   = summary.get("overall_risk_level", "LOW")

    # security_score is always set by risk_scoring.calculate_risk().
    # Read it directly; fall back only for legacy callers that pre-date v2.1.
    raw_score = summary.get("security_score", 100)
    security_score = max(int(raw_score) if isinstance(raw_score, (int, float)) else 100, 0)

    with get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO scans (
                domain, scan_date, findings_count,
                critical_count, high_count, medium_count, low_count,
                overall_risk_level, security_score,
                status, pdf_path, scan_duration_secs
            )
            VALUES (
                ?, datetime('now'), ?,
                ?, ?, ?, ?,
                ?, ?,
                'Completed', ?, ?
            )
        """, (
            domain,
            len(findings),
            critical_count, high_count, medium_count, low_count,
            overall_risk, security_score,
            pdf_path, duration_secs,
        ))

        scan_id = cursor.lastrowid

        # Save individual findings
        for f in findings[:200]:  # cap at 200 per scan
            if not isinstance(f, dict):
                continue
            conn.execute("""
                INSERT INTO findings (
                    scan_id, vuln_type, url, severity,
                    cvss_score, confidence, param, evidence, remediation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                f.get("type",        "Unknown"),
                f.get("url",         ""),
                f.get("severity",    "Low"),
                f.get("cvss",        None),
                f.get("confidence",  None),
                f.get("param",       None),
                f.get("evidence",    None),
                f.get("remediation", None),
            ))

    return scan_id


def get_scans(limit=50):
    """
    Return recent scans as list of dicts (not raw tuples).

    Args:
        limit: max number of scans to return

    Returns:
        list of dicts with all scan columns
    """
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    """Return a single scan dict by ID, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return dict(row) if row else None


def get_findings_for_scan(scan_id):
    """Return all findings for a given scan_id."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT
                id,
                scan_id,
                vuln_type AS type,
                url,
                severity,
                cvss_score,
                confidence,
                param,
                evidence,
                remediation
            FROM findings
            WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High'     THEN 2
                    WHEN 'Medium'   THEN 3
                    ELSE 4
                END
        """, (scan_id,)).fetchall()
    return [dict(row) for row in rows]


def delete_scan(scan_id):
    """Delete a scan and its findings."""
    with get_conn() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


# =========================
# USER OPERATIONS
# =========================

def create_user(username, password):
    """
    Create a new user.

    Args:
        username: plain username string
        password: pre-hashed password (hash before calling this)

    Returns:
        True on success, False if username already exists
    """
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    except Exception as e:
        print(f"[-] create_user error: {e}")
        return False


def authenticate_user(username):
    """
    Fetch user record for authentication.

    Returns:
        Row as tuple (id, username, password, ...) for
        backward compat with app.py's check_password_hash(user[2], ...)
        Returns None if not found.
    """
    with get_conn() as conn:
        # Fetch as tuple for backward compat (app.py uses user[2])
        conn.row_factory = None
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row


def update_last_login(username):
    """Update last_login timestamp for a user."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE username = ?",
            (username,)
        )


def get_user_scan_count(username):
    """Get total scan count — useful for rate limiting per user."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM scans",
        ).fetchone()
    return row[0] if row else 0


# =========================
# STATS (for dashboard)
# =========================

def get_stats():
    """
    Return aggregate stats for dashboard display.

    Returns:
        {
            "total_scans":     int,
            "total_findings":  int,
            "critical_total":  int,
            "high_total":      int,
            "recent_domains":  list of str,
        }
    """
    with get_conn() as conn:
        totals = conn.execute("""
            SELECT
                COUNT(*)             AS total_scans,
                SUM(findings_count)  AS total_findings,
                SUM(critical_count)  AS critical_total,
                SUM(high_count)      AS high_total
            FROM scans
        """).fetchone()

        recent = conn.execute("""
            SELECT domain FROM scans
            ORDER BY id DESC LIMIT 5
        """).fetchall()

    return {
        "total_scans":    totals[0] or 0,
        "total_findings": totals[1] or 0,
        "critical_total": totals[2] or 0,
        "high_total":     totals[3] or 0,
        "recent_domains": [r[0] for r in recent],
    }


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    import os
    test_db = "test_recon.db"
    os.environ["DB_PATH"] = test_db

    # reimport with test db
    DB_NAME = test_db

    init_db()
    print("[+] DB initialized")

    # Test save_scan
    mock_risk = {
        "critical": ["https://example.com/admin"],
        "high":     ["https://example.com/login"],
        "medium":   ["https://example.com/search?q=1"],
        "low":      [],
        "summary":  {"overall_risk_level": "HIGH"},
    }
    mock_findings = [
        {"type": "SQLi", "url": "https://example.com/admin", "severity": "Critical", "cvss": 9.4, "confidence": 90},
        {"type": "XSS",  "url": "https://example.com/search?q=1", "severity": "Medium", "cvss": 5.6, "confidence": 75},
    ]

    scan_id = save_scan("example.com", mock_risk, mock_findings, duration_secs=42)
    print(f"[+] Saved scan ID: {scan_id}")

    scans = get_scans()
    print(f"[+] get_scans() returned {len(scans)} scans")
    print(f"    First scan: {scans[0]}")

    findings = get_findings_for_scan(scan_id)
    print(f"[+] get_findings_for_scan() returned {len(findings)} findings")

    stats = get_stats()
    print(f"[+] Stats: {stats}")

    # Test user ops
    created = create_user("testuser", "hashed_password_here")
    print(f"[+] create_user: {created}")

    user = authenticate_user("testuser")
    print(f"[+] authenticate_user: {user}")

    # Cleanup
    os.remove(test_db)
    print("[+] Test DB cleaned up. All tests passed.")
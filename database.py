"""
database.py — SQLite persistence layer for SecureSight AI.
Handles users, scans, findings, and finding-status history.
All queries use parameterized statements to prevent SQL injection.
"""

import sqlite3
import hashlib
import hmac
import os
import logging
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SECURESIGHT_DB", "securesight.db")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    target_url  TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    completed_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    posture_score REAL,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    target      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    title       TEXT NOT NULL,
    evidence    TEXT,
    explanation TEXT,
    impact      TEXT,
    recommendation TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS finding_status_history (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    old_status  TEXT NOT NULL,
    new_status  TEXT NOT NULL,
    note        TEXT,
    changed_at  TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class _DB:
    """Context manager that opens a connection and guarantees close() on exit."""
    def __init__(self):
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        self.conn = _connect()
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
            self.conn = None
        return False


def _db() -> "_DB":
    """Use as: with _db() as conn: ..."""
    return _DB()


def init_db() -> None:
    """Create all tables if they do not exist."""
    with _db() as conn:
        conn.executescript(SCHEMA)
    logger.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256 via standard library)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def create_user(email: str, display_name: str, password: str) -> dict | None:
    """Return the new user dict or None if email is already registered."""
    uid = str(uuid.uuid4())
    ph = hash_password(password)
    now = datetime.utcnow().isoformat()
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (id, email, display_name, password_hash, created_at) VALUES (?,?,?,?,?)",
                (uid, email.lower().strip(), display_name.strip(), ph, now),
            )
        return {"id": uid, "email": email.lower().strip(), "display_name": display_name.strip()}
    except sqlite3.IntegrityError:
        return None


def authenticate_user(email: str, password: str) -> dict | None:
    """Return the user dict if credentials are valid, else None."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
        row_data = dict(row) if row else None
    if row_data and verify_password(password, row_data["password_hash"]):
        return {"id": row_data["id"], "email": row_data["email"], "display_name": row_data["display_name"]}
    return None


def get_user_by_id(user_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT id, email, display_name, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def update_display_name(user_id: str, new_name: str) -> bool:
    with _db() as conn:
        conn.execute("UPDATE users SET display_name = ? WHERE id = ?", (new_name.strip(), user_id))
    return True


# ---------------------------------------------------------------------------
# Scan management
# ---------------------------------------------------------------------------

def create_scan(user_id: str, target_url: str, target_domain: str) -> str:
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with _db() as conn:
        conn.execute(
            "INSERT INTO scans (id, user_id, target_url, target_domain, started_at, status) VALUES (?,?,?,?,?,?)",
            (scan_id, user_id, target_url, target_domain, now, "running"),
        )
    return scan_id


def complete_scan(scan_id: str, posture_score: float, findings_count: int) -> None:
    now = datetime.utcnow().isoformat()
    with _db() as conn:
        conn.execute(
            "UPDATE scans SET status=?, completed_at=?, posture_score=?, findings_count=? WHERE id=?",
            ("completed", now, posture_score, findings_count, scan_id),
        )


def fail_scan(scan_id: str, error_message: str) -> None:
    now = datetime.utcnow().isoformat()
    with _db() as conn:
        conn.execute(
            "UPDATE scans SET status=?, completed_at=?, error_message=? WHERE id=?",
            ("failed", now, error_message, scan_id),
        )


def get_scans_for_user(user_id: str) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id=? ORDER BY started_at DESC", (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: str, user_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id)
        ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Finding management
# ---------------------------------------------------------------------------

def save_findings(findings: list[dict]) -> None:
    if not findings:
        return
    now = datetime.utcnow().isoformat()
    with _db() as conn:
        for f in findings:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scan_id, user_id, check_name, target, severity, confidence,
                    title, evidence, explanation, impact, recommendation, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f.get("id", str(uuid.uuid4())),
                    f["scan_id"], f["user_id"], f["check_name"], f["target"],
                    f["severity"], f["confidence"], f["title"],
                    f.get("evidence", ""), f.get("explanation", ""),
                    f.get("impact", ""), f.get("recommendation", ""),
                    f.get("status", "open"), f.get("created_at", now),
                ),
            )


def get_findings_for_scan(scan_id: str, user_id: str) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? AND user_id=? ORDER BY "
            "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END",
            (scan_id, user_id),
        ).fetchall()
    return [dict(r) for r in rows]


def get_findings_for_user(user_id: str) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT f.* FROM findings f JOIN scans s ON f.scan_id=s.id "
            "WHERE f.user_id=? ORDER BY f.created_at DESC", (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def update_finding_status(finding_id: str, user_id: str, new_status: str, note: str = "") -> bool:
    with _db() as conn:
        row = conn.execute(
            "SELECT status FROM findings WHERE id=? AND user_id=?", (finding_id, user_id)
        ).fetchone()
        if not row:
            return False
        old_status = row["status"]
        conn.execute(
            "UPDATE findings SET status=? WHERE id=? AND user_id=?",
            (new_status, finding_id, user_id),
        )
        conn.execute(
            "INSERT INTO finding_status_history (id, finding_id, user_id, old_status, new_status, note, changed_at) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), finding_id, user_id, old_status, new_status, note, datetime.utcnow().isoformat()),
        )
    return True


def get_user_stats(user_id: str) -> dict:
    with _db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (user_id,)).fetchone()[0]
        domains = conn.execute("SELECT COUNT(DISTINCT target_domain) FROM scans WHERE user_id=?", (user_id,)).fetchone()[0]
        open_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE user_id=? AND status='open'", (user_id,)).fetchone()[0]
        high_findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE user_id=? AND status='open' AND severity IN ('Critical','High')", (user_id,)
        ).fetchone()[0]
        last_score = conn.execute(
            "SELECT posture_score FROM scans WHERE user_id=? AND status='completed' ORDER BY completed_at DESC LIMIT 1", (user_id,)
        ).fetchone()
    return {
        "total_scans": total_scans,
        "domains_assessed": domains,
        "open_findings": open_findings,
        "high_priority_findings": high_findings,
        "latest_score": last_score[0] if last_score else None,
    }

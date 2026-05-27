#!/usr/bin/env python3
"""
RuleRadar database — SQLite schema, connection management, and query helpers.
All other modules import from here; nothing here imports from the project.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# In Docker the RULERADAR_DB env var points the DB into the named volume.
# Locally it defaults to the project root so nothing extra is needed.
DB_PATH = Path(os.environ.get("RULERADAR_DB", str(Path(__file__).parent / "ruleradar.db")))

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Users ──────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

-- ── Detection rules (current state of every known rule) ───────────────────────
CREATE TABLE IF NOT EXISTS detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    detection_logic TEXT    NOT NULL DEFAULT '',
    spl             TEXT    NOT NULL DEFAULT '',
    rule_url        TEXT    NOT NULL DEFAULT '',
    first_seen      TEXT    NOT NULL,
    last_updated    TEXT    NOT NULL,
    UNIQUE(source, file_path)
);

CREATE INDEX IF NOT EXISTS idx_det_source       ON detections(source);
CREATE INDEX IF NOT EXISTS idx_det_last_updated ON detections(last_updated DESC);

-- ── Change log (every new/modified event is appended here) ────────────────────
CREATE TABLE IF NOT EXISTS updates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    change_type     TEXT    NOT NULL,   -- 'new' | 'modified'
    detection_logic TEXT    NOT NULL DEFAULT '',
    spl             TEXT    NOT NULL DEFAULT '',
    rule_url        TEXT    NOT NULL DEFAULT '',
    detected_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_upd_detected_at ON updates(detected_at DESC);

-- ── Repo releases ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS releases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT    NOT NULL,
    tag_name     TEXT    NOT NULL,
    name         TEXT    NOT NULL DEFAULT '',
    body         TEXT    NOT NULL DEFAULT '',
    published_at TEXT    NOT NULL DEFAULT '',
    html_url     TEXT    NOT NULL DEFAULT '',
    detected_at  TEXT    NOT NULL,
    UNIQUE(source, tag_name)
);

-- ── Singleton scan-status row ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_status (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    last_scan   TEXT,
    new_count   INTEGER NOT NULL DEFAULT 0,
    mod_count   INTEGER NOT NULL DEFAULT 0,
    is_scanning INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO scan_status (id) VALUES (1);
"""


# ── Connection ─────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables and indexes if they do not already exist."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── User helpers ───────────────────────────────────────────────────────────────

def user_count() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_user_by_username(username: str):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def get_user_by_id(user_id: int):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def create_user(username: str, password_hash: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, now_iso()),
        )


# ── Detection helpers ──────────────────────────────────────────────────────────

def upsert_detection(
    source: str, file_path: str, title: str,
    description: str, detection_logic: str, spl: str, rule_url: str,
) -> bool:
    """
    Insert or update a detection row.
    Returns True if the row was brand-new (first time we've seen this file).
    """
    ts = now_iso()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM detections WHERE source = ? AND file_path = ?",
            (source, file_path),
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE detections
                   SET title=?, description=?, detection_logic=?, spl=?,
                       rule_url=?, last_updated=?
                   WHERE source=? AND file_path=?""",
                (title, description, detection_logic, spl, rule_url, ts, source, file_path),
            )
            return False
        conn.execute(
            """INSERT INTO detections
               (source, file_path, title, description, detection_logic, spl,
                rule_url, first_seen, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (source, file_path, title, description, detection_logic, spl, rule_url, ts, ts),
        )
        return True


def search_detections(
    query: str = "", source: str = "", page: int = 1, per_page: int = 50
) -> tuple[list[dict], int]:
    """Full-text search across detections. Returns (rows, total_count)."""
    conditions, params = [], []
    if query:
        conditions.append(
            "(title LIKE ? OR description LIKE ? OR detection_logic LIKE ? OR spl LIKE ?)"
        )
        like = f"%{query}%"
        params += [like, like, like, like]
    if source:
        conditions.append("source = ?")
        params.append(source)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM detections {where}", params
        ).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT * FROM detections {where} ORDER BY last_updated DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

    return [dict(r) for r in rows], total


# ── Update helpers ─────────────────────────────────────────────────────────────

def record_update(
    source: str, file_path: str, title: str, change_type: str,
    detection_logic: str, spl: str, rule_url: str,
):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO updates
               (source, file_path, title, change_type, detection_logic,
                spl, rule_url, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (source, file_path, title, change_type, detection_logic, spl, rule_url, now_iso()),
        )


def get_updates(
    source: str = "", change_type: str = "", limit: int = 100, offset: int = 0
) -> tuple[list[dict], int]:
    conditions, params = [], []
    if source:
        conditions.append("source = ?")
        params.append(source)
    if change_type:
        conditions.append("change_type = ?")
        params.append(change_type)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM updates {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM updates {where} ORDER BY detected_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    return [dict(r) for r in rows], total


# ── Release helpers ────────────────────────────────────────────────────────────

def upsert_release(
    source: str, tag_name: str, name: str,
    body: str, published_at: str, html_url: str,
) -> bool:
    """Insert a release if not already known. Returns True if new."""
    with get_conn() as conn:
        if conn.execute(
            "SELECT id FROM releases WHERE source=? AND tag_name=?", (source, tag_name)
        ).fetchone():
            return False
        conn.execute(
            """INSERT INTO releases
               (source, tag_name, name, body, published_at, html_url, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (source, tag_name, name, body, published_at, html_url, now_iso()),
        )
        return True


# ── Scan status ────────────────────────────────────────────────────────────────

def get_scan_status() -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scan_status WHERE id = 1").fetchone()
        return dict(row) if row else {}


def set_scanning(value: bool):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_status SET is_scanning = ? WHERE id = 1",
            (1 if value else 0,),
        )


def finish_scan(new_count: int, mod_count: int):
    with get_conn() as conn:
        conn.execute(
            """UPDATE scan_status
               SET last_scan=?, new_count=?, mod_count=?, is_scanning=0
               WHERE id=1""",
            (now_iso(), new_count, mod_count),
        )

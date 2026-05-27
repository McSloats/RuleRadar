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
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL
);

-- ── Per-user settings ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_settings (
    user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    discord_webhook TEXT    NOT NULL DEFAULT '',
    saved_filters   TEXT    NOT NULL DEFAULT '[]'
);

-- ── Monitored repositories ────────────────────────────────────────────────────
-- Each row represents one GitHub repository being cloned and scanned.
-- status: 'pending' | 'cloning' | 'indexing' | 'ready' | 'error' | 'inactive'
CREATE TABLE IF NOT EXISTS repos (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,   -- short identifier, e.g. 'sigma'
    display_name   TEXT    NOT NULL DEFAULT '',
    owner          TEXT    NOT NULL DEFAULT '',
    repo           TEXT    NOT NULL DEFAULT '',
    branch         TEXT    NOT NULL DEFAULT '',
    paths          TEXT    NOT NULL DEFAULT '[]',   -- JSON array of sub-paths to scan
    parser         TEXT    NOT NULL DEFAULT '',     -- 'sigma' | 'splunk'
    local_path     TEXT    NOT NULL DEFAULT '',     -- absolute path on disk
    last_sha       TEXT    NOT NULL DEFAULT '',     -- HEAD SHA of last indexed commit
    status         TEXT    NOT NULL DEFAULT 'pending',
    error_msg      TEXT    NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    added_at       TEXT    NOT NULL DEFAULT '',
    last_synced_at TEXT    NOT NULL DEFAULT ''
);

-- ── Detection rules (current state of every known rule) ───────────────────────
CREATE TABLE IF NOT EXISTS detections (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source           TEXT    NOT NULL,
    file_path        TEXT    NOT NULL,
    title            TEXT    NOT NULL DEFAULT '',
    description      TEXT    NOT NULL DEFAULT '',
    detection_logic  TEXT    NOT NULL DEFAULT '',
    spl              TEXT    NOT NULL DEFAULT '',
    rule_url         TEXT    NOT NULL DEFAULT '',
    first_seen       TEXT    NOT NULL,
    last_updated     TEXT    NOT NULL,
    mitre_techniques TEXT    NOT NULL DEFAULT '',
    mitre_tactics    TEXT    NOT NULL DEFAULT '',
    author           TEXT    NOT NULL DEFAULT '',
    rule_status      TEXT    NOT NULL DEFAULT '',
    severity         TEXT    NOT NULL DEFAULT '',
    rule_date        TEXT    NOT NULL DEFAULT '',
    refs             TEXT    NOT NULL DEFAULT '',
    UNIQUE(source, file_path)
);

CREATE INDEX IF NOT EXISTS idx_det_source       ON detections(source);
CREATE INDEX IF NOT EXISTS idx_det_last_updated ON detections(last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_det_mitre        ON detections(mitre_techniques);

-- ── Change log (every new/modified/deleted event is appended here) ────────────
CREATE TABLE IF NOT EXISTS updates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    change_type     TEXT    NOT NULL,   -- 'new' | 'modified' | 'deleted' | 'renamed'
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

-- ── Activity log ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    category  TEXT    NOT NULL,          -- 'auth' | 'user' | 'scan' | 'admin' | 'system'
    level     TEXT    NOT NULL DEFAULT 'info',  -- 'info' | 'warning' | 'error'
    actor     TEXT    NOT NULL DEFAULT 'system',
    action    TEXT    NOT NULL,
    detail    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_log_timestamp ON activity_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_log_category  ON activity_log(category);
CREATE INDEX IF NOT EXISTS idx_log_level     ON activity_log(level);

-- ── Singleton scan-status row ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_status (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    last_scan    TEXT,
    new_count    INTEGER NOT NULL DEFAULT 0,
    mod_count    INTEGER NOT NULL DEFAULT 0,
    is_scanning  INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO scan_status (id) VALUES (1);
"""


# ── Connection ─────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Must be set per-connection for ON DELETE CASCADE to work
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables / indexes and apply any pending schema migrations."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _migrate_schema(conn)


def _migrate_schema(conn: sqlite3.Connection):
    """
    Idempotent migrations for databases created by older versions.
    Each ALTER is wrapped in try/except — safe to run repeatedly.
    """
    migrations = [
        # v2: admin flag on users (databases created before the settings redesign)
        "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0",
        # v3: extended detection metadata and MITRE fields
        "ALTER TABLE detections ADD COLUMN mitre_techniques TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN mitre_tactics    TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN author           TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN rule_status      TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN severity         TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN rule_date        TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN refs             TEXT NOT NULL DEFAULT ''",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists — harmless


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── User helpers ───────────────────────────────────────────────────────────────

def user_count() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def admin_count() -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_admin = 1"
        ).fetchone()[0]


def get_all_users() -> list[dict]:
    """Return all users joined with their webhook status."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT u.id, u.username, u.is_admin, u.created_at,
                      COALESCE(s.discord_webhook, '') AS discord_webhook
               FROM users u
               LEFT JOIN user_settings s ON s.user_id = u.id
               ORDER BY u.id""",
        ).fetchall()
        return [dict(r) for r in rows]


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


def create_user(username: str, password_hash: str, is_admin: bool = False):
    """Create a user and initialise their settings row."""
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, password_hash, 1 if is_admin else 0, now_iso()),
        )
        conn.execute(
            "INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)",
            (cur.lastrowid,),
        )


def update_user_password(user_id: int, password_hash: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id),
        )


def set_user_admin(user_id: int, is_admin: bool):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET is_admin = ? WHERE id = ?",
            (1 if is_admin else 0, user_id),
        )


def delete_user(user_id: int):
    """Delete a user; the user_settings row is removed by ON DELETE CASCADE."""
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Per-user settings helpers ──────────────────────────────────────────────────

def get_user_settings(user_id: int) -> dict:
    """Return a user's settings row, creating it with defaults if absent."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)", (user_id,)
        )
        row = conn.execute(
            "SELECT * FROM user_settings WHERE user_id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else {
            "user_id": user_id, "discord_webhook": "", "saved_filters": "[]"
        }


def update_user_discord(user_id: int, webhook: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO user_settings (user_id, discord_webhook) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET discord_webhook = excluded.discord_webhook",
            (user_id, webhook),
        )


def update_user_filters(user_id: int, filters_json: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO user_settings (user_id, saved_filters) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET saved_filters = excluded.saved_filters",
            (user_id, filters_json),
        )


def get_all_user_webhooks() -> list[str]:
    """Return every non-empty Discord webhook URL (used for mass notification)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT discord_webhook FROM user_settings WHERE discord_webhook != ''"
        ).fetchall()
        return [r["discord_webhook"] for r in rows]


# ── Repository helpers ─────────────────────────────────────────────────────────

def get_all_repos() -> list[dict]:
    """Return all repos ordered by name."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM repos ORDER BY name").fetchall()
        return [dict(r) for r in rows]


def get_repo_by_name(name: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM repos WHERE name = ?", (name,)
        ).fetchone()
        return dict(row) if row else None


def get_active_repos() -> list[dict]:
    """
    Return repos that are enabled and not inactive.
    These are the repos the scanner should process.
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM repos WHERE enabled = 1 AND status != 'inactive' ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]


def any_repos_configured() -> bool:
    """
    Return True if at least one repo has been enabled by an admin.
    Used by the repo gate in before_request to decide whether to show setup-repos.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM repos WHERE enabled = 1"
        ).fetchone()
        return row[0] > 0


def add_repo(
    name: str,
    display_name: str,
    owner: str,
    repo: str,
    branch: str,
    paths_json: str,
    parser: str,
    local_path: str,
) -> int:
    """
    Register a new repository for monitoring.
    Status starts as 'pending' — the scanner will clone it on the next run.
    Returns the new row id.
    """
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO repos
               (name, display_name, owner, repo, branch, paths, parser,
                local_path, status, enabled, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?)
               ON CONFLICT(name) DO UPDATE SET
                 display_name = excluded.display_name,
                 owner        = excluded.owner,
                 repo         = excluded.repo,
                 branch       = excluded.branch,
                 paths        = excluded.paths,
                 parser       = excluded.parser,
                 local_path   = excluded.local_path,
                 status       = 'pending',
                 enabled      = 1,
                 error_msg    = ''
            """,
            (name, display_name, owner, repo, branch, paths_json, parser,
             local_path, now_iso()),
        )
        return cur.lastrowid


def update_repo_status(name: str, status: str, error_msg: str = ""):
    with get_conn() as conn:
        conn.execute(
            "UPDATE repos SET status = ?, error_msg = ? WHERE name = ?",
            (status, error_msg, name),
        )


def update_repo_sha(name: str, sha: str):
    """Record the latest indexed commit SHA and update last_synced_at."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE repos SET last_sha = ?, last_synced_at = ? WHERE name = ?",
            (sha, now_iso(), name),
        )


def update_repo_local_path(name: str, local_path: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE repos SET local_path = ? WHERE name = ?",
            (local_path, name),
        )


def set_repo_enabled(name: str, enabled: bool):
    """Enable or disable a repo.  Disabled repos are skipped by the scanner."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE repos SET enabled = ? WHERE name = ?",
            (1 if enabled else 0, name),
        )


def remove_repo(name: str):
    """Remove a repo from tracking. Does NOT delete the local clone or its detections."""
    with get_conn() as conn:
        conn.execute("DELETE FROM repos WHERE name = ?", (name,))


# ── Detection helpers ──────────────────────────────────────────────────────────

def upsert_detection(
    source: str,
    file_path: str,
    title: str,
    description: str,
    detection_logic: str,
    spl: str,
    rule_url: str,
    *,
    mitre_techniques: str = "",
    mitre_tactics: str = "",
    author: str = "",
    rule_status: str = "",
    severity: str = "",
    rule_date: str = "",
    refs: str = "",
) -> bool:
    """
    Insert or update a detection row.
    Returns True if the row was brand-new (first time we've seen this file).

    Extra metadata fields (MITRE, author, etc.) are keyword-only to make
    call sites explicit.
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
                       rule_url=?, last_updated=?,
                       mitre_techniques=?, mitre_tactics=?,
                       author=?, rule_status=?, severity=?, rule_date=?, refs=?
                   WHERE source=? AND file_path=?""",
                (
                    title, description, detection_logic, spl, rule_url, ts,
                    mitre_techniques, mitre_tactics,
                    author, rule_status, severity, rule_date, refs,
                    source, file_path,
                ),
            )
            return False
        conn.execute(
            """INSERT INTO detections
               (source, file_path, title, description, detection_logic, spl,
                rule_url, first_seen, last_updated,
                mitre_techniques, mitre_tactics,
                author, rule_status, severity, rule_date, refs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?)""",
            (
                source, file_path, title, description, detection_logic, spl,
                rule_url, ts, ts,
                mitre_techniques, mitre_tactics,
                author, rule_status, severity, rule_date, refs,
            ),
        )
        return True


def delete_detection(source: str, file_path: str):
    """Remove a detection that was deleted from the repository."""
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM detections WHERE source = ? AND file_path = ?",
            (source, file_path),
        )


def search_detections(
    query: str = "",
    source: str = "",
    mitre: str = "",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """
    Full-text search across detections.
    - query  : searches title, description, detection_logic, spl
    - source : 'sigma' | 'splunk' | '' (all)
    - mitre  : searches mitre_techniques and mitre_tactics (e.g. 'T1059' or 'Execution')
    Returns (rows, total_count).
    """
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
    if mitre:
        conditions.append(
            "(mitre_techniques LIKE ? OR mitre_tactics LIKE ?)"
        )
        like = f"%{mitre}%"
        params += [like, like]

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
    """
    Return paginated update events, newest first.

    Each row is augmented with metadata from the current detections table
    (author, rule_status, rule_date, description, refs) via a LEFT JOIN so
    that the expand panel can show full rule context.  Deleted rules will
    have empty strings for those fields.
    """
    conds, params = [], []
    if source:
        conds.append("u.source = ?")
        params.append(source)
    if change_type:
        conds.append("u.change_type = ?")
        params.append(change_type)

    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM updates u {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT u.*,
                       COALESCE(d.author,      '') AS author,
                       COALESCE(d.rule_status, '') AS rule_status,
                       COALESCE(d.rule_date,   '') AS rule_date,
                       COALESCE(d.description, '') AS description,
                       COALESCE(d.refs,        '') AS refs
                FROM updates u
                LEFT JOIN detections d
                       ON d.source = u.source AND d.file_path = u.file_path
                {where}
                ORDER BY u.detected_at DESC LIMIT ? OFFSET ?""",
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


# ── Activity log ───────────────────────────────────────────────────────────────

def log_activity(
    category: str,
    action: str,
    actor: str = "system",
    detail: str = "",
    level: str = "info",
):
    """
    Append one row to the activity log.

    category : 'auth' | 'user' | 'scan' | 'admin' | 'system'
    level    : 'info' | 'warning' | 'error'
    actor    : username, 'system', 'scheduler', etc.
    """
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO activity_log (timestamp, category, level, actor, action, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now_iso(), category, level, actor, action, detail),
        )


def get_activity_log(
    category: str = "",
    level: str = "",
    actor: str = "",
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return paginated activity log rows, newest first."""
    conditions, params = [], []
    if category:
        conditions.append("category = ?")
        params.append(category)
    if level:
        conditions.append("level = ?")
        params.append(level)
    if actor:
        conditions.append("actor LIKE ?")
        params.append(f"%{actor}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM activity_log {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM activity_log {where} "
            f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return [dict(r) for r in rows], total

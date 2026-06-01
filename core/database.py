#!/usr/bin/env python3
"""
RuleRadar database — SQLite schema, connection management, and query helpers.
All other modules import from here; nothing here imports from the project.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

# In Docker the RULERADAR_DB env var points the DB into the named volume.
# Locally it defaults to the project root (core/../ruleradar.db).
DB_PATH = Path(os.environ.get("RULERADAR_DB", str(Path(__file__).parent.parent / "ruleradar.db")))

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
    rule_date        TEXT    NOT NULL DEFAULT '',
    refs             TEXT    NOT NULL DEFAULT '',
    rule_id          TEXT    NOT NULL DEFAULT '',
    UNIQUE(source, file_path)
);

CREATE INDEX IF NOT EXISTS idx_det_source       ON detections(source);
CREATE INDEX IF NOT EXISTS idx_det_last_updated ON detections(last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_det_mitre        ON detections(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_det_rule_id      ON detections(rule_id);

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

-- ── Per-user persistent rule filter ──────────────────────────────────────────
-- Each row is one filter criterion. A detection/update passes if it matches
-- ANY row for the user (rows are ORed). Within a row, all non-empty columns
-- are ANDed.  Duplicate rows are silently ignored via the UNIQUE constraint.
CREATE TABLE IF NOT EXISTS user_rule_filters (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_id       TEXT    NOT NULL DEFAULT '',
    title_pattern TEXT    NOT NULL DEFAULT '',
    source        TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL,
    UNIQUE(user_id, rule_id, title_pattern, source)
);
CREATE INDEX IF NOT EXISTS idx_urf_user_id ON user_rule_filters(user_id);
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
        "ALTER TABLE detections ADD COLUMN rule_date        TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE detections ADD COLUMN refs             TEXT NOT NULL DEFAULT ''",
        # v4: source rule UUID for precise filter matching
        "ALTER TABLE detections ADD COLUMN rule_id          TEXT NOT NULL DEFAULT ''",
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


def get_dashboard_repo_stats(cutoff_24h: str) -> list[dict]:
    """
    Return per-repo stats for the dashboard, ordered by the time they were added.
    Each dict is a repos row augmented with:
      total_rules  — number of detections indexed for this repo
      new_24h      — 'new' change events in the last 24 hours
      modified_24h — 'modified' change events in the last 24 hours
    """
    with get_conn() as conn:
        repos = conn.execute(
            "SELECT * FROM repos WHERE enabled = 1 ORDER BY added_at"
        ).fetchall()
        result = []
        for repo in repos:
            name = repo["name"]
            total = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE source = ?",
                (name,),
            ).fetchone()[0]
            new_24h = conn.execute(
                "SELECT COUNT(*) FROM updates "
                "WHERE source = ? AND change_type = 'new' AND detected_at >= ?",
                (name, cutoff_24h),
            ).fetchone()[0]
            mod_24h = conn.execute(
                "SELECT COUNT(*) FROM updates "
                "WHERE source = ? AND change_type = 'modified' AND detected_at >= ?",
                (name, cutoff_24h),
            ).fetchone()[0]
            row = dict(repo)
            row["total_rules"]  = total
            row["new_24h"]      = new_24h
            row["modified_24h"] = mod_24h
            result.append(row)
    return result


def get_dashboard_totals(cutoff_7d: str) -> dict:
    """
    Aggregate stats across all repos for the dashboard summary bar.
    Returns total_rules and events_7d (all change types).
    """
    with get_conn() as conn:
        total_rules = conn.execute(
            "SELECT COUNT(*) FROM detections"
        ).fetchone()[0]
        events_7d = conn.execute(
            "SELECT COUNT(*) FROM updates WHERE detected_at >= ?",
            (cutoff_7d,),
        ).fetchone()[0]
    return {"total_rules": total_rules, "events_7d": events_7d}


# ── Per-user rule filter helpers ───────────────────────────────────────────────

def get_user_rule_filters(user_id: int) -> list[dict]:
    """Return all filter rows for a user, newest first."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM user_rule_filters WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_user_rule_filter_count(user_id: int) -> int:
    """Return the number of active filter entries for a user."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM user_rule_filters WHERE user_id = ?",
            (user_id,),
        ).fetchone()[0]


def add_user_rule_filter(
    user_id: int,
    rule_id: str = "",
    title_pattern: str = "",
    source: str = "",
) -> bool:
    """
    Add one filter row.  Returns True if a new row was inserted, False if
    the row already existed (duplicate silently ignored).
    At least one of rule_id, title_pattern, or source must be non-empty.
    """
    if not (rule_id or title_pattern or source):
        return False
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO user_rule_filters
               (user_id, rule_id, title_pattern, source, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, rule_id, title_pattern, source, now_iso()),
        )
    return cur.rowcount > 0


def add_user_rule_filters_bulk(user_id: int, rows: list[dict]) -> int:
    """
    Insert multiple filter rows (each a dict with rule_id/title_pattern/source).
    Duplicates are silently ignored.  Returns the number of new rows inserted.
    """
    inserted = 0
    with get_conn() as conn:
        for row in rows:
            rid = (row.get("rule_id") or "").strip()
            pat = (row.get("title_pattern") or row.get("title") or "").strip()
            src = (row.get("source") or "").strip().lower()
            if not (rid or pat or src):
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO user_rule_filters
                   (user_id, rule_id, title_pattern, source, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, rid, pat, src, now_iso()),
            )
            inserted += cur.rowcount
    return inserted


def delete_user_rule_filter(user_id: int, filter_id: int) -> bool:
    """Delete one filter row, ensuring it belongs to the given user."""
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM user_rule_filters WHERE id = ? AND user_id = ?",
            (filter_id, user_id),
        )
    return cur.rowcount > 0


def clear_user_rule_filters(user_id: int) -> int:
    """Delete all filter rows for a user.  Returns the count deleted."""
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM user_rule_filters WHERE user_id = ?",
            (user_id,),
        )
    return cur.rowcount


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
    rule_date: str = "",
    refs: str = "",
    rule_id: str = "",
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
                       author=?, rule_status=?, rule_date=?, refs=?, rule_id=?
                   WHERE source=? AND file_path=?""",
                (
                    title, description, detection_logic, spl, rule_url, ts,
                    mitre_techniques, mitre_tactics,
                    author, rule_status, rule_date, refs, rule_id,
                    source, file_path,
                ),
            )
            return False
        conn.execute(
            """INSERT INTO detections
               (source, file_path, title, description, detection_logic, spl,
                rule_url, first_seen, last_updated,
                mitre_techniques, mitre_tactics,
                author, rule_status, rule_date, refs, rule_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?)""",
            (
                source, file_path, title, description, detection_logic, spl,
                rule_url, ts, ts,
                mitre_techniques, mitre_tactics,
                author, rule_status, rule_date, refs, rule_id,
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


def _build_rule_filter_clause(
    user_filter_rows: list,
    source_prefix: str = "",
) -> tuple[str, list]:
    """
    Build a SQL OR clause from a user's rule-filter rows.

    source_prefix: table alias prefix for column names (e.g. "u." for updates,
                   "" for detections queried without an alias).
    Returns (sql_fragment, params).  Returns ("", []) when rows is empty.
    Each row is ANDed internally; rows are ORed together.
    """
    if not user_filter_rows:
        return "", []

    sp        = source_prefix           # "" or "u." / "d."
    row_clauses, row_params = [], []
    for frow in user_filter_rows:
        conds, params_local = [], []
        if frow.get("rule_id"):
            conds.append(f"({sp}rule_id = ?)")
            params_local.append(frow["rule_id"])
        if frow.get("title_pattern"):
            conds.append(f"LOWER({sp}title) LIKE ?")
            params_local.append(f"%{frow['title_pattern'].lower()}%")
        if frow.get("source"):
            conds.append(f"{sp}source = ?")
            params_local.append(frow["source"])
        if conds:
            row_clauses.append("(" + " AND ".join(conds) + ")")
            row_params.extend(params_local)

    if not row_clauses:
        return "", []
    return "(" + " OR ".join(row_clauses) + ")", row_params


def search_detections(
    title: str = "",
    description: str = "",
    source: str = "",
    mitre: str = "",
    days: str = "",
    details_q: str = "",
    page: int = 1,
    per_page: int = 50,
    user_filter_rows: list | None = None,
) -> tuple[list[dict], int]:
    """
    Search detections with per-field filters and a detail-panel keyword search.
    - title            : searches title only
    - description      : searches description only
    - source           : 'sigma' | 'splunk' | 'elastic' | '' (all)
    - mitre            : searches mitre_techniques and mitre_tactics
    - days             : '7'|'30'|'90'|'' — limit to rules updated in the last N days
    - details_q        : keyword across detection_logic, spl, author, rule_status, rule_date, refs
    - user_filter_rows : if set, only return rules matching at least one filter row
    Returns (rows, total_count).
    """
    conditions, params = [], []
    if title:
        conditions.append("title LIKE ?")
        params.append(f"%{title}%")
    if description:
        conditions.append("description LIKE ?")
        params.append(f"%{description}%")
    if source:
        conditions.append("source = ?")
        params.append(source)
    if mitre:
        conditions.append("(mitre_techniques LIKE ? OR mitre_tactics LIKE ?)")
        like = f"%{mitre}%"
        params += [like, like]
    if days:
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=int(days))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            conditions.append("last_updated >= ?")
            params.append(cutoff)
        except ValueError:
            pass
    if details_q:
        conditions.append(
            "(detection_logic LIKE ? OR spl LIKE ? OR author LIKE ?"
            " OR rule_status LIKE ? OR rule_date LIKE ? OR refs LIKE ?)"
        )
        like = f"%{details_q}%"
        params += [like, like, like, like, like, like]

    # Per-user persistent rule filter (OR across rows, AND within each row)
    if user_filter_rows:
        fclause, fparams = _build_rule_filter_clause(user_filter_rows, source_prefix="")
        if fclause:
            conditions.append(fclause)
            params.extend(fparams)

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
    source: str = "",
    change_type: str = "",
    title: str = "",
    days: str = "",
    details_q: str = "",
    limit: int = 100,
    offset: int = 0,
    user_filter_rows: list | None = None,
) -> tuple[list[dict], int]:
    """
    Return paginated update events, newest first.

    Each row is augmented with metadata from the current detections table
    (author, rule_status, rule_date, description, refs) via a LEFT JOIN so
    that the expand panel can show full rule context.  Deleted rules will
    have empty strings for those fields.

    - source      : 'sigma' | 'splunk' | '' (all)
    - change_type : 'new' | 'modified' | 'deleted' | 'renamed' | ''
    - title       : keyword search on title
    - days        : '7'|'30'|'90'|'' — limit to events detected in the last N days
    - details_q   : keyword across description, detection_logic, spl, author, rule_status,
                    rule_date, refs (joined from detections for non-deleted rules)
    """
    conds, params = [], []
    if source:
        conds.append("u.source = ?")
        params.append(source)
    if change_type:
        conds.append("u.change_type = ?")
        params.append(change_type)
    if title:
        conds.append("u.title LIKE ?")
        params.append(f"%{title}%")
    if days:
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=int(days))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            conds.append("u.detected_at >= ?")
            params.append(cutoff)
        except ValueError:
            pass
    if details_q:
        like = f"%{details_q}%"
        conds.append(
            "(u.detection_logic LIKE ? OR u.spl LIKE ?"
            " OR COALESCE(d.author,      '') LIKE ?"
            " OR COALESCE(d.rule_status, '') LIKE ?"
            " OR COALESCE(d.rule_date,   '') LIKE ?"
            " OR COALESCE(d.description, '') LIKE ?"
            " OR COALESCE(d.refs,        '') LIKE ?)"
        )
        params += [like, like, like, like, like, like, like]

    # Per-user persistent rule filter.  For updates we match against u.title /
    # u.source; rule_id is matched against the joined detections.rule_id.
    if user_filter_rows:
        row_clauses, row_params = [], []
        for frow in user_filter_rows:
            fconds, fp = [], []
            if frow.get("rule_id"):
                fconds.append("COALESCE(d.rule_id, '') = ?")
                fp.append(frow["rule_id"])
            if frow.get("title_pattern"):
                fconds.append("LOWER(u.title) LIKE ?")
                fp.append(f"%{frow['title_pattern'].lower()}%")
            if frow.get("source"):
                fconds.append("u.source = ?")
                fp.append(frow["source"])
            if fconds:
                row_clauses.append("(" + " AND ".join(fconds) + ")")
                row_params.extend(fp)
        if row_clauses:
            conds.append("(" + " OR ".join(row_clauses) + ")")
            params.extend(row_params)

    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    join  = "LEFT JOIN detections d ON d.source = u.source AND d.file_path = u.file_path"

    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM updates u {join} {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT u.*,
                       COALESCE(d.author,      '') AS author,
                       COALESCE(d.rule_status, '') AS rule_status,
                       COALESCE(d.rule_date,   '') AS rule_date,
                       COALESCE(d.description, '') AS description,
                       COALESCE(d.refs,        '') AS refs
                FROM updates u
                {join}
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

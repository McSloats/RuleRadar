#!/usr/bin/env python3
"""
RuleRadar web interface.

Pages
-----
  /               → redirect to /dashboard (or /setup, /login)
  /dashboard      → post-login overview: per-repo stats and summary bar
  /setup          → first-run admin account creation
  /login, /logout → authentication
  /setup-repos    → first-run repo selection (admin enables repos, starts cloning)
  /detections     → searchable table of every known detection rule
  /updates        → feed of new/modified/deleted rule events
  /settings       → per-user: password, Discord webhook, saved filters
  /admin          → admin-only: repository management, user management
  /admin/activity → admin-only: activity log
  /api/v1/...     → read-only JSON API, authenticated with a per-user API key
                    (Authorization: Bearer rr_...) created on /settings

Scan policy
-----------
  * Scans use git clone / git fetch — no GitHub API rate limits, no auth needed.
  * The first scan fires when an admin enables repos on /setup-repos.
  * Subsequent scans are owned by the scheduler process (scheduler.py),
    which runs at every even UTC hour (00:00, 02:00, … 22:00).
  * A 90-minute staleness guard in the scheduler prevents double-scans.

Repo gate
---------
  Any authenticated user who visits a main page before any repos are
  configured is redirected to /setup-repos.  Non-admins see a waiting
  screen; admins see the repo-selection form.

Auth: Flask-Login with bcrypt-hashed passwords.
      First visit redirects to /setup to create the initial admin account.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from functools import wraps
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import bcrypt
from core import database as db
from core import ruleradar

from flask import (
    Blueprint, Flask, Response, abort, flash, g, jsonify, make_response,
    redirect, render_template, request, session, url_for,
)
from werkzeug.exceptions import HTTPException
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)
from flask_wtf.csrf import CSRFProtect, CSRFError

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)


def _load_secret_key() -> str:
    """
    Load or generate a persistent secret key for session signing.
    Stored alongside the database so it survives container restarts
    when the DB volume is mounted (Docker).

    Written with 0600 permissions (owner read/write only) -- this key signs
    every session cookie, so anyone else able to read it could forge a valid
    session for any user, including admin, without ever touching a password.
    """
    key_path = db.DB_PATH.parent / ".secret_key"
    if key_path.exists():
        key_path.chmod(0o600)  # tighten in case it predates this check
        return key_path.read_text().strip()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


app.secret_key = _load_secret_key()

# HttpOnly and SameSite are safe to force unconditionally. Secure can't be --
# the documented default deployment is plain HTTP on a LAN (http://localhost:5000
# or a bare IP), and a Secure cookie is silently dropped by the browser over HTTP,
# which would break login entirely. Tie it to RULERADAR_SITE_URL (already used for
# Discord notification links) so it only turns on once an operator declares this
# instance is actually served over HTTPS.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RULERADAR_SITE_URL", "").startswith("https://")
# Flask-Login's 30-day "remember me" cookie gets the same protections
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"]   = app.config["SESSION_COOKIE_SECURE"]

csrf = CSRFProtect(app)

# Browser hardening on every response. A full script/style CSP isn't
# possible while all JS and CSS are inline, so the CSP covers framing,
# plugins and <base> hijacking only.
_SECURITY_HEADERS = {
    "X-Frame-Options":         "DENY",
    "X-Content-Type-Options":  "nosniff",
    "Referrer-Policy":         "same-origin",
    "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
}


@app.after_request
def _security_headers(resp):
    for name, value in _SECURITY_HEADERS.items():
        resp.headers.setdefault(name, value)
    return resp


login_manager = LoginManager(app)
login_manager.login_view = "login"          # type: ignore[assignment]
login_manager.login_message = "Please log in to access RuleRadar."
login_manager.login_message_category = "error"

db.init_db()


# ── Timezone helpers ───────────────────────────────────────────────────────────

# Curated list of common IANA timezones for the admin selector.
COMMON_TIMEZONES: list[tuple[str, str]] = [
    ("UTC",                    "UTC"),
    ("America/New_York",       "US — Eastern (New York)"),
    ("America/Chicago",        "US — Central (Chicago)"),
    ("America/Denver",         "US — Mountain (Denver)"),
    ("America/Phoenix",        "US — Mountain no DST (Phoenix)"),
    ("America/Los_Angeles",    "US — Pacific (Los Angeles)"),
    ("America/Anchorage",      "US — Alaska (Anchorage)"),
    ("Pacific/Honolulu",       "US — Hawaii (Honolulu)"),
    ("America/Toronto",        "Canada — Eastern (Toronto)"),
    ("America/Vancouver",      "Canada — Pacific (Vancouver)"),
    ("America/Sao_Paulo",      "Brazil — São Paulo"),
    ("Europe/London",          "Europe — London (UK)"),
    ("Europe/Dublin",          "Europe — Dublin (Ireland)"),
    ("Europe/Paris",           "Europe — Paris / Berlin / Rome"),
    ("Europe/Helsinki",        "Europe — Helsinki / Kyiv"),
    ("Europe/Istanbul",        "Europe — Istanbul"),
    ("Europe/Moscow",          "Europe — Moscow"),
    ("Africa/Cairo",           "Africa — Cairo"),
    ("Africa/Johannesburg",    "Africa — Johannesburg"),
    ("Asia/Dubai",             "Asia — Dubai (UAE)"),
    ("Asia/Kolkata",           "Asia — Kolkata (India)"),
    ("Asia/Dhaka",             "Asia — Dhaka (Bangladesh)"),
    ("Asia/Bangkok",           "Asia — Bangkok"),
    ("Asia/Singapore",         "Asia — Singapore"),
    ("Asia/Shanghai",          "Asia — Shanghai (China)"),
    ("Asia/Tokyo",             "Asia — Tokyo (Japan)"),
    ("Asia/Seoul",             "Asia — Seoul (Korea)"),
    ("Australia/Perth",        "Australia — Perth"),
    ("Australia/Brisbane",     "Australia — Brisbane (no DST)"),
    ("Australia/Sydney",       "Australia — Sydney / Melbourne"),
    ("Pacific/Auckland",       "Pacific — Auckland (New Zealand)"),
]


def _get_display_tz() -> ZoneInfo:
    """Return the configured display timezone, falling back to UTC."""
    tz_name = db.get_app_setting("timezone", "UTC")
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, KeyError):
        return ZoneInfo("UTC")


def _format_dt(iso_str: str, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Convert a UTC ISO string to the configured display timezone."""
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone(_get_display_tz()).strftime(fmt)
    except Exception:
        return iso_str[:16].replace("T", " ")


app.jinja_env.filters["format_dt"] = _format_dt


@app.context_processor
def inject_app_settings():
    return {"app_tz_name": db.get_app_setting("timezone", "UTC")}


# ── Login rate limiter (in-memory, per IP) ─────────────────────────────────────

_login_attempts: dict[str, list[float]] = defaultdict(list)
_login_lock = threading.Lock()
_RATE_LIMIT_WINDOW = 60   # seconds
_RATE_LIMIT_MAX    = 10   # max POST attempts per window per IP


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _login_lock:
        bucket = _login_attempts[ip]
        bucket[:] = [t for t in bucket if now - t < _RATE_LIMIT_WINDOW]
        if len(bucket) >= _RATE_LIMIT_MAX:
            return True
        bucket.append(now)
        return False


# ── Discord webhook validator ──────────────────────────────────────────────────

def _is_valid_discord_webhook(url: str) -> bool:
    """Return True if url is empty (disabled) or a valid Discord webhook URL."""
    if not url:
        return True
    try:
        p = urllib.parse.urlparse(url)
        return (
            p.scheme == "https"
            and p.netloc in ("discord.com", "discordapp.com")
            and p.path.startswith("/api/webhooks/")
        )
    except Exception:
        return False


# ── Custom repo URL parsing ─────────────────────────────────────────────────────

def parse_github_url(raw: str) -> dict | None:
    """
    Parse a GitHub repo URL into its parts, so admins can paste a link instead
    of filling in owner/repo/branch/path separately. Accepts:
      - "https://github.com/owner/repo" (or with a trailing ".git" / "/")
      - ".../tree/<branch>/<path...>"  — a folder link, branch + path captured
      - ".../blob/<branch>/<path...>"  — a file link, path trimmed to its parent dir
      - bare "owner/repo" shorthand (no scheme, no host)
    Returns {"owner", "repo", "branch", "path"} (branch/path are None when
    absent from the URL) or None if the input doesn't parse as a GitHub repo.
    """
    raw = raw.strip()
    if not raw:
        return None

    if "github.com" not in raw and "://" not in raw:
        parts = [p for p in raw.strip("/").split("/") if p]
        if len(parts) != 2:
            return None
        owner, repo = parts
        return {"owner": owner, "repo": repo.removesuffix(".git"), "branch": None, "path": None}

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urllib.parse.urlsplit(raw)
    if not parsed.netloc.endswith("github.com"):
        return None

    segments = [s for s in parsed.path.split("/") if s]
    if len(segments) < 2:
        return None

    owner, repo = segments[0], segments[1].removesuffix(".git")
    branch = path = None
    if len(segments) > 3 and segments[2] in ("tree", "blob"):
        branch = segments[3]
        if len(segments) > 4:
            path_segments = segments[4:]
            if segments[2] == "blob":
                path_segments = path_segments[:-1]  # drop the filename
            path = "/".join(path_segments) or None

    return {"owner": owner, "repo": repo, "branch": branch, "path": path}


def detect_default_branch(owner: str, repo: str) -> str | None:
    """Ask the remote for its default branch without cloning (ls-remote only)."""
    url = f"https://github.com/{owner}/{repo}.git"
    rc, out = ruleradar.git_run(["ls-remote", "--symref", url, "HEAD"], timeout=15)
    if rc != 0:
        return None
    m = re.search(r"^ref:\s+refs/heads/(\S+)\s+HEAD", out, re.MULTILINE)
    return m.group(1) if m else None


# ── CSRF error handler ─────────────────────────────────────────────────────────

def _safe_local_path(target: str) -> str:
    """Return `target` if it is a path on this site, else "". Rejects
    absolute URLs, scheme-relative "//host" and backslash variants such as
    "/\\host", which browsers treat as "//host"."""
    if (not target.startswith("/") or target.startswith("//") or "\\" in target
            or any(ord(c) < 32 for c in target)):
        return ""
    parsed = urllib.parse.urlparse(target)
    return "" if parsed.scheme or parsed.netloc else target


def _same_site_referrer() -> str:
    """The Referer as a local path if it points at this site, else ""."""
    ref = urllib.parse.urlparse(request.referrer or "")
    if ref.netloc != request.host:
        return ""
    return _safe_local_path(ref.path + (f"?{ref.query}" if ref.query else ""))


@app.errorhandler(CSRFError)
def csrf_error(_e: CSRFError):
    flash("Your session expired or the request was invalid. Please try again.", "error")
    return redirect(_same_site_referrer() or url_for("index"))


# ── User model ─────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id       = row["id"]
        self.username = row["username"]
        self.is_admin = bool(row["is_admin"]) if "is_admin" in row.keys() else False


@login_manager.user_loader
def load_user(user_id: str):
    row = db.get_user_by_id(int(user_id))
    return User(row) if row else None


# ── Decorators ─────────────────────────────────────────────────────────────────

def admin_required(f):
    """Require the logged-in user to have is_admin = True."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Repo gate (before_request) ─────────────────────────────────────────────────

# Endpoints reachable before any repos are configured.
_REPO_GATE_SKIP = {
    "login", "logout", "setup",
    "setup_repos", "setup_repos_submit",
    "api_repo_sizes",      # AJAX called from setup-repos to fetch size estimates
    "api_scan_status",     # nav badge polls this even on the setup page
    "api_dashboard_stats", # dashboard live-update poll
    "health", "static",
    # Admin routes must stay accessible so the admin can fix a broken config
    "admin", "admin_add_user",
    "admin_toggle_admin", "admin_reset_password", "admin_delete_user",
    "admin_activity",
    "admin_repos_add", "admin_repos_toggle", "admin_repos_remove",
    "admin_scan_now", "admin_revoke_api_key",
    None,
}


@app.before_request
def require_repos_setup():
    """
    Redirect authenticated users to /setup-repos if no repositories have
    been configured yet.  Non-admins see a waiting screen; admins see
    the full repo-selection form.

    Unauthenticated users are handled by @login_required on individual routes.
    """
    if request.endpoint in _REPO_GATE_SKIP or request.blueprint == "api_v1":
        return
    if not current_user.is_authenticated:
        return  # @login_required redirects them to /login
    if not db.any_repos_configured():
        return redirect(url_for("setup_repos"))


# ── Scan scheduling helpers ────────────────────────────────────────────────────

def _next_scheduled_scan() -> datetime:
    """
    Return the UTC datetime of the next even-hour scheduler fire.
    The scheduler runs at 00:00, 02:00, 04:00 … 22:00 UTC.
    """
    now = datetime.now(timezone.utc)
    hours_to_add = 2 - (now.hour % 2)
    return (now + timedelta(hours=hours_to_add)).replace(
        minute=0, second=0, microsecond=0
    )


def _start_background_scan(triggered_by: str):
    """
    Spawn a daemon thread to run a full scan cycle.
    Used by the repo-setup flow; subsequent scans are scheduler-owned.
    """
    def _run():
        try:
            ruleradar.run_scan(triggered_by=triggered_by)
        except Exception as e:
            print(f"  Background scan error: {e}", flush=True)

    threading.Thread(target=_run, daemon=True).start()


def _get_saved_filters() -> list[dict]:
    """Return the current user's saved filter presets."""
    if not current_user.is_authenticated:
        return []
    settings = db.get_user_settings(current_user.id)
    try:
        return json.loads(settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


def _get_user_rule_filters() -> list[dict]:
    """Return the current user's persistent rule-filter rows."""
    if not current_user.is_authenticated:
        return []
    return db.get_user_rule_filters(current_user.id)


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run only — create the initial admin account."""
    if db.user_count() > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm",  "")

        if not username or not password:
            flash("Username and password are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            db.create_user(username, pw_hash, is_admin=True)
            db.log_activity("admin", f"Initial admin account '{username}' created",
                            actor=username)
            flash("Admin account created — please log in.", "success")
            return redirect(url_for("login"))

    return render_template("setup.html")


# Same cost factor as real password hashes (bcrypt.gensalt() default)
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt())


@app.route("/login", methods=["GET", "POST"])
def login():
    if db.user_count() == 0:
        return redirect(url_for("setup"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if _is_rate_limited(request.remote_addr):
            flash("Too many login attempts. Please wait a minute and try again.", "error")
            return render_template("login.html")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row      = db.get_user_by_username(username)
        # Always run bcrypt, against a dummy hash for unknown users, so the
        # response time doesn't reveal whether the username exists
        pw_hash  = row["password_hash"].encode() if row else _DUMMY_PASSWORD_HASH
        if bcrypt.checkpw(password.encode(), pw_hash) and row:
            login_user(User(row), remember=True, duration=timedelta(days=30))
            db.log_activity("auth", f"User '{username}' logged in",
                            actor=username,
                            detail=f"ip={request.remote_addr}")
            next_page = _safe_local_path(request.args.get("next", ""))
            return redirect(next_page or url_for("dashboard"))
        db.log_activity("auth", f"Failed login attempt for '{username}'",
                        actor=username or "unknown",
                        detail=f"ip={request.remote_addr}",
                        level="warning")
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    db.log_activity("auth", f"User '{current_user.username}' logged out",
                    actor=current_user.username)
    logout_user()
    return redirect(url_for("login"))


# ── Repository setup (mandatory first-run page) ────────────────────────────────

@app.route("/setup-repos")
@login_required
def setup_repos():
    """
    First-run repo selection page.

    - Non-admins:  see a "waiting for admin" message.
    - Admins:      see checkboxes for the available repos with size estimates,
                   plus the current status of any already-configured repos.

    Once at least one repo is enabled (any status), this page is no longer
    shown as a gate — regular navigation takes over.
    """
    # If repos are already configured redirect to dashboard (gate is lifted)
    if db.any_repos_configured():
        return redirect(url_for("dashboard"))

    configured_repos = db.get_all_repos()
    return render_template(
        "setup_repos.html",
        available=list(ruleradar.AVAILABLE_REPOS.values()),
        configured_repos=configured_repos,
        history_choices=db.MAX_EVENTS_CHOICES,
        history_default=db.DEFAULT_MAX_EVENTS_PER_RULE,
        # Storage model for the change-history estimate (measured Oct 2026
        # on the six default repos: ~3.1 KB per stored modification incl.
        # its diff, ~5.7 KB of database per indexed rule, and ~1.2
        # modifications per rule per year)
        storage_model={
            "bytes_per_event":     3300,
            "db_bytes_per_rule":   5900,
            "mods_per_rule_year":  1.2,
            "headroom":            1.25,
            "repos": {
                name: {"rules": cfg.get("approx_rules", 0), "mb": cfg.get("approx_disk_mb", 0)}
                for name, cfg in ruleradar.AVAILABLE_REPOS.items()
            },
        },
    )


@app.route("/setup-repos/submit", methods=["POST"])
@admin_required
def setup_repos_submit():
    """
    Enable the repos the admin selected and kick off the initial scan
    (clone + index) in a background thread.
    """
    selected = request.form.getlist("repos")  # list of repo names checked

    if not selected:
        flash("Please select at least one repository.", "error")
        return redirect(url_for("setup_repos"))

    added = []
    for name in selected:
        cfg = ruleradar.AVAILABLE_REPOS.get(name)
        if not cfg:
            continue
        local_path = str(ruleradar.REPOS_DIR / name)
        db.add_repo(
            name         = cfg["name"],
            display_name = cfg["display_name"],
            owner        = cfg["owner"],
            repo         = cfg["repo"],
            branch       = cfg["branch"],
            paths_json   = json.dumps(cfg["paths"]),
            parser       = cfg["parser"],
            local_path   = local_path,
        )
        added.append(cfg["display_name"])

    if not added:
        flash("No valid repositories selected.", "error")
        return redirect(url_for("setup_repos"))

    # Per-rule change-history limit chosen by the installer (default 50)
    try:
        max_events = int(request.form.get("max_events", db.DEFAULT_MAX_EVENTS_PER_RULE))
    except ValueError:
        max_events = db.DEFAULT_MAX_EVENTS_PER_RULE
    if max_events not in db.MAX_EVENTS_CHOICES:
        max_events = db.DEFAULT_MAX_EVENTS_PER_RULE
    db.set_app_setting("max_events_per_rule", str(max_events))

    db.log_activity(
        "admin", "Repository setup completed",
        actor=current_user.username,
        detail=f"repos enabled: {', '.join(added)}; change history kept per rule: {max_events}",
    )

    # Start the initial scan — it will clone and index all pending repos
    _start_background_scan(triggered_by=f"{current_user.username} (initial setup)")

    flash(
        f"Enabled: {', '.join(added)}. "
        "Cloning and indexing has started in the background — "
        "this may take several minutes. Rules will appear once indexing completes.",
        "success",
    )
    return redirect(url_for("dashboard"))


# ── Main pages ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if db.user_count() == 0:
        return redirect(url_for("setup"))
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


def _relative_time(ts_iso: str) -> str:
    """Convert an ISO-format UTC timestamp to a human-readable relative string."""
    if not ts_iso:
        return "never"
    try:
        ts      = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        seconds = int((datetime.now(timezone.utc) - ts).total_seconds())
        if seconds < -60:   # future (e.g. an API key's expiry)
            ahead = -seconds
            if ahead < 3600:
                return f"in {ahead // 60}m"
            if ahead < 86400:
                return f"in {ahead // 3600}h"
            return f"in {ahead // 86400}d"
        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"
    except Exception:
        return ts_iso[:16].replace("T", " ") + " UTC"


app.jinja_env.filters["relative_time"] = _relative_time


def _change_activity(days: int = 90) -> dict:
    """
    Daily rule-change counts for the dashboard activity chart, bucketed by
    day in the display timezone (matching every other date shown in the app).
    Returns {"start": first day, "days": N, "rows": [[day, source, type, n]]}.
    """
    tz        = _get_display_tz()
    today     = datetime.now(tz).date()
    start     = today - timedelta(days=days - 1)
    start_utc = datetime.combine(start, datetime.min.time(), tz).astimezone(timezone.utc)

    counts: dict[tuple[str, str, str], int] = {}
    for minute, source, change_type, n in db.get_change_activity(
        start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    ):
        day = datetime.fromisoformat(minute + "+00:00").astimezone(tz).date().isoformat()
        key = (day, source, change_type)
        counts[key] = counts.get(key, 0) + n

    return {
        "start": start.isoformat(),
        "days":  days,
        "rows":  [[d, s, t, n] for (d, s, t), n in sorted(counts.items())],
    }


def _radar_cells(now: datetime, days: int = 7, per_cell: int = 15) -> list[dict]:
    """
    Rule changes from the last `days` days for the dashboard radar, grouped
    into cells of (source, day ring) where ring 0 = the last 24 hours.

    A single scan can record hundreds of changes with the same timestamp, so
    every cell carries its full count and per-type breakdown, plus up to
    `per_cell` newest individual contacts. The radar draws a sparse cell as
    individual blips and a busy one as a single cluster -- nothing is dropped.
    """
    since = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cells: dict[tuple[str, int], dict] = {}
    for c in db.get_recent_rule_changes(limit=50000, since=since):
        detected = datetime.fromisoformat(c["detected_at"].replace("Z", "+00:00"))
        day      = min(days - 1, max(0, int((now - detected).total_seconds() // 86400)))
        cell     = cells.setdefault((c["source"], day), {
            "source": c["source"], "day": day, "count": 0, "types": {},
            "latest": c["detected_at"], "contacts": [],
        })
        cell["count"] += 1
        cell["types"][c["change_type"]] = cell["types"].get(c["change_type"], 0) + 1
        if len(cell["contacts"]) < per_cell:   # rows arrive newest first
            c["history_url"] = url_for("history", source=c["source"], file_path=c["file_path"])
            cell["contacts"].append(c)
    return list(cells.values())


@app.route("/dashboard")
@login_required
def dashboard():
    """Post-login overview: per-repo cards and aggregate summary stats."""
    now     = datetime.now(timezone.utc)
    cut_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    repos  = db.get_dashboard_repo_stats(cut_24h)
    totals = db.get_dashboard_totals(now.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Annotate repos with a human-readable last-sync string
    for repo in repos:
        repo["last_sync_rel"] = _relative_time(repo.get("last_synced_at", ""))

    # Next-scan countdown
    next_scan  = _next_scheduled_scan()
    delta      = next_scan - now
    h, rem     = divmod(int(delta.total_seconds()), 3600)
    m          = rem // 60
    next_scan_str = f"{h}h {m:02d}m" if h else f"{m}m"

    return render_template(
        "dashboard.html",
        repos=repos,
        totals=totals,
        next_scan_str=next_scan_str,
        activity=_change_activity(),
        radar=_radar_cells(now),
        scan_status=db.get_scan_status(),
    )


@app.route("/detections")
@login_required
def detections():
    """Searchable table of all known detection rules."""
    title       = request.args.get("title",       "").strip()
    description = request.args.get("description", "").strip()
    source      = request.args.get("source",      "")
    mitre       = request.args.get("mitre",       "").strip()
    days        = request.args.get("days",        "")
    details_q   = request.args.get("details_q",   "").strip()
    page        = max(1, int(request.args.get("page", 1) or 1))
    per_page    = 50

    rule_filter_rows  = _get_user_rule_filters()
    filter_active     = bool(session.get("filter_active_detections", False))
    # Apply rule filter only when the user has explicitly enabled "My Rules"
    active_filter     = rule_filter_rows if filter_active else None

    rows, total = db.search_detections(
        title=title, description=description,
        source=source, mitre=mitre, days=days, details_q=details_q,
        page=page, per_page=per_page,
        user_filter_rows=active_filter or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)
    _attach_change_counts(rows)

    # Build set of rule_ids already in the filter for per-row button state
    filtered_rule_ids = {f["rule_id"] for f in rule_filter_rows if f.get("rule_id")}

    return render_template(
        "detections.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        title=title, description=description,
        source=source, mitre=mitre, days=days, details_q=details_q,
        saved_filters=_get_saved_filters(),
        rule_filter_count=len(rule_filter_rows),
        filter_active=filter_active,
        filtered_rule_ids=filtered_rule_ids,
    )


def _attach_change_counts(rows: list[dict]) -> None:
    """Set row["change_count"] — the rule's recorded modifications, the same
    events the History page lists — on every row tied to a rule file."""
    counts = db.count_rule_modifications(
        [(r["source"], r["file_path"]) for r in rows if r.get("file_path")]
    )
    for r in rows:
        r["change_count"] = counts.get((r["source"], r.get("file_path")), 0)


@app.route("/updates")
@login_required
def updates():
    """Feed of new/modified/deleted rule events."""
    source      = request.args.get("source",      "")
    change_type = request.args.get("change_type", "")
    title       = request.args.get("title",       "").strip()
    days        = request.args.get("days",        "")
    details_q   = request.args.get("details_q",   "").strip()
    page        = max(1, int(request.args.get("page", 1) or 1))
    per_page    = 50
    offset      = (page - 1) * per_page

    rule_filter_rows  = _get_user_rule_filters()
    filter_active     = bool(session.get("filter_active_updates", False))
    active_filter     = rule_filter_rows if filter_active else None

    rows, total = db.get_updates(
        source=source, change_type=change_type,
        title=title, days=days, details_q=details_q,
        limit=per_page, offset=offset,
        user_filter_rows=active_filter or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    # Line-change counts for the diff view (modified/renamed/deleted only)
    for row in rows:
        if row.get("diff_text"):
            added, removed = ruleradar.diff_stats(row["diff_text"])
            row["diff_added"], row["diff_removed"] = added, removed
    _attach_change_counts(rows)

    # Build set of rule_ids already favorited, for per-row button state
    filtered_rule_ids = {f["rule_id"] for f in rule_filter_rows if f.get("rule_id")}

    return render_template(
        "updates.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        source=source, change_type=change_type,
        title=title, days=days, details_q=details_q,
        saved_filters=_get_saved_filters(),
        rule_filter_count=len(rule_filter_rows),
        filter_active=filter_active,
        filtered_rule_ids=filtered_rule_ids,
    )


@app.route("/history")
@login_required
def history():
    """
    Pick a rule and see a summary, a timeline of every recorded change
    (each with its diff, reusing the Updates page's diff machinery) and the
    current file behind a toggle. With no rule or search, lists the 5 most
    recent rule changes instead.
    """
    source    = request.args.get("source",    "").strip()
    file_path = request.args.get("file_path", "").strip()
    q         = request.args.get("q",         "").strip()

    selected  = None
    events    = []
    mod_count = 0
    if source and file_path:
        selected = db.get_detection(source, file_path)
        # Every recorded event for the rule (new/modified/renamed/deleted),
        # newest first, for the timeline
        events = db.get_rule_updates(source, file_path, limit=db.get_max_events_per_rule())
        for e in events:
            if e.get("diff_text"):
                added, removed = ruleradar.diff_stats(e["diff_text"])
                e["diff_added"], e["diff_removed"] = added, removed
        mod_count = db.count_rule_modifications([(source, file_path)]).get((source, file_path), 0)

    results = []
    if q and not (source and file_path):
        results, _ = db.search_detections(title=q, per_page=25)

    recent_changes = []
    if not q and not (source and file_path):
        recent_changes = db.get_recent_rule_changes(limit=5)

    return render_template(
        "history.html",
        source=source, file_path=file_path, q=q,
        selected=selected, events=events, mod_count=mod_count, results=results,
        recent_changes=recent_changes,
    )


# ── View-mode toggle routes (All Rules ↔ My Rules, stored in session) ──────────

@app.route("/detections/toggle-filter", methods=["POST"])
@login_required
def toggle_filter_detections():
    """Set the Detections page to All Rules (state=0) or My Rules (state=1)."""
    session["filter_active_detections"] = request.form.get("state") == "1"
    return redirect(url_for("detections"))


@app.route("/updates/toggle-filter", methods=["POST"])
@login_required
def toggle_filter_updates():
    """Set the Updates page to All Rules (state=0) or My Rules (state=1)."""
    session["filter_active_updates"] = request.form.get("state") == "1"
    return redirect(url_for("updates"))


# ── My Rules (favorited rules) ──────────────────────────────────────────────────

@app.route("/my-rules")
@login_required
def my_rules():
    """
    Dedicated page for the user's favorited rules: a Detections-style view
    limited to whatever they've favorited from Detections/Updates, plus easy
    bulk removal.

    Favorite rows (added via the "⊕" button or bulk "Add Selected") always
    carry an exact rule_id, so each matched detection maps back to exactly
    one filter row for removal. CSV-uploaded title/source-only patterns can
    match many rules at once and have no single row to attribute a removal
    to, so those are listed separately as raw criteria.
    """
    filters = db.get_user_rule_filters(current_user.id)

    rows: list[dict] = []
    pattern_filters: list[dict] = []
    if filters:
        filter_id_by_rule_id = {f["rule_id"]: f["id"] for f in filters if f["rule_id"]}
        pattern_filters = [f for f in filters if not f["rule_id"]]
        rows, _ = db.search_detections(user_filter_rows=filters, per_page=500)
        for row in rows:
            row["_filter_id"] = filter_id_by_rule_id.get(row.get("rule_id"))
        _attach_change_counts(rows)

    return render_template(
        "my_rules.html",
        rows=rows,
        filter_count=len(filters),
        pattern_filters=pattern_filters,
    )


@app.route("/settings/rule-filter/sample.csv")
@login_required
def rule_filter_sample_csv():
    """Download a sample CSV showing the expected upload format."""
    sample = (
        "rule_id,title,source\n"
        "7b15a4a0-1f0b-4d8e-9bf3-b8e8e5fb6a77,Mimikatz Use,sigma\n"
        ",PowerShell Download Cradle,splunk\n"
        "abc12345-0000-0000-0000-000000000001,,elastic\n"
    )
    return Response(
        sample,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=rule_filter_sample.csv"},
    )


@app.route("/settings/rule-filter/upload", methods=["POST"])
@login_required
def rule_filter_upload():
    """Parse an uploaded CSV and bulk-insert rows into the user's filter."""
    f = request.files.get("csv_file")
    if not f or not f.filename:
        flash("Please select a CSV file to upload.", "error")
        return redirect(url_for("my_rules"))

    try:
        text    = f.read().decode("utf-8-sig", errors="replace")
        reader  = csv.DictReader(io.StringIO(text))
        rows    = []
        for row in reader:
            rid = (row.get("rule_id") or "").strip()
            pat = (row.get("title")   or "").strip()
            src = (row.get("source")  or "").strip().lower()
            if rid or pat or src:
                rows.append({"rule_id": rid, "title": pat, "source": src})
    except Exception as e:
        flash(f"Could not parse CSV: {e}", "error")
        return redirect(url_for("my_rules"))

    if not rows:
        flash("The CSV contained no valid rows.", "error")
        return redirect(url_for("my_rules"))

    added = db.add_user_rule_filters_bulk(current_user.id, rows)
    total = db.get_user_rule_filter_count(current_user.id)
    db.log_activity("user", f"Rule filter CSV uploaded ({added} added)",
                    actor=current_user.username,
                    detail=f"rows_in_file={len(rows)}, new={added}, total={total}")
    flash(f"My Rules updated: {added} new entr{'ies' if added != 1 else 'y'} added "
          f"({total} total).", "success")
    return redirect(url_for("my_rules"))


@app.route("/settings/rule-filter/clear", methods=["POST"])
@login_required
def rule_filter_clear():
    """Remove all of the current user's rule-filter entries."""
    deleted = db.clear_user_rule_filters(current_user.id)
    db.log_activity("user", f"Rule filter cleared ({deleted} entries removed)",
                    actor=current_user.username)
    flash(f"My Rules cleared — {deleted} entr{'ies' if deleted != 1 else 'y'} removed.",
          "success")
    return redirect(url_for("my_rules"))


@app.route("/my-rules/remove", methods=["POST"])
@login_required
def my_rules_remove():
    """Bulk-remove selected favorites (checkbox form submit from My Rules)."""
    filter_ids = [int(v) for v in request.form.getlist("filter_id") if v.isdigit()]
    deleted = db.delete_user_rule_filters_bulk(current_user.id, filter_ids)
    db.log_activity("user", f"Removed {deleted} favorite rule(s) from My Rules",
                    actor=current_user.username)
    flash(f"Removed {deleted} rule{'s' if deleted != 1 else ''} from My Rules.", "success")
    return redirect(url_for("my_rules"))


@app.route("/settings/rule-filter/add", methods=["POST"])
@login_required
def rule_filter_add():
    """AJAX endpoint: add one rule to the filter. Returns JSON."""
    data        = request.get_json(silent=True) or {}
    rule_id     = (data.get("rule_id")  or "").strip()
    title       = (data.get("title")    or "").strip()
    source      = (data.get("source")   or "").strip().lower()
    inserted    = db.add_user_rule_filter(current_user.id,
                                         rule_id=rule_id,
                                         title_pattern=title,
                                         source=source)
    total = db.get_user_rule_filter_count(current_user.id)
    return jsonify({"ok": True, "inserted": inserted, "count": total})


@app.route("/settings/rule-filter/add-bulk", methods=["POST"])
@login_required
def rule_filter_add_bulk():
    """AJAX endpoint: add multiple rules to the filter. Returns JSON."""
    data  = request.get_json(silent=True) or {}
    rules = data.get("rules") or []
    added = db.add_user_rule_filters_bulk(current_user.id, rules)
    total = db.get_user_rule_filter_count(current_user.id)
    return jsonify({"ok": True, "added": added, "count": total})


@app.route("/settings/rule-filter/delete/<int:filter_id>", methods=["POST"])
@login_required
def rule_filter_delete(filter_id: int):
    """Delete one rule-filter entry by id (must belong to the current user)."""
    db.delete_user_rule_filter(current_user.id, filter_id)
    return redirect(url_for("my_rules"))


# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    """Per-user settings: password, Discord webhook, API key, saved filters, scan status."""
    return _render_settings()


def _render_settings(new_api_key: str = ""):
    """Render the Settings page. `new_api_key` is the plaintext of a key
    created by this very request — the only time it is ever shown."""
    user_settings = db.get_user_settings(current_user.id)
    try:
        saved_filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        saved_filters = []

    # Scan schedule -- raw UTC ISO strings; the template formats them with
    # format_dt / relative_time like every other page
    status    = db.get_scan_status()
    last_scan = status.get("last_scan") or ""
    next_scan = _next_scheduled_scan().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Active repos for the status card
    repos = db.get_all_repos()

    return render_template(
        "settings.html",
        user_settings=user_settings,
        saved_filters=saved_filters,
        last_scan=last_scan,
        next_scan=next_scan,
        repos=repos,
        api_key=db.get_api_key(current_user.id),
        new_api_key=new_api_key,
        expiry_choices=_API_KEY_EXPIRY_LABELS,
        default_expiry=db.API_KEY_DEFAULT_EXPIRY,
        api_base_url=request.host_url.rstrip("/") + "/api/v1",
        api_docs_url=API_DOCS_URL,
    )


# Dropdown labels for db.API_KEY_EXPIRY_CHOICES, in display order
_API_KEY_EXPIRY_LABELS = [
    ("1", "1 day"), ("7", "7 days"), ("30", "30 days"),
    ("90", "90 days"), ("365", "1 year"), ("never", "Never"),
]


def _requested_expiry() -> tuple[str, int | None] | None:
    """The expiry chosen on the form as (choice, days), or None if invalid."""
    choice = request.form.get("expires", db.API_KEY_DEFAULT_EXPIRY)
    if choice not in db.API_KEY_EXPIRY_CHOICES:
        return None
    return choice, db.API_KEY_EXPIRY_CHOICES[choice]


def _show_new_api_key(key: str):
    """Render Settings with the new key shown once. Rendered directly (not
    flashed, which would put the key in the session cookie) and marked
    no-store so the browser doesn't cache it."""
    resp = make_response(_render_settings(new_api_key=key))
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _expiry_detail(choice: str) -> str:
    return "expires: never" if choice == "never" else f"expires in {choice} day(s)"


@app.route("/settings/api-key/generate", methods=["POST"])
@login_required
def settings_api_key_generate():
    """Create the user's single API key and show it once."""
    expiry = _requested_expiry()
    if expiry is None:
        flash("Choose a valid expiration.", "error")
        return redirect(url_for("settings"))
    key = db.create_api_key(current_user.id, expiry[1])
    if key is None:
        flash("You already have an API key. Regenerate or revoke it instead.", "error")
        return redirect(url_for("settings"))
    db.log_activity("user", "API key generated", actor=current_user.username,
                    detail=_expiry_detail(expiry[0]))
    return _show_new_api_key(key)


@app.route("/settings/api-key/regenerate", methods=["POST"])
@login_required
def settings_api_key_regenerate():
    """Revoke the current key and issue a new one in one step."""
    expiry = _requested_expiry()
    if expiry is None:
        flash("Choose a valid expiration.", "error")
        return redirect(url_for("settings"))
    key = db.replace_api_key(current_user.id, expiry[1])
    db.log_activity("user", "API key regenerated (previous key revoked)",
                    actor=current_user.username, detail=_expiry_detail(expiry[0]))
    return _show_new_api_key(key)


@app.route("/settings/api-key/revoke", methods=["POST"])
@login_required
def settings_api_key_revoke():
    if db.revoke_api_key(current_user.id):
        db.log_activity("user", "API key revoked", actor=current_user.username)
        flash("API key revoked. Anything using it will stop working immediately.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    current_pw = request.form.get("current_password", "")
    new_pw     = request.form.get("new_password", "")
    confirm    = request.form.get("confirm_password", "")

    row = db.get_user_by_id(current_user.id)
    if not bcrypt.checkpw(current_pw.encode(), row["password_hash"].encode()):
        db.log_activity("user", "Failed password change — incorrect current password",
                        actor=current_user.username, level="warning")
        flash("Current password is incorrect.", "error")
    elif new_pw != confirm:
        flash("New passwords do not match.", "error")
    elif len(new_pw) < 8:
        flash("New password must be at least 8 characters.", "error")
    else:
        db.update_user_password(current_user.id,
                                bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode())
        db.log_activity("user", "Password changed", actor=current_user.username)
        flash("Password updated successfully.", "success")

    return redirect(url_for("settings"))


@app.route("/settings/discord", methods=["POST"])
@login_required
def settings_discord():
    webhook = request.form.get("discord_webhook", "").strip()
    if not _is_valid_discord_webhook(webhook):
        flash(
            "Invalid Discord webhook URL. It must start with "
            "https://discord.com/api/webhooks/",
            "error",
        )
        return redirect(url_for("settings"))
    db.update_user_discord(current_user.id, webhook)
    db.log_activity("user",
                    "Discord webhook updated" if webhook else "Discord webhook cleared",
                    actor=current_user.username)
    flash("Discord webhook saved.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/discord/test", methods=["POST"])
@login_required
def settings_discord_test():
    user_settings = db.get_user_settings(current_user.id)
    webhook = user_settings.get("discord_webhook", "").strip()
    if not webhook:
        flash("No Discord webhook configured — save one first.", "error")
        return redirect(url_for("settings"))
    try:
        _tz     = _get_display_tz()
        _tzname = db.get_app_setting("timezone", "UTC")
        ts      = datetime.now(timezone.utc).astimezone(_tz).strftime("%Y-%m-%d %H:%M") + f" {_tzname}"
        updates_url = request.host_url.rstrip("/") + url_for("updates")
        test_msg = "\n".join([
            f"**RuleRadar — {ts}**",
            "• SigmaHQ/sigma: 2 new, 1 modified",
            "  ↳ Detect PowerShell Download Cradle (new)",
            "  ↳ Suspicious LSASS Memory Access (modified)",
            "  ↳ NTDS.dit Access via NTDSUtil (new)",
            "• splunk/security_content: 1 new",
            "  ↳ Windows Credential Dumping via Registry (new)",
            "",
            f"🔗 View updates: {updates_url}",
            f"\n✅ This is a test notification for **{current_user.username}** — your webhook is working!",
        ])
        ruleradar.send_discord(webhook, test_msg)
        db.log_activity("user", "Discord webhook test sent", actor=current_user.username)
        flash("Test notification sent to Discord.", "success")
    except Exception as e:
        db.log_activity("user", f"Discord webhook test failed: {e}",
                        actor=current_user.username, level="error")
        flash(f"Failed to send test notification: {e}", "error")
    return redirect(url_for("settings"))


@app.route("/settings/filters/add", methods=["POST"])
@login_required
def settings_filters_add():
    name        = request.form.get("name",        "").strip()
    source      = request.form.get("source",      "")
    change_type = request.form.get("change_type", "")
    title       = request.form.get("title",       "").strip()
    mitre       = request.form.get("mitre",       "").strip()
    days        = request.form.get("days",        "")

    if not name:
        flash("Filter name is required.", "error")
        return redirect(url_for("settings"))

    user_settings = db.get_user_settings(current_user.id)
    try:
        filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        filters = []

    if any(f.get("name") == name for f in filters):
        flash(f"A filter named \"{name}\" already exists.", "error")
        return redirect(url_for("settings"))

    filters.append({
        "id":          uuid.uuid4().hex[:10],
        "name":        name,
        "source":      source,
        "change_type": change_type,
        "title":       title,
        "mitre":       mitre,
        "days":        days,
    })
    db.update_user_filters(current_user.id, json.dumps(filters))
    db.log_activity("user", f"Saved filter '{name}' added", actor=current_user.username,
                    detail=(
                        f"source={source or 'all'}, change_type={change_type or 'all'}, "
                        f"title={title or ''}, mitre={mitre or ''}, days={days or ''}"
                    ))
    flash(f"Filter \"{name}\" saved.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/filters/delete", methods=["POST"])
@login_required
def settings_filters_delete():
    filter_id = request.form.get("filter_id", "")
    user_settings = db.get_user_settings(current_user.id)
    try:
        filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        filters = []

    removed  = [f for f in filters if f.get("id") == filter_id]
    filters  = [f for f in filters if f.get("id") != filter_id]
    db.update_user_filters(current_user.id, json.dumps(filters))
    removed_name = removed[0].get("name", filter_id) if removed else filter_id
    db.log_activity("user", f"Saved filter '{removed_name}' removed",
                    actor=current_user.username)
    flash("Filter removed.", "success")
    return redirect(url_for("settings"))


# ── Admin ──────────────────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin():
    users  = db.get_all_users()
    repos  = db.get_all_repos()

    # Which available repos are not yet configured
    configured_names = {r["name"] for r in repos}
    unconfigured     = [
        cfg for name, cfg in ruleradar.AVAILABLE_REPOS.items()
        if name not in configured_names
    ]

    return render_template(
        "admin.html",
        users=users,
        repos=repos,
        unconfigured=unconfigured,
        current_user_id=current_user.id,
        current_timezone=db.get_app_setting("timezone", "UTC"),
        common_timezones=COMMON_TIMEZONES,
        max_fetch_failures=ruleradar.MAX_CONSECUTIVE_FETCH_FAILURES,
        max_events_per_rule=db.get_max_events_per_rule(),
        now_utc=db.now_iso(),   # to mark expired API keys
    )


@app.route("/admin/settings/timezone", methods=["POST"])
@admin_required
def admin_settings_timezone():
    tz_name = request.form.get("timezone", "UTC").strip()
    valid_names = {tz for tz, _ in COMMON_TIMEZONES}
    if tz_name not in valid_names:
        flash("Invalid timezone selection.", "error")
        return redirect(url_for("admin"))
    db.set_app_setting("timezone", tz_name)
    db.log_activity("admin", f"Timezone set to {tz_name}", actor=current_user.username)
    flash(f"Timezone updated to {tz_name}.", "success")
    return redirect(url_for("admin"))


# ── Admin — on-demand scan ────────────────────────────────────────────────────

@app.route("/admin/scan/now", methods=["POST"])
@admin_required
def admin_scan_now():
    status = db.get_scan_status()
    if status.get("is_scanning"):
        flash("A scan is already in progress.", "error")
    else:
        _start_background_scan(triggered_by=f"{current_user.username} (manual)")
        flash("Scan started. The nav badge will update as it runs.", "success")
    return redirect(url_for("admin"))


# ── Admin — repository management ──────────────────────────────────────────────

@app.route("/admin/repos/add", methods=["POST"])
@admin_required
def admin_repos_add():
    """
    Add a repository to monitor.  Accepts either:
      - a name from AVAILABLE_REPOS (pre-filled config), or
      - a custom repo, specified as a GitHub URL (owner/repo/branch/path are
        parsed from it — see parse_github_url) plus paths/parser.
    """
    # Collapse anything other than a-z/0-9/-/_ to a single underscore. The
    # sanitized name is used as both a URL path segment (/admin/repos/<name>/…)
    # and a filesystem directory name (REPOS_DIR/<name>) — an unsanitized
    # "/" (e.g. from pasting a display name like "Anvilogic / Armory") breaks
    # the toggle/remove routes with a 404 and splits the clone across nested
    # directories.
    name = request.form.get("name", "").strip().lower()
    name = re.sub(r"[^a-z0-9_-]+", "_", name).strip("_")

    # Check for pre-defined config
    pre = ruleradar.AVAILABLE_REPOS.get(name) if name else None
    if pre:
        cfg = pre
    else:
        # Custom repo — owner/repo/branch/path come from a pasted GitHub URL
        # rather than separate fields.
        github_url = request.form.get("github_url", "").strip()
        parsed = parse_github_url(github_url)
        if not parsed:
            flash(
                "Enter a valid GitHub repository URL, e.g. "
                "https://github.com/owner/repo",
                "error",
            )
            return redirect(url_for("admin"))

        owner = parsed["owner"]
        repo  = parsed["repo"]

        if not name:
            name = re.sub(r"[^a-z0-9_-]+", "_", repo.lower()).strip("_")
        if not name:
            flash("Could not derive a repository identifier from that URL — set one manually.", "error")
            return redirect(url_for("admin"))

        # Branch precedence: explicit field > parsed from a /tree/<branch>/
        # URL > the remote's actual default branch > "main" as a last resort.
        branch = (
            request.form.get("branch", "").strip()
            or parsed["branch"]
            or detect_default_branch(owner, repo)
            or "main"
        )
        if branch.startswith("-"):
            # branch is passed as a literal git argument (git_run([..., branch]));
            # a leading "-" could be misread as a flag rather than a ref name.
            # git itself never produces ref names starting with "-", so this
            # only rejects malformed input, never a real branch.
            flash("Branch name can't start with '-'.", "error")
            return redirect(url_for("admin"))
        display_name = request.form.get("display_name", "").strip() or f"{owner} / {repo}"
        paths_raw     = request.form.get("paths", "").strip() or (parsed["path"] or "")
        parser        = request.form.get("parser", "sigma")

        paths = [p.strip().rstrip("/") + "/" for p in paths_raw.split(",") if p.strip()]
        has_dotdot   = any(seg == ".." for p in paths for seg in p.replace("\\", "/").split("/"))
        has_absolute = any(p.startswith(("/", "\\")) for p in paths)
        if has_dotdot or has_absolute:
            flash("Repository paths may not be absolute or contain '..'.", "error")
            return redirect(url_for("admin"))
        if not paths:
            paths = [""]

        cfg = {
            "name":         name,
            "display_name": display_name,
            "owner":        owner,
            "repo":         repo,
            "branch":       branch,
            "paths":        paths,
            "parser":       parser,
        }

    local_path = str(ruleradar.REPOS_DIR / name)
    db.add_repo(
        name         = cfg["name"],
        display_name = cfg["display_name"],
        owner        = cfg["owner"],
        repo         = cfg["repo"],
        branch       = cfg["branch"],
        paths_json   = json.dumps(cfg["paths"]),
        parser       = cfg["parser"],
        local_path   = local_path,
    )
    db.log_activity("admin", f"Repository '{name}' added",
                    actor=current_user.username,
                    detail=f"{cfg['owner']}/{cfg['repo']} ({cfg['branch']})")

    # Kick off a scan so the new repo gets cloned immediately
    _start_background_scan(triggered_by=f"{current_user.username} (repo add)")

    flash(
        f"Repository \"{cfg['display_name']}\" added and queued for cloning. "
        "The scan has started in the background.",
        "success",
    )
    return redirect(url_for("admin"))


@app.route("/admin/repos/<name>/toggle", methods=["POST"])
@admin_required
def admin_repos_toggle(name: str):
    """Enable or disable a repository (pauses scanning without removing data)."""
    repo = db.get_repo_by_name(name)
    if not repo:
        abort(404)

    currently_enabled = bool(repo["enabled"])
    db.set_repo_enabled(name, not currently_enabled)
    action = "disabled" if currently_enabled else "re-enabled"
    db.log_activity("admin", f"Repository '{name}' {action}",
                    actor=current_user.username)
    flash(f"Repository \"{repo['display_name']}\" {action}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/repos/<name>/remove", methods=["POST"])
@admin_required
def admin_repos_remove(name: str):
    """
    Remove a repository from monitoring.
    The local clone and all detections for this source are optionally deleted.
    """
    repo = db.get_repo_by_name(name)
    if not repo:
        abort(404)

    delete_data = request.form.get("delete_data") == "1"

    db.remove_repo(name)

    if delete_data:
        # Remove detections + updates for this source from the DB
        with db.get_conn() as conn:
            conn.execute("DELETE FROM detections WHERE source = ?", (name,))
            conn.execute("DELETE FROM updates    WHERE source = ?", (name,))

        # Remove the local git clone
        local = Path(repo["local_path"])
        if local.exists():
            try:
                shutil.rmtree(str(local))
            except Exception as e:
                print(f"  Warning: could not remove {local}: {e}", flush=True)

    db.log_activity(
        "admin", f"Repository '{name}' removed",
        actor=current_user.username,
        detail=f"delete_data={delete_data}",
    )
    flash(
        f"Repository \"{repo['display_name']}\" removed"
        + (" (data deleted)" if delete_data else " (data kept)") + ".",
        "success",
    )
    return redirect(url_for("admin"))


# ── Admin — user management ────────────────────────────────────────────────────

@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm", "")
    is_admin = bool(request.form.get("is_admin"))

    if not username or not password:
        flash("Username and password are required.", "error")
    elif password != confirm:
        flash("Passwords do not match.", "error")
    elif len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
    elif db.get_user_by_username(username):
        flash(f"Username \"{username}\" is already taken.", "error")
    else:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db.create_user(username, pw_hash, is_admin=is_admin)
        db.log_activity("admin", f"User '{username}' created",
                        actor=current_user.username,
                        detail=f"admin={is_admin}")
        flash(f"User \"{username}\" created.", "success")

    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(user_id: int):
    new_password = request.form.get("new_password", "")
    confirm      = request.form.get("confirm", "")

    if not new_password:
        flash("New password is required.", "error")
    elif new_password != confirm:
        flash("Passwords do not match.", "error")
    elif len(new_password) < 8:
        flash("Password must be at least 8 characters.", "error")
    else:
        pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        db.update_user_password(user_id, pw_hash)
        row = db.get_user_by_id(user_id)
        db.log_activity("admin", f"Password reset for '{row['username']}'",
                        actor=current_user.username)
        flash(f"Password reset for \"{row['username']}\".", "success")

    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id: int):
    if user_id == current_user.id:
        flash("You cannot change your own admin status.", "error")
        return redirect(url_for("admin"))

    row = db.get_user_by_id(user_id)
    if not row:
        abort(404)

    currently_admin = bool(row["is_admin"])
    if currently_admin and db.admin_count() <= 1:
        flash("Cannot remove the last admin account.", "error")
        return redirect(url_for("admin"))

    db.set_user_admin(user_id, not currently_admin)
    action = "revoked from" if currently_admin else "granted to"
    db.log_activity("admin", f"Admin access {action} '{row['username']}'",
                    actor=current_user.username)
    flash(f"Admin access {'revoked' if currently_admin else 'granted'} for "
          f"\"{row['username']}\".", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id: int):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin"))

    row = db.get_user_by_id(user_id)
    if not row:
        abort(404)

    if bool(row["is_admin"]) and db.admin_count() <= 1:
        flash("Cannot delete the last admin account.", "error")
        return redirect(url_for("admin"))

    db.delete_user(user_id)
    db.log_activity("admin", f"User '{row['username']}' deleted",
                    actor=current_user.username)
    flash(f"User \"{row['username']}\" deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/revoke-api-key", methods=["POST"])
@admin_required
def admin_revoke_api_key(user_id: int):
    row = db.get_user_by_id(user_id)
    if not row:
        abort(404)
    if db.revoke_api_key(user_id):
        db.log_activity("admin", f"API key revoked for '{row['username']}'",
                        actor=current_user.username)
        flash(f"API key revoked for \"{row['username']}\".", "success")
    return redirect(url_for("admin"))


# ── Internal JSON endpoints (browser session) ─────────────────────────────────

@app.route("/api/scan/status")
@login_required
def api_scan_status():
    """
    Returns current scan status as JSON.
    Polled every 15 s by the nav-bar badge (layout.html).
    Also includes per-repo statuses so the setup page can show progress.
    """
    status = db.get_scan_status()
    result = dict(status)
    result["next_scan"] = _next_scheduled_scan().isoformat()
    # Include per-repo status for the setup / admin pages
    result["repos"] = [
        {
            "name":          r["name"],
            "display_name":  r["display_name"],
            "status":        r["status"],
            "error_msg":     r["error_msg"],
            "last_synced_at": r["last_synced_at"],
        }
        for r in db.get_all_repos()
    ]
    return jsonify(result)


@app.route("/api/rule-suggest")
@login_required
def api_rule_suggest():
    """
    Live search dropdown on Detections, Updates and History (layout.html).
    ?q=<title text>&scope=detections|updates|history — up to 8 matching rules.
    """
    q     = request.args.get("q", "").strip()[:200]
    scope = request.args.get("scope", "detections")
    if scope not in ("detections", "updates", "history"):
        scope = "detections"
    if len(q) < 2:
        return jsonify(results=[])

    results = db.suggest_rules(q, scope=scope)
    for r in results:
        r["history_url"] = url_for("history", source=r["source"], file_path=r["file_path"])
    return jsonify(results=results)


@app.route("/api/dashboard/stats")
@login_required
def api_dashboard_stats():
    """
    Returns dashboard stats as JSON for the live-update poller in dashboard.html.
    Called every 5 s while a scan is in progress so the repo cards and summary
    bar update in real-time without a full page reload.
    """
    now     = datetime.now(timezone.utc)
    cut_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    repos  = db.get_dashboard_repo_stats(cut_24h)
    totals = db.get_dashboard_totals(now.strftime("%Y-%m-%dT%H:%M:%SZ"))

    for repo in repos:
        repo["last_sync_rel"] = _relative_time(repo.get("last_synced_at", ""))

    next_scan  = _next_scheduled_scan()
    delta      = next_scan - now
    h, rem     = divmod(int(delta.total_seconds()), 3600)
    m          = rem // 60
    next_scan_str = f"{h}h {m:02d}m" if h else f"{m}m"

    status = db.get_scan_status()

    return jsonify({
        "repos":         repos,
        "totals":        totals,
        "next_scan_str": next_scan_str,
        "is_scanning":   bool(status.get("is_scanning")),
        "last_scan":     status.get("last_scan") or "",
    })


@app.route("/api/repo-sizes")
@login_required
def api_repo_sizes():
    """
    Fetch rough download size estimates for the available repositories
    from the GitHub API (/repos/{owner}/{repo} returns size in KB).
    No token required — public repos are accessible without auth.
    """
    sizes: dict[str, dict] = {}
    for name, cfg in ruleradar.AVAILABLE_REPOS.items():
        url = f"https://api.github.com/repos/{cfg['owner']}/{cfg['repo']}"
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "ruleradar/1.0")
            req.add_header("Accept", "application/vnd.github.v3+json")
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            size_kb  = data.get("size", 0)
            size_mb  = round(size_kb / 1024, 1)
            sizes[name] = {"size_mb": size_mb, "ok": True}
        except Exception as e:
            sizes[name] = {"size_mb": None, "ok": False, "error": str(e)}

    return jsonify(sizes)


# ── Admin activity log ─────────────────────────────────────────────────────────

@app.route("/admin/activity")
@admin_required
def admin_activity():
    category = request.args.get("category", "")
    level    = request.args.get("level", "")
    actor    = request.args.get("actor", "").strip()
    page     = max(1, int(request.args.get("page", 1) or 1))
    per_page = 100
    offset   = (page - 1) * per_page

    rows, total = db.get_activity_log(
        category=category, level=level, actor=actor,
        limit=per_page, offset=offset,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "admin_activity.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        category=category, level=level, actor=actor,
    )



# ── Public API v1 (API-key auth) ───────────────────────────────────────────────
#
# Read-only JSON API for scripts and tools. Every request must send the
# caller's key as "Authorization: Bearer rr_..." — browser sessions are not
# accepted here, so the API can't be driven cross-site from a logged-in
# browser. Keys are created and revoked on /settings (one per user).

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Full endpoint and parameter reference lives in the GitHub wiki, linked
# from the API Key card on /settings
API_DOCS_URL = "https://github.com/McSloats/RuleRadar/wiki/API"

_API_RATE_WINDOW     = 60    # seconds
_API_RATE_MAX        = 120   # requests per window per key
_API_AUTH_FAIL_MAX   = 10    # failed authentications per window per IP
_API_TOUCH_INTERVAL  = 60    # seconds between last_used_at writes per key
_API_MAX_PER_PAGE    = 200
_API_MAX_INT         = 1_000_000   # bound for page/days so SQLite never sees an oversized integer

_api_requests:      dict[int, list[float]] = defaultdict(list)
_api_auth_failures: dict[str, list[float]] = defaultdict(list)
_api_lock = threading.Lock()


def _api_error(status: int, message: str, **headers):
    resp = jsonify(error={"status": status, "message": message})
    resp.status_code = status
    for k, v in headers.items():
        resp.headers[k.replace("_", "-")] = v
    return resp


def _window_hits(bucket: list[float], now: float) -> list[float]:
    bucket[:] = [t for t in bucket if now - t < _API_RATE_WINDOW]
    return bucket


@api_v1.before_request
def _api_authenticate():
    """Resolve the Bearer key to a user (in g.api_user) or reject the request."""
    ip  = request.remote_addr or ""
    now = time.time()

    # The key is checked before the failure limit, so a valid key always
    # works: junk requests from a shared IP (NAT, reverse proxy) can't lock
    # out real users, and 256-bit keys can't be guessed anyway. The failure
    # limit throttles bad callers and stops them flooding the activity log.
    scheme, _, key = request.headers.get("Authorization", "").partition(" ")
    user = db.authenticate_api_key(key.strip()) if scheme.lower() == "bearer" else None
    expired = bool(user and user["expired"])
    if user is None or expired:
        with _api_lock:
            failures = _window_hits(_api_auth_failures[ip], now)
            over_limit = len(failures) >= _API_AUTH_FAIL_MAX
            if not over_limit:
                failures.append(now)
        if over_limit:
            return _api_error(429, "Too many failed authentication attempts. Try again later.",
                              Retry_After=str(_API_RATE_WINDOW))
        if expired:
            db.log_activity("auth", "API request with expired key",
                            actor=user["username"], detail=f"ip={ip} path={request.path}",
                            level="warning")
            return _api_error(401, "API key has expired. Regenerate it on the Settings page.",
                              WWW_Authenticate='Bearer realm="RuleRadar", error="invalid_token"')
        db.log_activity("auth", "API request with missing or invalid key",
                        actor="anonymous", detail=f"ip={ip} path={request.path}",
                        level="warning")
        return _api_error(401, "Missing or invalid API key. Send 'Authorization: Bearer <key>'.",
                          WWW_Authenticate='Bearer realm="RuleRadar"')

    with _api_lock:
        hits = _window_hits(_api_requests[user["id"]], now)
        if len(hits) >= _API_RATE_MAX:
            return _api_error(429, f"Rate limit exceeded ({_API_RATE_MAX} requests per minute).",
                              Retry_After=str(_API_RATE_WINDOW))
        hits.append(now)

    # Throttle the last-used write so busy scripts don't write on every call
    last = user.get("last_used_at") or ""
    if not last or (datetime.now(timezone.utc)
                    - datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    ).total_seconds() >= _API_TOUCH_INTERVAL:
        db.touch_api_key(user["id"], ip)

    g.api_user = user


@api_v1.after_request
def _api_no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


class _BadParam(Exception):
    pass


@api_v1.errorhandler(_BadParam)
def _api_bad_param(e):
    return _api_error(400, str(e))


def _int_arg(name: str, default: int, lo: int, hi: int = _API_MAX_INT) -> int:
    raw = request.args.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise _BadParam(f"'{name}' must be an integer.")
    if not lo <= value <= hi:
        raise _BadParam(f"'{name}' must be between {lo} and {hi}.")
    return value


def _since_arg() -> str:
    """Parse ?since= (ISO 8601 date or datetime; no offset means UTC) into
    the UTC '%Y-%m-%dT%H:%M:%SZ' form the database stores."""
    raw = request.args.get("since", "").strip()
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        raise _BadParam("'since' must be an ISO 8601 date or datetime, e.g. 2026-10-01 or 2026-10-01T12:00:00Z.")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bool_arg(name: str) -> bool:
    return request.args.get(name, "").strip().lower() in ("1", "true", "yes")


def _split(value: str, sep: str) -> list[str]:
    return [v.strip() for v in (value or "").split(sep) if v.strip()]


def _api_detection(row: dict, include_raw: bool = False) -> dict:
    out = {
        "source":           row["source"],
        "file_path":        row["file_path"],
        "rule_id":          row.get("rule_id", ""),
        "title":            row["title"],
        "description":      row["description"],
        "author":           row.get("author", ""),
        "status":           row.get("rule_status", ""),
        "date":             row.get("rule_date", ""),
        "mitre_techniques": _split(row.get("mitre_techniques", ""), "|"),
        "references":       _split(row.get("refs", ""), "\n"),
        "detection_logic":  row.get("detection_logic", ""),
        "spl":              row.get("spl", ""),
        "rule_url":         row["rule_url"],
        "first_seen":       row["first_seen"],
        "last_updated":     row["last_updated"],
    }
    if include_raw:
        out["raw_content"] = row.get("raw_content", "")
    return out


def _api_event(row: dict, include_diff: bool = False) -> dict:
    out = {
        "id":          row["id"],
        "source":      row["source"],
        "change_type": row["change_type"],
        "title":       row["title"],
        "detected_at": row["detected_at"],
        "url":         row["rule_url"],
    }
    if row["change_type"] == "release":
        out["tag_name"] = row.get("tag_name") or ""
        out["body"]     = row.get("body") or ""
        return out
    out["file_path"] = row["file_path"]
    if "rule_id" in row:
        out["rule_id"]          = row.get("rule_id") or ""
        out["mitre_techniques"] = _split(row.get("mitre_techniques") or "", "|")
    diff = row.get("diff_text") or ""
    added, removed = ruleradar.diff_stats(diff) if diff else (0, 0)
    out["lines_added"], out["lines_removed"] = added, removed
    if include_diff:
        out["diff"] = diff
    return out


def _paginated(items: list, total: int, page: int, per_page: int):
    return jsonify(
        data=items,
        pagination={
            "page":        page,
            "per_page":    per_page,
            "total":       total,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        },
    )


def _api_user_filters() -> list[dict] | None:
    """The caller's My Rules filter rows when ?my_rules=true, else None.
    An empty My Rules list matches nothing (the db helpers treat an empty
    list as "no filter", so callers must check for it)."""
    if not _bool_arg("my_rules"):
        return None
    return db.get_user_rule_filters(g.api_user["id"])


@api_v1.route("/me")
def api_v1_me():
    """Who the key belongs to — handy for checking a key works."""
    u = g.api_user
    return jsonify(
        username=u["username"], is_admin=bool(u["is_admin"]),
        key_prefix=u["key_prefix"], key_created_at=u["key_created_at"],
        key_expires_at=u["key_expires_at"] or None,
    )


@api_v1.route("/status")
def api_v1_status():
    """Scan status: last and next scan, counts from the last scan, per-repo state."""
    status = db.get_scan_status()
    return jsonify(
        is_scanning=bool(status.get("is_scanning")),
        last_scan=status.get("last_scan") or "",
        last_scan_new=status.get("new_count", 0),
        last_scan_modified=status.get("mod_count", 0),
        next_scan=_next_scheduled_scan().strftime("%Y-%m-%dT%H:%M:%SZ"),
        repos=[
            {"name": r["name"], "status": r["status"], "error": r["error_msg"],
             "last_synced_at": r["last_synced_at"]}
            for r in db.get_all_repos()
        ],
    )


@api_v1.route("/repos")
def api_v1_repos():
    """Monitored repositories (local disk paths are not exposed)."""
    return jsonify(data=[
        {
            "name":           r["name"],
            "display_name":   r["display_name"],
            "url":            f"https://github.com/{r['owner']}/{r['repo']}",
            "branch":         r["branch"],
            "parser":         r["parser"],
            "enabled":        bool(r["enabled"]),
            "status":         r["status"],
            "last_sha":       r["last_sha"],
            "last_synced_at": r["last_synced_at"],
        }
        for r in db.get_all_repos()
    ])


@api_v1.route("/detections")
def api_v1_detections():
    """
    Search current rules, newest-updated first.
    ?q=title text  &description=  &source=sigma  &mitre=MITRE technique ID (T1059)
    &details=keyword in logic/author/refs/raw file  &days=N  &since=ISO date
    &my_rules=true  &include_raw=true  &page=1  &per_page=50 (max 200)
    """
    page     = _int_arg("page", 1, 1)
    per_page = _int_arg("per_page", 50, 1, _API_MAX_PER_PAGE)
    days     = _int_arg("days", 0, 1)
    filters  = _api_user_filters()
    if filters == []:
        return _paginated([], 0, page, per_page)
    rows, total = db.search_detections(
        title=request.args.get("q", "").strip(),
        description=request.args.get("description", "").strip(),
        source=request.args.get("source", "").strip(),
        mitre=request.args.get("mitre", "").strip(),
        days=str(days) if days else "",
        details_q=request.args.get("details", "").strip(),
        since=_since_arg(),
        page=page, per_page=per_page,
        user_filter_rows=filters,
    )
    include_raw = _bool_arg("include_raw")
    return _paginated([_api_detection(r, include_raw) for r in rows], total, page, per_page)


@api_v1.route("/detections/<source>/<path:file_path>")
def api_v1_detection(source: str, file_path: str):
    """One rule, including its raw file and number of recorded modifications."""
    row = db.get_detection(source, file_path)
    if not row:
        return _api_error(404, "No rule with that source and file path.")
    out = _api_detection(row, include_raw=True)
    out["modification_count"] = db.count_rule_modifications(
        [(source, file_path)]).get((source, file_path), 0)
    return jsonify(out)


@api_v1.route("/history/<source>/<path:file_path>")
def api_v1_history(source: str, file_path: str):
    """Every recorded change event for one rule, newest first, with diffs.
    Works for deleted rules too, as long as their events are still kept."""
    events = db.get_rule_updates(source, file_path, limit=db.get_max_events_per_rule())
    if not events and not db.get_detection(source, file_path):
        return _api_error(404, "No rule or recorded history with that source and file path.")
    return jsonify(
        source=source, file_path=file_path,
        data=[_api_event(e, include_diff=True) for e in events],
    )


@api_v1.route("/updates")
def api_v1_updates():
    """
    Change feed (new/modified/deleted/renamed rules and repo releases), newest first.
    ?source=  &change_type=new|modified|deleted|renamed|release  &q=title text
    &details=keyword  &days=N  &since=ISO date  &my_rules=true  &include_diff=true
    &page=1  &per_page=50 (max 200)
    """
    change_type = request.args.get("change_type", "").strip()
    if change_type not in ("", "new", "modified", "deleted", "renamed", "release"):
        raise _BadParam("'change_type' must be one of new, modified, deleted, renamed, release.")
    page     = _int_arg("page", 1, 1)
    per_page = _int_arg("per_page", 50, 1, _API_MAX_PER_PAGE)
    days     = _int_arg("days", 0, 1)
    filters  = _api_user_filters()
    if filters == []:
        return _paginated([], 0, page, per_page)
    rows, total = db.get_updates(
        source=request.args.get("source", "").strip(),
        change_type=change_type,
        title=request.args.get("q", "").strip(),
        days=str(days) if days else "",
        details_q=request.args.get("details", "").strip(),
        since=_since_arg(),
        limit=per_page, offset=(page - 1) * per_page,
        user_filter_rows=filters,
    )
    include_diff = _bool_arg("include_diff")
    return _paginated([_api_event(r, include_diff) for r in rows], total, page, per_page)


@api_v1.route("/my-rules")
def api_v1_my_rules():
    """The caller's My Rules list: the filter rows and the rules they match."""
    filters = db.get_user_rule_filters(g.api_user["id"])
    rows = db.search_detections(user_filter_rows=filters, per_page=500)[0] if filters else []
    return jsonify(
        filters=[{"rule_id": f["rule_id"], "title_pattern": f["title_pattern"],
                  "source": f["source"]} for f in filters],
        data=[_api_detection(r) for r in rows],
    )


app.register_blueprint(api_v1)


@app.errorhandler(HTTPException)
def _http_error(e: HTTPException):
    """JSON errors under /api/v1 (unknown endpoint, wrong method, ...);
    the default HTML error pages everywhere else."""
    if request.path.startswith("/api/v1/") or request.path == "/api/v1":
        return _api_error(e.code or 500, e.description or e.name)
    return e


# ── Health check ───────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Flask's development server, for running this file directly while
    # developing. Production (start.py, Docker) serves the app with gunicorn
    # using webapp/gunicorn.conf.py instead.
    # threaded=True lets concurrent requests (page loads + 15-s badge poll) be
    # handled in parallel rather than queueing behind each other.
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

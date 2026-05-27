#!/usr/bin/env python3
"""
RuleRadar web interface.

Two main pages:
  /detections  — searchable, paginated table of every known detection rule
  /updates     — feed of new/modified rule events (change log)

Auth: Flask-Login with bcrypt-hashed passwords.
      First visit redirects to /setup to create the initial admin account.
      The setup page is disabled permanently once any user exists.

Scan triggering:
  - Automatically on page load (if last scan was >30 min ago)
  - Manually via the "Scan Now" button (POST /api/scan/trigger)
  - Independently by the hourly scheduler process
  All three paths share the threading.Lock inside ruleradar.run_scan(),
  so concurrent calls are harmless.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Allow importing database and ruleradar from the project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import bcrypt
import database as db
import ruleradar

from flask import (
    Flask, flash, jsonify, redirect, render_template,
    request, url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)


def _load_secret_key() -> str:
    """
    Load or generate a persistent secret key used to sign session cookies.
    Stored alongside the database so it survives container restarts when the
    DB volume is mounted (Docker).  Falls back to the project root locally.
    """
    key_path = db.DB_PATH.parent / ".secret_key"
    if key_path.exists():
        return key_path.read_text().strip()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    key_path.write_text(key)
    return key


app.secret_key = _load_secret_key()

login_manager = LoginManager(app)
login_manager.login_view = "login"          # type: ignore[assignment]
login_manager.login_message = "Please log in to access RuleRadar."
login_manager.login_message_category = "error"

# Ensure DB tables exist whenever the webapp starts
db.init_db()


# ── User model for Flask-Login ─────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id       = row["id"]
        self.username = row["username"]


@login_manager.user_loader
def load_user(user_id: str):
    row = db.get_user_by_id(int(user_id))
    return User(row) if row else None


# ── Background scan helper ─────────────────────────────────────────────────────

_STALE_MINUTES = 30   # trigger a background scan if last scan is older than this


def _maybe_trigger_scan():
    """
    Start a background scan if:
      - no scan is currently running, AND
      - the last scan finished more than _STALE_MINUTES ago (or never ran)

    Returns immediately; the scan runs in a daemon thread.
    """
    status = db.get_scan_status()
    if status.get("is_scanning"):
        return

    last = status.get("last_scan")
    if last:
        last_dt     = datetime.fromisoformat(last.replace("Z", "+00:00"))
        age_minutes = (datetime.now(timezone.utc) - last_dt).total_seconds() / 60
        if age_minutes < _STALE_MINUTES:
            return

    def _run():
        try:
            cfg_path = ROOT / "config.json"
            with open(cfg_path) as fh:
                cfg = json.load(fh)
            ruleradar.run_scan(cfg)
        except Exception as e:
            print(f"  Background scan error: {e}", flush=True)

    threading.Thread(target=_run, daemon=True).start()


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """
    First-run setup — create the initial admin account.
    Redirects to /login once any user exists.
    """
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
            db.create_user(username, pw_hash)
            flash("Account created — please log in.", "success")
            return redirect(url_for("login"))

    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if db.user_count() == 0:
        return redirect(url_for("setup"))
    if current_user.is_authenticated:
        return redirect(url_for("detections"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row      = db.get_user_by_username(username)
        if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
            login_user(User(row), remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("detections"))
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── Main page routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    if db.user_count() == 0:
        return redirect(url_for("setup"))
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return redirect(url_for("detections"))


@app.route("/detections")
@login_required
def detections():
    _maybe_trigger_scan()

    q        = request.args.get("q", "").strip()
    source   = request.args.get("source", "")
    page     = max(1, int(request.args.get("page", 1) or 1))
    per_page = 50

    rows, total = db.search_detections(query=q, source=source, page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "detections.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        q=q, source=source,
    )


@app.route("/updates")
@login_required
def updates():
    _maybe_trigger_scan()

    source      = request.args.get("source", "")
    change_type = request.args.get("change_type", "")
    page        = max(1, int(request.args.get("page", 1) or 1))
    per_page    = 50
    offset      = (page - 1) * per_page

    rows, total = db.get_updates(
        source=source, change_type=change_type,
        limit=per_page, offset=offset,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "updates.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        source=source, change_type=change_type,
    )


# ── API routes ─────────────────────────────────────────────────────────────────

@app.route("/api/scan/trigger", methods=["POST"])
@login_required
def api_scan_trigger():
    """Kick off a background scan (honours the 30-minute throttle)."""
    _maybe_trigger_scan()
    return jsonify({"queued": True})


@app.route("/api/scan/status")
@login_required
def api_scan_status():
    """Return the current scan status row as JSON."""
    return jsonify(db.get_scan_status())


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

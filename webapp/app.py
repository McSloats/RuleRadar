#!/usr/bin/env python3
"""
RuleRadar web interface.

Pages
-----
  /               → redirect to /detections (or /setup, /login)
  /setup          → first-run admin account creation
  /login, /logout → authentication
  /setup-token    → mandatory token gate (shown before any page if no token is set)
  /detections     → searchable table of every known detection rule
  /updates        → feed of new/modified rule events
  /settings       → per-user: password, Discord webhook, saved filters; also shows
                    GitHub token status and scan schedule (read-only)
  /admin          → admin-only: GitHub token management, user management
  /admin/activity → admin-only: activity log

Scan policy
-----------
  * Scans are NEVER triggered automatically by page loads or a "Scan Now" button.
  * The first scan fires when the user submits a validated GitHub token on /setup-token.
  * Subsequent scans are owned entirely by the scheduler process (scheduler.py),
    which runs at every even UTC hour (00:00, 02:00, … 22:00).
  * A 90-minute staleness guard in the scheduler prevents a double-scan immediately
    after the initial token-submission scan.

Auth: Flask-Login with bcrypt-hashed passwords.
      First visit redirects to /setup to create the initial admin account.
      Any authenticated visit without a valid GitHub token redirects to /setup-token.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import bcrypt
import database as db
import ruleradar

from flask import (
    Flask, abort, flash, jsonify, redirect,
    render_template, request, url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)


def _load_secret_key() -> str:
    """
    Load or generate a persistent secret key for session signing.
    Stored alongside the database so it survives container restarts
    when the DB volume is mounted (Docker).
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

db.init_db()


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


# ── Token gate (before_request) ────────────────────────────────────────────────

# Endpoints that must remain reachable even when no token is configured.
# This covers: auth flow, the token setup page itself, and status/health probes.
_TOKEN_GATE_SKIP = {
    "login", "logout", "setup",
    "setup_token", "setup_token_validate", "setup_token_submit",
    "api_scan_status",   # nav badge polls this even during token setup
    "health", "static",
    None,                # unknown endpoints (Flask internally generated)
}


@app.before_request
def require_github_token():
    """
    Redirect authenticated users to /setup-token if no valid GitHub token is
    stored in the database.  Unauthenticated users are handled by @login_required
    on individual routes; this hook only enforces the token gate.
    """
    if request.endpoint in _TOKEN_GATE_SKIP:
        return
    if not current_user.is_authenticated:
        return  # @login_required will redirect them to /login
    token = db.get_app_config("github_token")
    if not ruleradar._is_real_token(token):
        return redirect(url_for("setup_token"))


# ── Scan scheduling helpers ────────────────────────────────────────────────────

def _next_scheduled_scan() -> datetime:
    """
    Return the UTC datetime of the next even-hour scheduler fire.
    The scheduler runs at 00:00, 02:00, 04:00 … 22:00 UTC.
    """
    now = datetime.now(timezone.utc)
    # hours_to_add is always 1 or 2 — brings us to the next multiple-of-2 hour
    hours_to_add = 2 - (now.hour % 2)
    return (now + timedelta(hours=hours_to_add)).replace(
        minute=0, second=0, microsecond=0
    )


def _start_background_scan(triggered_by: str):
    """
    Spawn a daemon thread to run a full scan cycle.
    Used only by the token-submission flow; subsequent scans are scheduler-owned.
    """
    def _run():
        try:
            ruleradar.run_scan(triggered_by=triggered_by)
        except Exception as e:
            print(f"  Background scan error: {e}", flush=True)

    threading.Thread(target=_run, daemon=True).start()


def _get_saved_filters() -> list[dict]:
    """Return the current user's saved filter presets (empty list if not logged in)."""
    if not current_user.is_authenticated:
        return []
    settings = db.get_user_settings(current_user.id)
    try:
        return json.loads(settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


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
            db.log_activity("auth", f"User '{username}' logged in",
                            actor=username,
                            detail=f"ip={request.remote_addr}")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("detections"))
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


# ── GitHub token setup (mandatory gate) ────────────────────────────────────────

@app.route("/setup-token")
@login_required
def setup_token():
    """
    Mandatory token setup page.  Any authenticated user without a valid GitHub
    token configured is redirected here by require_github_token().  Once a
    valid token is submitted via /setup-token/submit, the user is never sent
    here again (unless an admin clears the token).
    """
    # If a valid token is already set, there is nothing to do here
    token = db.get_app_config("github_token")
    if ruleradar._is_real_token(token):
        return redirect(url_for("detections"))
    return render_template("setup_token.html")


@app.route("/setup-token/validate", methods=["POST"])
@login_required
def setup_token_validate():
    """
    AJAX endpoint: test a GitHub token against the GitHub API without saving it.
    Expects JSON body {"token": "ghp_..."}.
    Returns JSON {"valid": bool, "limit": int, "remaining": int, "error": str}.
    """
    data  = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    result = ruleradar.validate_token(token)
    return jsonify(result)


@app.route("/setup-token/submit", methods=["POST"])
@login_required
def setup_token_submit():
    """
    Save the submitted GitHub token (after the user has validated and confirmed),
    then immediately launch the initial catalog scan in a background thread.
    """
    token = request.form.get("github_token", "").strip()

    # Validate one more time server-side before persisting
    result = ruleradar.validate_token(token)
    if not result.get("valid"):
        flash(
            f"Token rejected: {result.get('error', 'unknown error')}. "
            "Please go back and re-validate.",
            "error",
        )
        return redirect(url_for("setup_token"))

    db.set_app_config("github_token", token)
    db.log_activity(
        "admin",
        "GitHub token configured via setup-token page",
        actor=current_user.username,
        detail=f"rate_limit={result.get('limit')}/hr",
    )

    # Kick off the initial scan (catalog + incremental) in the background.
    # The scheduler's 90-minute staleness guard ensures it won't double-scan.
    _start_background_scan(triggered_by=f"{current_user.username} (initial setup)")

    flash(
        "Token saved and verified! The initial scan has started — it will index all "
        "rules from SigmaHQ/sigma and splunk/security_content. "
        "This may take a few minutes. Check the scan status badge in the top bar.",
        "success",
    )
    return redirect(url_for("detections"))


# ── Main pages ─────────────────────────────────────────────────────────────────

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
    """
    Searchable table of all known detection rules.
    No scan is triggered here — scans are scheduler-owned.
    """
    q        = request.args.get("q", "").strip()
    source   = request.args.get("source", "")
    mitre    = request.args.get("mitre", "").strip()
    page     = max(1, int(request.args.get("page", 1) or 1))
    per_page = 50

    rows, total = db.search_detections(
        query=q, source=source, mitre=mitre, page=page, per_page=per_page
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "detections.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        q=q, source=source, mitre=mitre,
        saved_filters=_get_saved_filters(),
    )


@app.route("/updates")
@login_required
def updates():
    """
    Feed of new/modified rule events.
    No scan is triggered here — scans are scheduler-owned.
    """
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
        saved_filters=_get_saved_filters(),
    )


# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    """
    Per-user settings page.  Also shows the global GitHub token status and the
    scan schedule so users can see when the last and next scans occur.
    """
    user_settings = db.get_user_settings(current_user.id)
    try:
        saved_filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        saved_filters = []

    # Token display (masked) — global setting, same for all users
    github_token  = db.get_app_config("github_token")
    token_display = ""
    if github_token:
        # Show first 8 chars + dots + last 4 chars for recognition without exposure
        if len(github_token) > 12:
            token_display = github_token[:8] + "●" * 8 + github_token[-4:]
        else:
            token_display = github_token[:4] + "●" * max(0, len(github_token) - 4)

    # Scan schedule
    status    = db.get_scan_status()
    last_scan = status.get("last_scan")
    last_scan_display = (
        last_scan[:19].replace("T", " ") + " UTC" if last_scan else "No scan yet"
    )
    next_scan_dt      = _next_scheduled_scan()
    next_scan_display = next_scan_dt.strftime("%Y-%m-%d %H:%M UTC")

    return render_template(
        "settings.html",
        user_settings=user_settings,
        saved_filters=saved_filters,
        token_display=token_display,
        token_is_set=ruleradar._is_real_token(github_token),
        last_scan_display=last_scan_display,
        next_scan_display=next_scan_display,
    )


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
        db.log_activity("user", "Password changed",
                        actor=current_user.username)
        flash("Password updated successfully.", "success")

    return redirect(url_for("settings"))


@app.route("/settings/discord", methods=["POST"])
@login_required
def settings_discord():
    webhook = request.form.get("discord_webhook", "").strip()
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
        ruleradar.send_discord(
            webhook,
            f"✅ **RuleRadar** — test notification for **{current_user.username}**. "
            "Your webhook is working!"
        )
        db.log_activity("user", "Discord webhook test sent",
                        actor=current_user.username)
        flash("Test notification sent to Discord.", "success")
    except Exception as e:
        db.log_activity("user", f"Discord webhook test failed: {e}",
                        actor=current_user.username, level="error")
        flash(f"Failed to send test notification: {e}", "error")
    return redirect(url_for("settings"))


@app.route("/settings/filters/add", methods=["POST"])
@login_required
def settings_filters_add():
    name        = request.form.get("name", "").strip()
    source      = request.form.get("source", "")
    change_type = request.form.get("change_type", "")
    q           = request.form.get("q", "").strip()
    mitre       = request.form.get("mitre", "").strip()

    if not name:
        flash("Filter name is required.", "error")
        return redirect(url_for("settings"))

    user_settings = db.get_user_settings(current_user.id)
    try:
        filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        filters = []

    # Prevent duplicate names
    if any(f.get("name") == name for f in filters):
        flash(f"A filter named \"{name}\" already exists.", "error")
        return redirect(url_for("settings"))

    filters.append({
        "id":          uuid.uuid4().hex[:10],
        "name":        name,
        "source":      source,
        "change_type": change_type,
        "q":           q,
        "mitre":       mitre,
    })
    db.update_user_filters(current_user.id, json.dumps(filters))
    db.log_activity("user", f"Saved filter '{name}' added",
                    actor=current_user.username,
                    detail=(
                        f"source={source or 'all'}, change_type={change_type or 'all'}, "
                        f"q={q or ''}, mitre={mitre or ''}"
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

    removed = [f for f in filters if f.get("id") == filter_id]
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
    users        = db.get_all_users()
    github_token = db.get_app_config("github_token")
    # Mask token for display: show prefix + dots + last 4 chars
    token_display = ""
    if github_token:
        if len(github_token) > 12:
            token_display = github_token[:8] + "●" * 8 + github_token[-4:]
        else:
            token_display = github_token[:4] + "●" * max(0, len(github_token) - 4)
    return render_template("admin.html",
                           users=users,
                           github_token=github_token,
                           token_display=token_display,
                           current_user_id=current_user.id)


@app.route("/admin/config", methods=["POST"])
@admin_required
def admin_config():
    token = request.form.get("github_token", "").strip()
    db.set_app_config("github_token", token)
    db.log_activity("admin",
                    "GitHub token updated" if token else "GitHub token cleared",
                    actor=current_user.username)
    flash("GitHub token saved.", "success")
    return redirect(url_for("admin"))


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
    flash(f"Admin access {'revoked' if currently_admin else 'granted'} for \"{row['username']}\".", "success")
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


# ── API ────────────────────────────────────────────────────────────────────────

@app.route("/api/scan/status")
@login_required
def api_scan_status():
    """
    Returns the current scan status as JSON.
    Polled every 15 s by the nav-bar badge (layout.html).
    Also includes the next scheduled scan time for informational display.
    """
    status = db.get_scan_status()
    result = dict(status)
    result["next_scan"] = _next_scheduled_scan().isoformat()
    return jsonify(result)


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


# ── Health check ───────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

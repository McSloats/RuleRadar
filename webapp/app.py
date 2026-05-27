#!/usr/bin/env python3
"""
RuleRadar web interface.

Pages:
  /detections   — searchable table of every known detection rule
  /updates      — feed of new/modified rule events
  /settings     — per-user: Discord webhook, saved filters, change password
  /admin        — admin-only: GitHub token, user management

Auth: Flask-Login with bcrypt-hashed passwords.
      First visit redirects to /setup to create the initial admin account.
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


# ── Background scan ────────────────────────────────────────────────────────────

_STALE_MINUTES = 30


def _maybe_trigger_scan():
    """
    Start a background scan if:
      - no scan is currently running, AND
      - the last scan finished more than _STALE_MINUTES ago (or never ran).
    Returns immediately.
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
            ruleradar.run_scan()
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
            next_page = request.args.get("next")
            return redirect(next_page or url_for("detections"))
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


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
        saved_filters=_get_saved_filters(),
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
        saved_filters=_get_saved_filters(),
    )


# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    user_settings = db.get_user_settings(current_user.id)
    try:
        saved_filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        saved_filters = []
    return render_template("settings.html",
                           user_settings=user_settings,
                           saved_filters=saved_filters)


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    current_pw = request.form.get("current_password", "")
    new_pw     = request.form.get("new_password", "")
    confirm    = request.form.get("confirm_password", "")

    row = db.get_user_by_id(current_user.id)
    if not bcrypt.checkpw(current_pw.encode(), row["password_hash"].encode()):
        flash("Current password is incorrect.", "error")
    elif new_pw != confirm:
        flash("New passwords do not match.", "error")
    elif len(new_pw) < 8:
        flash("New password must be at least 8 characters.", "error")
    else:
        db.update_user_password(current_user.id,
                                bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode())
        flash("Password updated successfully.", "success")

    return redirect(url_for("settings"))


@app.route("/settings/discord", methods=["POST"])
@login_required
def settings_discord():
    webhook = request.form.get("discord_webhook", "").strip()
    db.update_user_discord(current_user.id, webhook)
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
        flash("Test notification sent to Discord.", "success")
    except Exception as e:
        flash(f"Failed to send test notification: {e}", "error")
    return redirect(url_for("settings"))


@app.route("/settings/filters/add", methods=["POST"])
@login_required
def settings_filters_add():
    name        = request.form.get("name", "").strip()
    source      = request.form.get("source", "")
    change_type = request.form.get("change_type", "")
    q           = request.form.get("q", "").strip()

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
    })
    db.update_user_filters(current_user.id, json.dumps(filters))
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

    filters = [f for f in filters if f.get("id") != filter_id]
    db.update_user_filters(current_user.id, json.dumps(filters))
    flash("Filter removed.", "success")
    return redirect(url_for("settings"))


# ── Admin ──────────────────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin():
    users        = db.get_all_users()
    github_token = db.get_app_config("github_token")
    # Mask token for display: show prefix + dots
    token_display = ""
    if github_token:
        visible = github_token[:8] if len(github_token) >= 8 else github_token
        token_display = visible + "●" * max(0, len(github_token) - 8)
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
    action = "revoked" if currently_admin else "granted"
    flash(f"Admin access {action} for \"{row['username']}\".", "success")
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
    flash(f"User \"{row['username']}\" deleted.", "success")
    return redirect(url_for("admin"))


# ── API ────────────────────────────────────────────────────────────────────────

@app.route("/api/scan/trigger", methods=["POST"])
@login_required
def api_scan_trigger():
    _maybe_trigger_scan()
    return jsonify({"queued": True})


@app.route("/api/scan/status")
@login_required
def api_scan_status():
    return jsonify(db.get_scan_status())


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

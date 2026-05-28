#!/usr/bin/env python3
"""
RuleRadar web interface.

Pages
-----
  /               → redirect to /detections (or /setup, /login)
  /setup          → first-run admin account creation
  /login, /logout → authentication
  /setup-repos    → first-run repo selection (admin enables repos, starts cloning)
  /detections     → searchable table of every known detection rule
  /updates        → feed of new/modified/deleted rule events
  /settings       → per-user: password, Discord webhook, saved filters
  /admin          → admin-only: repository management, user management
  /admin/activity → admin-only: activity log

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

import json
import secrets
import sys
import threading
import urllib.error
import urllib.request
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


# ── Repo gate (before_request) ─────────────────────────────────────────────────

# Endpoints reachable before any repos are configured.
_REPO_GATE_SKIP = {
    "login", "logout", "setup",
    "setup_repos", "setup_repos_submit",
    "api_repo_sizes",    # AJAX called from setup-repos to fetch size estimates
    "api_scan_status",   # nav badge polls this even on the setup page
    "health", "static",
    # Admin routes must stay accessible so the admin can fix a broken config
    "admin", "admin_add_user",
    "admin_toggle_admin", "admin_reset_password", "admin_delete_user",
    "admin_activity",
    "admin_repos_add", "admin_repos_toggle", "admin_repos_remove",
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
    if request.endpoint in _REPO_GATE_SKIP:
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
    # If repos are already configured redirect to detections (gate is lifted)
    if db.any_repos_configured():
        return redirect(url_for("detections"))

    configured_repos = db.get_all_repos()
    return render_template(
        "setup_repos.html",
        available=list(ruleradar.AVAILABLE_REPOS.values()),
        configured_repos=configured_repos,
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

    db.log_activity(
        "admin", "Repository setup completed",
        actor=current_user.username,
        detail=f"repos enabled: {', '.join(added)}",
    )

    # Start the initial scan — it will clone and index all pending repos
    _start_background_scan(triggered_by=f"{current_user.username} (initial setup)")

    flash(
        f"Enabled: {', '.join(added)}. "
        "Cloning and indexing has started in the background — "
        "this may take several minutes. Detections will appear as indexing completes.",
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
    """Searchable table of all known detection rules."""
    title       = request.args.get("title",       "").strip()
    description = request.args.get("description", "").strip()
    severity    = request.args.get("severity",    "").strip().lower()
    source      = request.args.get("source",      "")
    mitre       = request.args.get("mitre",       "").strip()
    days        = request.args.get("days",        "")
    details_q   = request.args.get("details_q",   "").strip()
    page        = max(1, int(request.args.get("page", 1) or 1))
    per_page    = 50

    rows, total = db.search_detections(
        title=title, description=description, severity=severity,
        source=source, mitre=mitre, days=days, details_q=details_q,
        page=page, per_page=per_page,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "detections.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        title=title, description=description, severity=severity,
        source=source, mitre=mitre, days=days, details_q=details_q,
        saved_filters=_get_saved_filters(),
    )


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

    rows, total = db.get_updates(
        source=source, change_type=change_type,
        title=title, days=days, details_q=details_q,
        limit=per_page, offset=offset,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "updates.html",
        rows=rows, total=total,
        page=page, total_pages=total_pages,
        source=source, change_type=change_type,
        title=title, days=days, details_q=details_q,
        saved_filters=_get_saved_filters(),
    )


# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    """Per-user settings: password, Discord webhook, saved filters, scan status."""
    user_settings = db.get_user_settings(current_user.id)
    try:
        saved_filters = json.loads(user_settings.get("saved_filters", "[]"))
    except (json.JSONDecodeError, TypeError):
        saved_filters = []

    # Scan schedule
    status            = db.get_scan_status()
    last_scan         = status.get("last_scan")
    last_scan_display = (
        last_scan[:19].replace("T", " ") + " UTC" if last_scan else "No scan yet"
    )
    next_scan_dt      = _next_scheduled_scan()
    next_scan_display = next_scan_dt.strftime("%Y-%m-%d %H:%M UTC")

    # Active repos for the status card
    repos = db.get_all_repos()

    return render_template(
        "settings.html",
        user_settings=user_settings,
        saved_filters=saved_filters,
        last_scan_display=last_scan_display,
        next_scan_display=next_scan_display,
        repos=repos,
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
        db.log_activity("user", "Password changed", actor=current_user.username)
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
    })
    db.update_user_filters(current_user.id, json.dumps(filters))
    db.log_activity("user", f"Saved filter '{name}' added", actor=current_user.username,
                    detail=(
                        f"source={source or 'all'}, change_type={change_type or 'all'}, "
                        f"title={title or ''}, mitre={mitre or ''}"
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
    )


# ── Admin — repository management ──────────────────────────────────────────────

@app.route("/admin/repos/add", methods=["POST"])
@admin_required
def admin_repos_add():
    """
    Add a repository to monitor.  Accepts either:
      - a name from AVAILABLE_REPOS (pre-filled config), or
      - a fully custom repo (owner/repo/branch/paths/parser fields).
    """
    name = request.form.get("name", "").strip().lower().replace(" ", "_")
    if not name:
        flash("Repository identifier is required.", "error")
        return redirect(url_for("admin"))

    # Check for pre-defined config
    pre = ruleradar.AVAILABLE_REPOS.get(name)
    if pre:
        cfg = pre
    else:
        # Custom repo
        display_name = request.form.get("display_name", name)
        owner        = request.form.get("owner", "").strip()
        repo         = request.form.get("repo", "").strip()
        branch       = request.form.get("branch", "main").strip()
        paths_raw    = request.form.get("paths", "").strip()
        parser       = request.form.get("parser", "sigma")

        if not owner or not repo:
            flash("Owner and repo are required for custom repositories.", "error")
            return redirect(url_for("admin"))

        paths = [p.strip().rstrip("/") + "/" for p in paths_raw.split(",") if p.strip()]
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
            import shutil
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


# ── API ────────────────────────────────────────────────────────────────────────

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


# ── Health check ───────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

#!/usr/bin/env python3
"""
RuleRadar — security detection monitor for:
  - SigmaHQ/sigma (rules directories)
  - splunk/security_content (develop branch, detections/)

Scans both repos for new/modified rules, persists everything to the
local SQLite database, and sends a brief Discord notification to every
user who has configured a personal webhook.

Call run_scan() directly to trigger a scan from any other module.
GitHub token and Discord webhooks are read from the database (configured
via the web admin panel); no config.json is needed.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import database as db

# ── dependencies (install via: pip install -r requirements.txt) ───────────────
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False  # falls back to a basic line parser; install pyyaml

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    SIGMA_BACKEND_AVAILABLE = True
except ImportError:
    SIGMA_BACKEND_AVAILABLE = False  # Sigma→SPL conversion disabled; install pySigma-backend-splunk

# ── constants ──────────────────────────────────────────────────────────────────
SIGMA_REPO  = {"owner": "SigmaHQ", "repo": "sigma",           "branch": "master"}
SPLUNK_REPO = {"owner": "splunk",  "repo": "security_content", "branch": "develop"}

SIGMA_PATHS = [
    "rules/", "rules-emerging-threats/",
    "rules-threat-hunting/", "rules-compliance/", "rules-placeholder/",
]
SPLUNK_PATHS = ["detections/"]

# Prevent concurrent scans across threads
_scan_lock = threading.Lock()


# ── GitHub helpers ─────────────────────────────────────────────────────────────

def _is_real_token(token: str) -> bool:
    """Return True only if the token looks like an actual GitHub token."""
    if not token:
        return False
    # GitHub tokens start with a known prefix; reject obvious placeholders
    known_prefixes = ("ghp_", "github_pat_", "ghs_", "gho_", "v1.")
    return any(token.startswith(p) for p in known_prefixes)


def gh(url: str, token: str) -> dict | list | None:
    req = urllib.request.Request(url)
    if _is_real_token(token):
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "ruleradar/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  GitHub {e.code}: {url}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Error fetching {url}: {e}", file=sys.stderr)
        return None


def commits_since(owner, repo, branch, since_iso, token):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/commits"
        f"?sha={branch}&since={since_iso}&per_page=100"
    )
    return gh(url, token) or []


def commit_files(owner, repo, sha, token):
    data = gh(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}", token)
    return (data or {}).get("files", [])


def releases_since(owner, repo, since_dt, token):
    data = gh(
        f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=10", token
    ) or []
    cutoff = since_dt.isoformat().replace("+00:00", "Z")
    return [r for r in data if (r.get("published_at") or "") >= cutoff]


def file_content(owner, repo, path, ref, token) -> str | None:
    data = gh(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}", token
    )
    if data and "content" in data:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return None


# ── YAML / content helpers ─────────────────────────────────────────────────────

def parse_yaml(text: str) -> dict:
    if YAML_AVAILABLE and text:
        try:
            return yaml.safe_load(text) or {}
        except Exception:
            pass
    # Minimal fallback: parse top-level key: value lines only
    result = {}
    for line in (text or "").splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


def sigma_detection_block(text: str) -> str:
    """Return the raw detection: YAML block from a Sigma rule."""
    lines = text.splitlines()
    out, inside = [], False
    for line in lines:
        if line.startswith("detection:"):
            inside = True
        elif inside and line and line[0] not in (" ", "\t"):
            break
        if inside:
            out.append(line)
    return "\n".join(out)[:600]


def sigma_to_spl(yaml_text: str) -> str | None:
    """Convert a Sigma rule to Splunk SPL. Returns None if conversion fails."""
    if not SIGMA_BACKEND_AVAILABLE or not yaml_text:
        return None
    try:
        rules = SigmaCollection.from_yaml(yaml_text)
        backend = SplunkBackend()
        results = backend.convert(rules)
        return "\n".join(results) if results else None
    except Exception:
        return None


def is_rule_file(fname: str, paths: list) -> bool:
    return any(fname.startswith(p) for p in paths) and fname.endswith((".yml", ".yaml"))


# ── Repository scanners ────────────────────────────────────────────────────────

def scan_sigma(since_iso: str, token: str) -> tuple[int, int]:
    """
    Scan SigmaHQ/sigma for new and modified rules.
    Saves each rule to the database and records change events.
    Returns (new_count, modified_count).
    """
    owner, repo, branch = SIGMA_REPO["owner"], SIGMA_REPO["repo"], SIGMA_REPO["branch"]
    commits = commits_since(owner, repo, branch, since_iso, token)
    print(f"  SigmaHQ/sigma: {len(commits)} commits in window", flush=True)

    new_count, mod_count, seen = 0, 0, set()

    for c in commits:
        for f in commit_files(owner, repo, c["sha"], token):
            fname = f.get("filename", "")
            if fname in seen or not is_rule_file(fname, SIGMA_PATHS):
                continue
            seen.add(fname)

            text  = file_content(owner, repo, fname, branch, token)
            meta  = parse_yaml(text) if text else {}
            spl   = sigma_to_spl(text) if text else None
            logic = sigma_detection_block(text or "")

            title       = str(meta.get("title", fname.split("/")[-1]))
            description = str(meta.get("description", ""))[:350]
            rule_url    = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"

            is_new = db.upsert_detection(
                "sigma", fname, title, description, logic, spl or "", rule_url
            )

            status = f.get("status", "modified")
            if status == "added":
                change_type = "new"
                new_count += 1
            elif status in ("modified", "renamed", "changed"):
                change_type = "modified"
                mod_count += 1
            else:
                continue

            db.record_update("sigma", fname, title, change_type, logic, spl or "", rule_url)

    return new_count, mod_count


def scan_splunk(since_iso: str, token: str) -> tuple[int, int]:
    """
    Scan splunk/security_content for new and modified detections.
    Saves each detection to the database and records change events.
    Returns (new_count, modified_count).
    """
    owner, repo, branch = SPLUNK_REPO["owner"], SPLUNK_REPO["repo"], SPLUNK_REPO["branch"]
    commits = commits_since(owner, repo, branch, since_iso, token)
    print(f"  splunk/security_content: {len(commits)} commits in window", flush=True)

    new_count, mod_count, seen = 0, 0, set()

    for c in commits:
        for f in commit_files(owner, repo, c["sha"], token):
            fname = f.get("filename", "")
            if fname in seen or not is_rule_file(fname, SPLUNK_PATHS):
                continue
            seen.add(fname)

            text  = file_content(owner, repo, fname, branch, token)
            meta  = parse_yaml(text) if text else {}

            # Prefer the structured 'search' field; fall back to line scan
            search = str(meta.get("search", ""))
            if not search and text:
                for line in text.splitlines():
                    if line.startswith("search:"):
                        search = line[7:].strip()
                        break

            title       = str(meta.get("name", fname.split("/")[-1].replace("_", " ").title()))
            description = str(meta.get("description", ""))[:350]
            rule_url    = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"

            db.upsert_detection(
                "splunk", fname, title, description, "", search[:500], rule_url
            )

            status = f.get("status", "modified")
            if status == "added":
                change_type = "new"
                new_count += 1
            elif status in ("modified", "renamed", "changed"):
                change_type = "modified"
                mod_count += 1
            else:
                continue

            db.record_update("splunk", fname, title, change_type, "", search[:500], rule_url)

    return new_count, mod_count


# ── Discord notification ───────────────────────────────────────────────────────

def send_discord(webhook_url: str, message: str):
    """Send a plain-text Discord notification."""
    payload = json.dumps({"content": message, "username": "RuleRadar"}).encode()
    req = urllib.request.Request(webhook_url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"  Discord: {r.status}", flush=True)
    except urllib.error.HTTPError as e:
        print(f"  Discord error {e.code}: {e.read().decode(errors='replace')}", file=sys.stderr)


# ── Main scan entry point ──────────────────────────────────────────────────────

def run_scan() -> dict:
    """
    Run a full scan cycle. Thread-safe — returns immediately if a scan is
    already in progress.

    On the first ever run (empty database) a 30-day window is used to
    populate the database with recent history. Subsequent runs use 2 hours.

    GitHub token is read from the database (set via the admin panel).
    Discord notifications are sent to every user with a webhook configured.

    Returns a summary dict: {new, modified, skipped, error}.
    """
    if not _scan_lock.acquire(blocking=False):
        print("  Scan already in progress — skipping.", flush=True)
        return {"skipped": True}

    try:
        db.set_scanning(True)

        # Read GitHub token from DB (set via admin panel; empty = unauthenticated)
        token = db.get_app_config("github_token")

        if not YAML_AVAILABLE:
            print(
                "  WARNING: pyyaml not installed — using basic parser. "
                "Run: pip install -r requirements.txt",
                flush=True,
            )
        if not SIGMA_BACKEND_AVAILABLE:
            print(
                "  WARNING: pySigma-backend-splunk not installed — "
                "Sigma→SPL conversion disabled. Run: pip install -r requirements.txt",
                flush=True,
            )

        # First ever run: use 30-day window to seed the database
        status = db.get_scan_status()
        hours  = 720 if not status.get("last_scan") else 2
        if hours == 720:
            print("  First run — using 30-day window for initial database seed.", flush=True)

        since_dt  = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

        print(f"[{timestamp}] Running RuleRadar (window: {hours}h)", flush=True)
        print(f"  Commits since {since_iso}", flush=True)

        s_new, s_mod = scan_sigma(since_iso, token)
        p_new, p_mod = scan_splunk(since_iso, token)

        total_new = s_new + p_new
        total_mod = s_mod + p_mod

        # Persist new releases
        for r in releases_since(SIGMA_REPO["owner"], SIGMA_REPO["repo"], since_dt, token):
            db.upsert_release(
                "sigma", r["tag_name"], r.get("name", ""),
                (r.get("body") or "")[:1000], r.get("published_at", ""), r.get("html_url", ""),
            )
        for r in releases_since(SPLUNK_REPO["owner"], SPLUNK_REPO["repo"], since_dt, token):
            db.upsert_release(
                "splunk", r["tag_name"], r.get("name", ""),
                (r.get("body") or "")[:1000], r.get("published_at", ""), r.get("html_url", ""),
            )

        db.finish_scan(total_new, total_mod)

        print(
            f"  sigma  → new={s_new}  mod={s_mod}\n"
            f"  splunk → new={p_new}  mod={p_mod}",
            flush=True,
        )

        # Send Discord notifications to every user who has a webhook configured
        if total_new + total_mod > 0:
            msg = (
                f"**RuleRadar — {timestamp}**\n"
                f"Sigma: **{s_new}** new / **{s_mod}** modified\n"
                f"Splunk: **{p_new}** new / **{p_mod}** modified\n"
                f"View full details in your RuleRadar instance."
            )
            for webhook_url in db.get_all_user_webhooks():
                send_discord(webhook_url, msg)

        print("Done.", flush=True)
        return {"new": total_new, "modified": total_mod, "skipped": False}

    except Exception as e:
        print(f"  ERROR during scan: {e}", file=sys.stderr)
        db.finish_scan(0, 0)
        return {"error": str(e), "skipped": False}

    finally:
        _scan_lock.release()


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    db.init_db()
    result = run_scan()
    if result.get("error"):
        sys.exit(1)

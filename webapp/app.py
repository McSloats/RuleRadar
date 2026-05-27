#!/usr/bin/env python3
"""
RuleRadar web interface — serves the report viewer UI and provides
JSON API endpoints for listing, fetching, and searching reports
stored in the configured GitHub repository.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

# ── In-memory report content cache (content never changes once written) ────────
_content_cache: dict[str, str] = {}
_cache_lock = Lock()


# ── Config ─────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


# ── GitHub helpers ─────────────────────────────────────────────────────────────

def gh_get(url: str, token: str) -> "dict | list | None":
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "ruleradar/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        app.logger.error("GitHub %s: %s", e.code, url)
        return None
    except Exception as e:
        app.logger.error("GitHub fetch error: %s", e)
        return None


def list_reports_from_github(cfg: dict) -> list[dict]:
    """Return a sorted list of report metadata from the reports/ directory."""
    owner  = cfg["github_reports_owner"]
    repo   = cfg["github_reports_repo"]
    branch = cfg.get("github_reports_branch", "main")
    token  = cfg.get("github_token", "")

    url  = f"https://api.github.com/repos/{owner}/{repo}/contents/reports?ref={branch}"
    data = gh_get(url, token) or []

    reports = []
    for f in data:
        name = f.get("name", "")
        if not name.endswith(".md"):
            continue
        # Filenames are YYYY-MM-DD_HH-MM.md
        reports.append({
            "name": name,
            "date": name[:10],
            "time": name[11:16].replace("-", ":") if len(name) > 15 else "",
            "size": f.get("size", 0),
        })

    return sorted(reports, key=lambda x: x["name"], reverse=True)


def fetch_report_content(cfg: dict, filename: str) -> "str | None":
    """Fetch a single report's markdown content, using the cache."""
    with _cache_lock:
        if filename in _content_cache:
            return _content_cache[filename]

    owner  = cfg["github_reports_owner"]
    repo   = cfg["github_reports_repo"]
    branch = cfg.get("github_reports_branch", "main")
    token  = cfg.get("github_token", "")

    url  = f"https://api.github.com/repos/{owner}/{repo}/contents/reports/{filename}?ref={branch}"
    data = gh_get(url, token)

    content = None
    if data and "content" in data:
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    if content:
        with _cache_lock:
            _content_cache[filename] = content

    return content


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/reports")
def api_list_reports():
    """Return metadata for all available reports."""
    try:
        cfg     = load_config()
        reports = list_reports_from_github(cfg)
        return jsonify(reports)
    except Exception as e:
        app.logger.exception("Failed to list reports")
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/<path:filename>")
def api_get_report(filename: str):
    """Return the raw markdown content of a single report."""
    try:
        cfg     = load_config()
        content = fetch_report_content(cfg, filename)
        if content:
            return jsonify({"content": content})
        return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        app.logger.exception("Failed to fetch report: %s", filename)
        return jsonify({"error": str(e)}), 500


@app.route("/api/search")
def api_search():
    """
    Filter reports by date range and/or text content.

    Query params:
      q     — case-insensitive text to search within report content
      from  — start date (YYYY-MM-DD, inclusive)
      to    — end date   (YYYY-MM-DD, inclusive)
    """
    query     = request.args.get("q", "").strip().lower()
    from_date = request.args.get("from", "")
    to_date   = request.args.get("to", "")

    try:
        cfg         = load_config()
        all_reports = list_reports_from_github(cfg)

        # Date range filter (cheap — no extra API calls needed)
        date_filtered = [
            r for r in all_reports
            if (not from_date or r["date"] >= from_date)
            and (not to_date   or r["date"] <= to_date)
        ]

        if not query:
            return jsonify(date_filtered)

        # Text search — fetch content for each date-filtered report
        results = []
        for r in date_filtered:
            content = fetch_report_content(cfg, r["name"])
            if content and query in content.lower():
                results.append({**r, "matches": content.lower().count(query)})

        return jsonify(results)

    except Exception as e:
        app.logger.exception("Search failed")
        return jsonify({"error": str(e)}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

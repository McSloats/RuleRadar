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
import re
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
SIGMA_REPO  = {"owner": "SigmaHQ", "repo": "sigma",            "branch": "master"}
SPLUNK_REPO = {"owner": "splunk",  "repo": "security_content",  "branch": "develop"}

SIGMA_PATHS = [
    "rules/", "rules-emerging-threats/",
    "rules-threat-hunting/", "rules-compliance/", "rules-placeholder/",
]
SPLUNK_PATHS = ["detections/"]

# Prevent concurrent scans across threads
_scan_lock = threading.Lock()

# ── MITRE ATT&CK tactic slug → display name ───────────────────────────────────
MITRE_TACTICS: dict[str, str] = {
    "initial_access":        "Initial Access",
    "execution":             "Execution",
    "persistence":           "Persistence",
    "privilege_escalation":  "Privilege Escalation",
    "defense_evasion":       "Defense Evasion",
    "credential_access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral_movement":      "Lateral Movement",
    "collection":            "Collection",
    "command_and_control":   "Command and Control",
    "exfiltration":          "Exfiltration",
    "impact":                "Impact",
    "reconnaissance":        "Reconnaissance",
    "resource_development":  "Resource Development",
}

# Regex matching a MITRE technique ID: t1234 or t1234.567
_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


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


def git_tree(owner: str, repo: str, branch: str, token: str) -> list[dict]:
    """
    Fetch the complete recursive file tree via the git/trees API.
    Returns the list of tree entries (dicts with 'path', 'type', 'sha', etc.).
    Warns if the response was truncated (repo too large for one call).
    """
    data = gh(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
        token,
    )
    if not data or "tree" not in data:
        return []
    if data.get("truncated"):
        print(
            f"  WARNING: git tree for {owner}/{repo} was truncated — "
            "some files may be missed during catalog scan.",
            file=sys.stderr,
        )
    return data["tree"]


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


def clean_title_fallback(fname: str) -> str:
    """Generate a readable title from a filename when no title field is present."""
    base = fname.split("/")[-1]
    for ext in (".yml", ".yaml"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base.replace("_", " ").replace("-", " ").title()


# ── MITRE extraction helpers ───────────────────────────────────────────────────

def extract_sigma_mitre(meta: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK tags from a Sigma rule's 'tags' list.

    Sigma tags look like:
        tags:
          - attack.execution           ← tactic slug
          - attack.t1059               ← technique (no sub)
          - attack.t1059.001           ← technique + sub-technique

    Returns a tuple of pipe-separated strings:
        (techniques, tactics)
        e.g. ("T1059|T1059.001", "Execution")
    """
    tags = meta.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    techniques: list[str] = []
    tactics: list[str]    = []
    seen_t: set[str]      = set()
    seen_ta: set[str]     = set()

    for tag in tags:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        part = tag[7:]  # strip "attack."
        if _TECHNIQUE_RE.match(part):
            uid = part.upper()
            if uid not in seen_t:
                seen_t.add(uid)
                techniques.append(uid)
        else:
            display = MITRE_TACTICS.get(part, "")
            if display and display not in seen_ta:
                seen_ta.add(display)
                tactics.append(display)

    return "|".join(techniques), "|".join(tactics)


def extract_splunk_mitre(meta: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK data from a Splunk security_content detection's 'tags' dict.

    Splunk tags look like:
        tags:
          mitre_attack_id:
            - T1059.001
          mitre_attack_enrichments:
            - mitre_attack_id: T1059.001
              mitre_attack_technique: 'Command and Scripting Interpreter: PowerShell'
              mitre_attack_tactic:
                - Execution
              mitre_attack_tactic_id:
                - TA0002

    Returns (techniques, tactics) as pipe-separated strings.
    """
    tags = meta.get("tags") or {}
    if not isinstance(tags, dict):
        return "", ""

    # ── Techniques from mitre_attack_id ──────────────────────────────────────
    raw_ids = tags.get("mitre_attack_id") or []
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    seen_t: set[str] = set()
    techniques: list[str] = []
    for t in raw_ids:
        uid = str(t).strip().upper()
        if uid and uid not in seen_t:
            seen_t.add(uid)
            techniques.append(uid)

    # ── Tactics from mitre_attack_enrichments ────────────────────────────────
    enrichments = tags.get("mitre_attack_enrichments") or []
    seen_ta: set[str] = set()
    tactics: list[str] = []
    if isinstance(enrichments, list):
        for enr in enrichments:
            if not isinstance(enr, dict):
                continue
            tactic_list = enr.get("mitre_attack_tactic") or []
            if isinstance(tactic_list, str):
                tactic_list = [tactic_list]
            for t in tactic_list:
                name = str(t).strip()
                if name and name not in seen_ta:
                    seen_ta.add(name)
                    tactics.append(name)

    return "|".join(techniques), "|".join(tactics)


# ── Repository scanners ────────────────────────────────────────────────────────

def scan_sigma(since_iso: str, token: str) -> tuple[int, int]:
    """
    Scan SigmaHQ/sigma for new and modified rules since *since_iso*.
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

            title           = str(meta.get("title", "")).strip() or clean_title_fallback(fname)
            description     = str(meta.get("description", ""))[:350]
            author          = str(meta.get("author", ""))[:200]
            rule_status     = str(meta.get("status", ""))[:50]
            severity        = str(meta.get("level", ""))[:50]
            rule_date       = str(meta.get("date", ""))[:20]
            refs_raw        = meta.get("references") or []
            refs            = "\n".join(str(r) for r in refs_raw) if isinstance(refs_raw, list) else str(refs_raw)
            refs            = refs[:500]
            rule_url        = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"
            techniques, tactics = extract_sigma_mitre(meta)

            is_new = db.upsert_detection(
                "sigma", fname, title, description, logic, spl or "", rule_url,
                mitre_techniques=techniques, mitre_tactics=tactics,
                author=author, rule_status=rule_status, severity=severity,
                rule_date=rule_date, refs=refs,
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
    Scan splunk/security_content for new and modified detections since *since_iso*.
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

            title           = str(meta.get("name", "")).strip() or clean_title_fallback(fname)
            description     = str(meta.get("description", ""))[:350]
            author          = str(meta.get("author", ""))[:200]
            rule_status     = str(meta.get("status", ""))[:50]
            severity        = ""  # Splunk uses 'tags.risk_score' — not a simple field
            rule_date       = str(meta.get("date", ""))[:20]
            refs_raw        = meta.get("references") or []
            refs            = "\n".join(str(r) for r in refs_raw) if isinstance(refs_raw, list) else str(refs_raw)
            refs            = refs[:500]
            rule_url        = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"
            techniques, tactics = extract_splunk_mitre(meta)

            db.upsert_detection(
                "splunk", fname, title, description, "", search[:500], rule_url,
                mitre_techniques=techniques, mitre_tactics=tactics,
                author=author, rule_status=rule_status, severity=severity,
                rule_date=rule_date, refs=refs,
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


# ── Catalog scanners (full repo enumeration) ───────────────────────────────────

def catalog_scan_sigma(token: str) -> int:
    """
    Enumerate ALL sigma rule files via the git tree API and fetch any
    that aren't already in the database.  Returns the number of rules added.

    Only meaningful when a real GitHub token is available (5 000 req/hr);
    without one the caller falls back to a 30-day incremental window.
    """
    owner, repo, branch = SIGMA_REPO["owner"], SIGMA_REPO["repo"], SIGMA_REPO["branch"]

    print("  Sigma catalog: fetching file tree…", flush=True)
    tree = git_tree(owner, repo, branch, token)

    rule_files = [
        item["path"] for item in tree
        if item.get("type") == "blob"
        and is_rule_file(item.get("path", ""), SIGMA_PATHS)
    ]
    print(f"  Sigma catalog: {len(rule_files)} rule files in repo", flush=True)

    existing  = db.get_existing_detection_paths("sigma")
    to_fetch  = [f for f in rule_files if f not in existing]
    print(f"  Sigma catalog: {len(to_fetch)} new files to index", flush=True)

    added = 0
    for i, fname in enumerate(to_fetch, 1):
        if i % 100 == 0:
            print(f"    … {i}/{len(to_fetch)} sigma files fetched", flush=True)

        text  = file_content(owner, repo, fname, branch, token)
        if not text:
            continue
        meta  = parse_yaml(text)
        spl   = sigma_to_spl(text)
        logic = sigma_detection_block(text)

        title           = str(meta.get("title", "")).strip() or clean_title_fallback(fname)
        description     = str(meta.get("description", ""))[:350]
        author          = str(meta.get("author", ""))[:200]
        rule_status     = str(meta.get("status", ""))[:50]
        severity        = str(meta.get("level", ""))[:50]
        rule_date       = str(meta.get("date", ""))[:20]
        refs_raw        = meta.get("references") or []
        refs            = "\n".join(str(r) for r in refs_raw) if isinstance(refs_raw, list) else str(refs_raw)
        refs            = refs[:500]
        rule_url        = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"
        techniques, tactics = extract_sigma_mitre(meta)

        db.upsert_detection(
            "sigma", fname, title, description, logic, spl or "", rule_url,
            mitre_techniques=techniques, mitre_tactics=tactics,
            author=author, rule_status=rule_status, severity=severity,
            rule_date=rule_date, refs=refs,
        )
        added += 1

    print(f"  Sigma catalog: done — {added} rules indexed", flush=True)
    return added


def catalog_scan_splunk(token: str) -> int:
    """
    Enumerate ALL splunk/security_content detection files via the git tree API
    and fetch any not already in the database.  Returns the number added.
    """
    owner, repo, branch = SPLUNK_REPO["owner"], SPLUNK_REPO["repo"], SPLUNK_REPO["branch"]

    print("  Splunk catalog: fetching file tree…", flush=True)
    tree = git_tree(owner, repo, branch, token)

    rule_files = [
        item["path"] for item in tree
        if item.get("type") == "blob"
        and is_rule_file(item.get("path", ""), SPLUNK_PATHS)
    ]
    print(f"  Splunk catalog: {len(rule_files)} detection files in repo", flush=True)

    existing  = db.get_existing_detection_paths("splunk")
    to_fetch  = [f for f in rule_files if f not in existing]
    print(f"  Splunk catalog: {len(to_fetch)} new files to index", flush=True)

    added = 0
    for i, fname in enumerate(to_fetch, 1):
        if i % 100 == 0:
            print(f"    … {i}/{len(to_fetch)} splunk files fetched", flush=True)

        text  = file_content(owner, repo, fname, branch, token)
        if not text:
            continue
        meta  = parse_yaml(text)

        search = str(meta.get("search", ""))
        if not search and text:
            for line in text.splitlines():
                if line.startswith("search:"):
                    search = line[7:].strip()
                    break

        title           = str(meta.get("name", "")).strip() or clean_title_fallback(fname)
        description     = str(meta.get("description", ""))[:350]
        author          = str(meta.get("author", ""))[:200]
        rule_status     = str(meta.get("status", ""))[:50]
        rule_date       = str(meta.get("date", ""))[:20]
        refs_raw        = meta.get("references") or []
        refs            = "\n".join(str(r) for r in refs_raw) if isinstance(refs_raw, list) else str(refs_raw)
        refs            = refs[:500]
        rule_url        = f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}"
        techniques, tactics = extract_splunk_mitre(meta)

        db.upsert_detection(
            "splunk", fname, title, description, "", search[:500], rule_url,
            mitre_techniques=techniques, mitre_tactics=tactics,
            author=author, rule_status=rule_status, severity="",
            rule_date=rule_date, refs=refs,
        )
        added += 1

    print(f"  Splunk catalog: done — {added} detections indexed", flush=True)
    return added


# ── Token validation helper ───────────────────────────────────────────────────

def validate_token(token: str) -> dict:
    """
    Verify a GitHub personal access token by hitting the rate_limit endpoint.

    Returns a dict:
        {"valid": True,  "limit": 5000, "remaining": 4995}
        {"valid": False, "limit": 0,    "error": "...reason..."}

    A valid token must be recognised by _is_real_token() AND accepted by GitHub
    (HTTP 200 from /rate_limit). Unauthenticated calls return limit=60, so we
    require limit >= 5000 to confirm the token actually authenticated.
    """
    if not _is_real_token(token):
        return {"valid": False, "limit": 0,
                "error": "Token format not recognised — must start with ghp_, github_pat_, etc."}
    try:
        req = urllib.request.Request("https://api.github.com/rate_limit")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("User-Agent", "ruleradar/1.0")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        rate      = data.get("rate", {})
        limit     = rate.get("limit", 0)
        remaining = rate.get("remaining", 0)
        if limit >= 5000:
            return {"valid": True, "limit": limit, "remaining": remaining}
        # Token accepted but unusually low limit — report it so the user knows
        return {
            "valid": False, "limit": limit, "remaining": remaining,
            "error": f"Token accepted but rate limit is only {limit}/hr (expected 5 000+). "
                     "Check that the token has public_repo scope.",
        }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"valid": False, "limit": 0,
                    "error": "GitHub rejected the token (401 Unauthorized). "
                             "Check that the token hasn't expired or been revoked."}
        return {"valid": False, "limit": 0,
                "error": f"GitHub API returned HTTP {e.code}."}
    except Exception as e:
        return {"valid": False, "limit": 0, "error": str(e)}


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

def run_scan(triggered_by: str = "scheduler") -> dict:
    """
    Run a full scan cycle.  Thread-safe — returns immediately if a scan is
    already in progress.

    First-run behaviour
    -------------------
    If a real GitHub token is configured AND the catalog has not been done yet,
    the full git-tree catalog scan runs first (indexes every rule file in the
    repo).  This takes a few minutes but gives complete coverage.

    Without a valid token on the first run, a 30-day incremental window is
    used instead, with a warning printed to stderr.

    Subsequent runs always use a 2-hour incremental window.

    GitHub token is read from the database (set via the admin panel).
    Discord notifications are sent to every user with a webhook configured.

    triggered_by : free-text label recorded in the activity log.
    Returns a summary dict: {new, modified, skipped, error}.
    """
    if not _scan_lock.acquire(blocking=False):
        print("  Scan already in progress — skipping.", flush=True)
        db.log_activity("scan", "Scan skipped — already in progress",
                        actor=triggered_by, level="warning")
        return {"skipped": True}

    try:
        db.set_scanning(True)

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

        timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M")
        catalog_done = db.is_catalog_done()
        status       = db.get_scan_status()
        has_token    = _is_real_token(token)

        # ── Catalog scan (runs once when a real token is available) ──────────
        catalog_new = 0
        if not catalog_done and has_token:
            print(
                f"[{timestamp}] Running full catalog scan (first time with token)…",
                flush=True,
            )
            db.log_activity("scan", "Full catalog scan started",
                            actor=triggered_by,
                            detail="Indexing all rules from both repos")
            cs_new = catalog_scan_sigma(token)
            cp_new = catalog_scan_splunk(token)
            catalog_new = cs_new + cp_new
            db.mark_catalog_done()
            db.log_activity(
                "scan",
                f"Catalog scan complete — {catalog_new} rules indexed",
                actor=triggered_by,
                detail=f"sigma: {cs_new} | splunk: {cp_new}",
            )
            print(f"  Catalog complete — {catalog_new} rules indexed.", flush=True)

        elif not catalog_done and not has_token:
            print(
                "  WARNING: No GitHub token — catalog scan skipped. "
                "Add a token in the Admin panel for complete rule coverage.",
                file=sys.stderr,
            )

        # ── Incremental scan ─────────────────────────────────────────────────
        # After a catalog the window is short (2 h) so we pick up anything
        # committed since the catalog started.  Without a catalog on the first
        # run we fall back to 30 days.
        if catalog_done or status.get("last_scan"):
            hours = 2
        elif not catalog_done and not has_token:
            hours = 720  # 30-day seed when no token available
            print("  First run — using 30-day window for initial database seed.", flush=True)
        else:
            hours = 2  # catalog was just done above

        since_dt  = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        print(f"[{timestamp}] Incremental scan (window: {hours}h, since {since_iso})", flush=True)

        db.log_activity("scan", f"Incremental scan started (window: {hours}h)",
                        actor=triggered_by,
                        detail=f"since={since_iso}")

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

        db.log_activity(
            "scan",
            f"Scan complete — {total_new} new, {total_mod} modified",
            actor=triggered_by,
            detail=(
                f"sigma: {s_new} new / {s_mod} modified | "
                f"splunk: {p_new} new / {p_mod} modified"
                + (f" | catalog: {catalog_new} indexed" if catalog_new else "")
            ),
        )

        # Send Discord notifications to every user who has a webhook configured
        if total_new + total_mod + catalog_new > 0:
            msg_parts = [f"**RuleRadar — {timestamp}**"]
            if catalog_new:
                msg_parts.append(f"📚 Full catalog: **{catalog_new}** rules indexed")
            msg_parts += [
                f"Sigma: **{s_new}** new / **{s_mod}** modified",
                f"Splunk: **{p_new}** new / **{p_mod}** modified",
                "View full details in your RuleRadar instance.",
            ]
            msg = "\n".join(msg_parts)
            for webhook_url in db.get_all_user_webhooks():
                send_discord(webhook_url, msg)

        print("Done.", flush=True)
        return {"new": total_new, "modified": total_mod, "skipped": False}

    except Exception as e:
        print(f"  ERROR during scan: {e}", file=sys.stderr)
        db.log_activity("scan", f"Scan error: {e}",
                        actor=triggered_by, detail=str(e), level="error")
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

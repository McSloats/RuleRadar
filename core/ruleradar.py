#!/usr/bin/env python3
"""
RuleRadar — security detection monitor using local git clones.

Repositories are cloned with git (no rate limits, no authentication needed)
and kept up to date via git fetch + diff.  The GitHub REST API is used only
for releases metadata (2 unauthenticated calls per scan).

Scanning flow
-------------
  First run (status='pending'):
    clone_repo()  → git clone --depth=1
    index_repo()  → walk every YAML file and upsert into DB

  Subsequent runs (status='ready'):
    sync_repo()   → git fetch, diff old SHA vs FETCH_HEAD, process changed files

Call run_scan() directly to trigger a scan from any other module.
Discord webhooks are read from the database (configured via the web admin
panel); no config.json is needed.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pathlib import Path

# Ensure the project root is on sys.path so this module can be run directly
# (e.g. `python3 core/ruleradar.py`) as well as imported as a package member.
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import database as db

# ── Optional Python dependencies ───────────────────────────────────────────────
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import tomllib                  # stdlib on Python 3.11+
    TOML_AVAILABLE = True
except ImportError:
    try:
        import tomli as tomllib     # pip install tomli  (backport for ≤3.10)
        TOML_AVAILABLE = True
    except ImportError:
        TOML_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────────

# Root directory for all cloned repositories.  Lives alongside the database
# so it is included in the Docker named volume and survives container restarts.
REPOS_DIR: Path = db.DB_PATH.parent / "repos"

# Prevent concurrent scans across threads
_scan_lock = threading.Lock()

# A shallow (--depth=1) clone that is fetched indefinitely can get its local
# .git/shallow boundary into a state where every subsequent fetch fails the
# same way, even once the underlying remote-side condition is gone. After
# this many consecutive sync failures, wipe the local clone and re-clone from
# scratch instead of retrying against the same broken repo forever.
MAX_CONSECUTIVE_FETCH_FAILURES = 3

# Pre-defined repositories that can be enabled via the setup-repos page.
# Admins can add custom repos via the admin panel.
AVAILABLE_REPOS: dict[str, dict] = {
    "sigma": {
        "name":         "sigma",
        "display_name": "SigmaHQ / sigma",
        "description":  "Community Sigma detection rules for SIEM platforms (4,000+ rules)",
        "owner":        "SigmaHQ",
        "repo":         "sigma",
        "branch":       "master",
        "paths":        [
            "rules/",
            "rules-emerging-threats/",
            "rules-threat-hunting/",
            "rules-compliance/",
        ],
        "parser":       "sigma",
    },
    "splunk": {
        "name":         "splunk",
        "display_name": "splunk / security_content",
        "description":  "Splunk's official security content and detection rules (1,000+ detections)",
        "owner":        "splunk",
        "repo":         "security_content",
        "branch":       "develop",
        "paths":        ["detections/"],
        "parser":       "splunk",
    },
    "elastic": {
        "name":         "elastic",
        "display_name": "Elastic / detection-rules",
        "description":  "Elastic Security detection rules in EQL, KQL, and ES|QL (1,000+ rules)",
        "owner":        "elastic",
        "repo":         "detection-rules",
        "branch":       "main",
        "paths":        ["rules/"],
        "parser":       "elastic",
    },
    "panther": {
        "name":         "panther",
        "display_name": "Panther Labs / panther-analysis",
        "description":  "Panther community detection rules for cloud and SaaS platforms (1,000+ rules)",
        "owner":        "panther-labs",
        "repo":         "panther-analysis",
        "branch":       "develop",
        "paths":        ["rules/"],
        "parser":       "panther",
    },
    "sublime": {
        "name":         "sublime",
        "display_name": "Sublime Security / sublime-rules",
        "description":  "Sublime Security email detection rules in MQL (600+ rules)",
        "owner":        "sublime-security",
        "repo":         "sublime-rules",
        "branch":       "main",
        "paths":        ["detection-rules/"],
        "parser":       "sublime",
    },
    "anvilogic": {
        "name":         "anvilogic",
        "display_name": "Anvilogic / armory",
        "description":  "Anvilogic Armory detection rules for Splunk and Snowflake (1,000+ detections)",
        "owner":        "anvilogic-forge",
        "repo":         "armory",
        "branch":       "main",
        "paths":        ["detections/"],
        "parser":       "anvilogic",
    },
}

# ── GitHub REST API helpers (used only for releases metadata) ──────────────────

def _gh(url: str) -> dict | list | None:
    """Minimal unauthenticated GitHub REST helper — used only for releases."""
    req = urllib.request.Request(url)
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


def releases_since(owner: str, repo: str, since_dt: datetime):
    """Fetch recent GitHub releases newer than since_dt (unauthenticated REST call)."""
    data = _gh(
        f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=10"
    ) or []
    cutoff = since_dt.isoformat().replace("+00:00", "Z")
    return [r for r in data if (r.get("published_at") or "") >= cutoff]


# ── YAML / content helpers ─────────────────────────────────────────────────────

def parse_yaml(text: str) -> dict:
    if YAML_AVAILABLE and text:
        try:
            return yaml.safe_load(text) or {}
        except Exception as _yaml_err:
            # Log so operators can see which files trigger parse failures
            print(f"  [parse_yaml] yaml.safe_load failed ({_yaml_err!r}); "
                  "falling back to line parser", file=sys.stderr)
    # Minimal fallback: parse top-level key: value lines only.
    # NOTE: this cannot parse nested structures like 'tags', so any rule
    # that reaches this path will have empty MITRE / tags data.
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


def clean_title_fallback(fname: str) -> str:
    """Generate a readable title from a filename when no title field is present."""
    base = fname.split("/")[-1]
    for ext in (".toml", ".yml", ".yaml"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base.replace("_", " ").replace("-", " ").title()


# ── MITRE extraction ─────────────────────────────────────────────────────────

# Matches MITRE ATT&CK technique IDs (T1059, T1059.001), case-insensitive,
# word-bounded so it won't match inside a longer token (e.g. "RT1059X").
_MITRE_TECHNIQUE_RE = re.compile(
    r"(?<![A-Za-z0-9_])[Tt](\d{4})(\.(\d{3}))?(?![A-Za-z0-9_])"
)


def extract_mitre_techniques(raw_text: str) -> str:
    """
    Scan a rule file's raw text for MITRE ATT&CK technique IDs.

    Runs the same regex over every source — native or custom — instead of
    relying on each format's own schema (Sigma tags, Splunk's
    mitre_attack_id field, Elastic's threat array, etc.). Those bespoke
    extractors only ever work on the exact schema they were written for;
    a custom repo that stores technique IDs any other way (or a native repo
    that mentions a technique outside its usual tag location) would come
    back empty. Regex-matching the literal ID text wherever it appears
    (tags, free-text description, inline comments) finds it regardless of
    the surrounding schema.

    Matches both standalone techniques (T1059) and sub-techniques
    (T1059.001), de-duplicated and order-preserving. Returns a pipe-joined
    string of uppercase IDs, or "" if none were found.
    """
    if not raw_text:
        return ""
    seen: set[str] = set()
    out: list[str] = []
    for m in _MITRE_TECHNIQUE_RE.finditer(raw_text):
        tid = f"T{m.group(1)}" + (f".{m.group(3)}" if m.group(3) else "")
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return "|".join(out)


# ── File diffing (Updates page) ─────────────────────────────────────────────────

def compute_file_diff(old_text: str, new_text: str, file_path: str) -> str:
    """
    Full unified diff between a file's previously stored content and its
    current content, for the Updates page's modified/renamed/deleted entries.

    old_text=="" renders as a pure addition (every line "+"); new_text==""
    renders as a pure removal (every line "-") for deleted files.
    """
    # Normalize a missing trailing newline so the last changed line doesn't
    # run together with the next diff line when both are joined below.
    if old_text and not old_text.endswith("\n"):
        old_text += "\n"
    if new_text and not new_text.endswith("\n"):
        new_text += "\n"

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    # Content lines already carry their own "\n" from keepends=True, and
    # difflib's default lineterm="\n" appends one to the header/hunk lines
    # too -- joining on "" (not "\n") avoids doubling every line break.
    diff = difflib.unified_diff(old_lines, new_lines, fromfile=file_path, tofile=file_path)
    return "".join(diff)


def diff_stats(diff_text: str) -> tuple[int, int]:
    """Return (lines_added, lines_removed) by counting +/- body lines in a
    unified diff, excluding the --- / +++ file-header lines."""
    added = removed = 0
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


# ── Git helpers ────────────────────────────────────────────────────────────────

def git_run(args: list[str], cwd: str | None = None, timeout: int = 600) -> tuple[int, str]:
    """
    Run a git command and return (returncode, combined_output).
    timeout : seconds to wait before killing the process (default 10 min).
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()
    except subprocess.TimeoutExpired:
        return 1, f"git command timed out after {timeout}s"
    except FileNotFoundError:
        return 1, "git not found — ensure git is installed"
    except Exception as e:
        return 1, str(e)


# ── File-level parsers ─────────────────────────────────────────────────────────

def _process_sigma(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str]:
    """
    Parse a Sigma rule file and upsert it into the database.
    Returns (is_new, title).
    """
    meta  = parse_yaml(text)
    logic = sigma_detection_block(text)

    title       = str(meta.get("title",       "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    author      = str(meta.get("author",      ""))[:200]
    rule_status = str(meta.get("status",      ""))[:50]
    rule_date   = str(meta.get("date",        ""))[:20]
    rule_id     = str(meta.get("id",          ""))[:64]
    refs_raw    = meta.get("references") or []
    refs        = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]
    techniques = extract_mitre_techniques(text)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques=techniques,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title


def _process_splunk(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str]:
    """
    Parse a Splunk security_content YAML file and upsert it into the database.
    Returns (is_new, title).
    """
    meta = parse_yaml(text)

    search = str(meta.get("search", ""))
    if not search:
        for line in text.splitlines():
            if line.startswith("search:"):
                search = line[7:].strip()
                break

    title       = str(meta.get("name",        "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    author      = str(meta.get("author",      ""))[:200]
    rule_status = str(meta.get("status",      ""))[:50]
    rule_date   = str(meta.get("date",        ""))[:20]
    rule_id     = str(meta.get("id",          ""))[:64]
    refs_raw    = meta.get("references") or []
    refs        = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]
    techniques = extract_mitre_techniques(text)

    is_new = db.upsert_detection(
        source, rel_path, title, description, "", search[:500], rule_url,
        mitre_techniques=techniques,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title


def _process_elastic(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str]:
    """
    Parse an Elastic detection-rules TOML file and upsert it into the database.
    Returns (is_new, title).

    Requires the 'tomli' package (or Python 3.11+ stdlib 'tomllib').
    Falls back to title-only storage if TOML parsing is unavailable.
    """
    if not TOML_AVAILABLE:
        title  = clean_title_fallback(rel_path)
        is_new = db.upsert_detection(
            source, rel_path, title, "", "", "", rule_url,
            mitre_techniques=extract_mitre_techniques(text), raw_content=text,
        )
        return is_new, title

    try:
        data = tomllib.loads(text)
    except Exception:
        title  = clean_title_fallback(rel_path)
        is_new = db.upsert_detection(
            source, rel_path, title, "", "", "", rule_url,
            mitre_techniques=extract_mitre_techniques(text), raw_content=text,
        )
        return is_new, title

    rule = data.get("rule") or {}

    title       = str(rule.get("name", "")).strip() or clean_title_fallback(rel_path)
    description = str(rule.get("description", ""))[:350]

    # Author may be a list (["Elastic"]) or a plain string
    author_raw = rule.get("author") or ""
    author     = (
        ", ".join(str(a) for a in author_raw)
        if isinstance(author_raw, list)
        else str(author_raw)
    )[:200]

    # Maturity ("stable" / "production") doubles as rule status in Elastic rules
    rule_status = str(rule.get("maturity", "") or rule.get("status", ""))[:50]
    # Elastic stores the UUID as rule.rule_id
    rule_id     = str(rule.get("rule_id", ""))[:64]

    # Creation date — lives in [metadata] or [rule] depending on version
    meta      = data.get("metadata") or {}
    rule_date = str(meta.get("creation_date", "") or rule.get("creation_date", ""))[:20]

    refs_raw = rule.get("references") or []
    refs     = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]

    # Detection logic: raw query labelled with its language (EQL / KQL / ES|QL)
    query    = str(rule.get("query", "")).strip()
    language = str(rule.get("language", "")).upper()
    logic    = (f"[{language}]\n{query}" if language else query)[:600]

    techniques = extract_mitre_techniques(text)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques=techniques,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title


def _process_panther(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str] | None:
    """
    Parse a Panther Labs panther-analysis rule YAML and upsert it into the DB.
    Returns (is_new, title), or None if the file is not a rule (e.g. policy,
    scheduled_rule, data_model) and should be skipped entirely.

    Key fields:
      AnalysisType  — "rule" | "policy" | "scheduled_rule" | etc. (skip non-rule)
      DisplayName   — human-readable rule title
      RuleID        — unique string identifier
      Description   — what the rule detects
      Severity      — Info | Low | Medium | High | Critical
      Reference     — single URL string (not a list)
      Reports.MITRE ATT&CK — list of "TA####:T####" entries

    Detection logic is Python (in a separate .py file referenced by Filename)
    and is not stored inline.
    """
    meta = parse_yaml(text)

    # Only index rule-type files; skip policies, global helpers, data models, etc.
    analysis_type = str(meta.get("AnalysisType", "")).strip().lower()
    if analysis_type and analysis_type != "rule":
        return None

    title       = str(meta.get("DisplayName", "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("Description", ""))[:350]
    rule_id     = str(meta.get("RuleID",      ""))[:64]
    rule_status = str(meta.get("Severity",    ""))[:50]

    # Panther uses "Reference" (singular) for a single URL, unlike most repos
    ref_raw = meta.get("Reference") or meta.get("References") or ""
    if isinstance(ref_raw, list):
        refs = "\n".join(str(r) for r in ref_raw)[:500]
    else:
        refs = str(ref_raw)[:500]

    techniques = extract_mitre_techniques(text)

    is_new = db.upsert_detection(
        source, rel_path, title, description, "", "", rule_url,
        mitre_techniques=techniques,
        author="", rule_status=rule_status,
        rule_date="", refs=refs, rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title


def _process_sublime(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str]:
    """
    Parse a Sublime Security sublime-rules YAML and upsert it into the DB.

    Key fields:
      name                 — rule title
      id                   — UUID
      description          — what the rule detects
      severity             — low | medium | high | critical
      source               — MQL (Message Query Language) detection logic
      tactics_and_techniques — Sublime's own classification (not standard MITRE T-numbers)

    Sublime rules are email-focused and use MQL; tactics_and_techniques is
    Sublime's own taxonomy, not standard T-numbers, so it isn't used for
    MITRE TTPs — extract_mitre_techniques() regex-scans the raw file instead,
    same as every other source.
    """
    meta = parse_yaml(text)

    title       = str(meta.get("name",        "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    rule_id     = str(meta.get("id",          ""))[:64]
    rule_status = str(meta.get("severity",    ""))[:50]

    # MQL detection logic stored in the 'source' field
    logic = str(meta.get("source", "")).strip()[:600]

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques=extract_mitre_techniques(text),
        author="", rule_status=rule_status,
        rule_date="", refs="", rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title


def _process_anvilogic(source: str, rel_path: str, text: str, rule_url: str) -> tuple[bool, str]:
    """
    Parse an Anvilogic Armory detection YAML and upsert it into the DB.

    Armory detections live inside per-detection directories; each YAML is one
    platform variant (Splunk SPL, Snowflake SQL, etc.).

    Key fields:
      title        — human-readable rule title
      id           — numeric string identifier
      description  — what the rule detects
      logic_format — "Splunk" | "snowflake" | other (case may vary)
      logic        — the actual query string
      technique_id — list of standard MITRE T-numbers
      techniques   — list of "tactic:sub:technique" slugs (tactic before first ":")
      references   — list of URLs
    """
    meta = parse_yaml(text)

    title       = str(meta.get("title",       "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    rule_id     = str(meta.get("id",          ""))[:64]

    refs_raw = meta.get("references") or []
    refs = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]

    logic_raw    = str(meta.get("logic",        "")).strip()
    logic_format = str(meta.get("logic_format", "")).strip()

    # For Splunk queries store in spl (mirrors how the native Splunk repo works);
    # for other formats prefix the logic block with its language label.
    if logic_format.lower() == "splunk":
        detection_logic = ""
        spl = logic_raw[:500]
    else:
        label = f"[{logic_format}]\n" if logic_format else ""
        detection_logic = (label + logic_raw)[:600]
        spl = ""

    techniques = extract_mitre_techniques(text)

    is_new = db.upsert_detection(
        source, rel_path, title, description, detection_logic, spl, rule_url,
        mitre_techniques=techniques,
        author="", rule_status="",
        rule_date="", refs=refs, rule_id=rule_id,
        raw_content=text,
    )
    return is_new, title



# ── Repository operations ──────────────────────────────────────────────────────

def clone_repo(repo_cfg: dict) -> bool:
    """
    Shallow-clone a repository to REPOS_DIR/<name>.
    Updates the DB status during the operation.
    Returns True on success.
    """
    name       = repo_cfg["name"]
    owner      = repo_cfg["owner"]
    repo       = repo_cfg["repo"]
    branch     = repo_cfg["branch"]
    local_path = repo_cfg["local_path"] or str(REPOS_DIR / name)
    url        = f"https://github.com/{owner}/{repo}.git"

    db.update_repo_status(name, "cloning")
    db.log_activity("scan", f"Cloning {owner}/{repo}", actor="system",
                    detail=f"branch={branch} → {local_path}")
    print(f"  [{name}] Cloning {owner}/{repo} ({branch})…", flush=True)

    # Clean up any partial clone
    local = Path(local_path)
    if local.exists():
        try:
            shutil.rmtree(str(local))
        except Exception as e:
            print(f"  [{name}] Warning: could not remove {local}: {e}", file=sys.stderr)

    REPOS_DIR.mkdir(parents=True, exist_ok=True)

    # Shallow clone with full working tree so we can read files directly from disk
    rc, out = git_run([
        "clone", "--depth=1", "--single-branch",
        "--branch", branch,
        url, str(local),
    ])

    if rc != 0:
        msg = f"Clone failed: {out[:400]}"
        print(f"  [{name}] {msg}", file=sys.stderr)
        db.update_repo_status(name, "error", msg)
        db.log_activity("scan", f"Clone failed for {name}", actor="system",
                        detail=msg, level="error")
        return False

    # Record the HEAD commit SHA
    rc2, sha = git_run(["rev-parse", "HEAD"], cwd=str(local))
    if rc2 == 0 and sha:
        db.update_repo_sha(name, sha.strip())

    print(f"  [{name}] Clone complete", flush=True)
    return True


def index_repo(repo_cfg: dict) -> int:
    """
    Walk all matching YAML files in the cloned repo and upsert them into the DB.
    Updates DB status.  Returns the number of files indexed.
    """
    name       = repo_cfg["name"]
    local_path = Path(repo_cfg["local_path"])
    paths      = json.loads(repo_cfg["paths"])
    parser     = repo_cfg["parser"]
    owner      = repo_cfg["owner"]
    repo       = repo_cfg["repo"]
    branch     = repo_cfg["branch"]

    db.update_repo_status(name, "indexing")
    db.log_activity("scan", f"Indexing {name}", actor="system",
                    detail=f"walking {len(paths)} path(s)")
    print(f"  [{name}] Indexing files…", flush=True)

    indexed = 0
    for sub_path in paths:
        rule_dir = local_path / sub_path.rstrip("/")
        if not rule_dir.exists():
            print(f"  [{name}] Path not found: {rule_dir}", file=sys.stderr)
            continue

        for dirpath, _, filenames in os.walk(str(rule_dir)):
            for fname in filenames:
                # File extension varies by parser
                if parser == "elastic":
                    if not fname.endswith(".toml"):
                        continue
                else:
                    if not fname.endswith((".yml", ".yaml")):
                        continue
                full = Path(dirpath) / fname
                rel  = str(full.relative_to(local_path)).replace("\\", "/")
                rule_url = f"https://github.com/{owner}/{repo}/blob/{branch}/{rel}"

                try:
                    text = full.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    print(f"  [{name}] Read error {rel}: {e}", file=sys.stderr)
                    continue

                try:
                    # Panther YAML files that are not rule type (policy, data_model,
                    # scheduled_rule, global) are skipped before parsing.
                    if parser == "panther":
                        _at_line = next(
                            (l for l in text.splitlines()[:20]
                             if l.startswith("AnalysisType:")), ""
                        )
                        if _at_line:
                            _at_val = _at_line.partition(":")[2].strip().strip("'\"").lower()
                            if _at_val and _at_val != "rule":
                                continue

                    result = None
                    if parser == "sigma":
                        result = _process_sigma(name, rel, text, rule_url)
                    elif parser == "elastic":
                        result = _process_elastic(name, rel, text, rule_url)
                    elif parser == "panther":
                        result = _process_panther(name, rel, text, rule_url)
                    elif parser == "sublime":
                        result = _process_sublime(name, rel, text, rule_url)
                    elif parser == "anvilogic":
                        result = _process_anvilogic(name, rel, text, rule_url)
                    else:
                        result = _process_splunk(name, rel, text, rule_url)

                    if result is not None:
                        indexed += 1
                except Exception as e:
                    print(f"  [{name}] Parse error {rel}: {e}", file=sys.stderr)

                if indexed > 0 and indexed % 500 == 0:
                    print(f"  [{name}] … {indexed} files indexed", flush=True)

    db.update_repo_status(name, "ready")
    db.log_activity("scan", f"Index complete for {name}", actor="system",
                    detail=f"{indexed} files indexed")
    print(f"  [{name}] Index complete — {indexed} rules", flush=True)
    return indexed


def sync_repo(repo_cfg: dict) -> tuple[int, int]:
    """
    Fetch the latest commits and process only files that changed since last_sha.
    Returns (new_count, modified_count).

    Changed files are detected via:
        git diff --name-status <last_sha> FETCH_HEAD

    Status codes from git:
        A = Added (new file)
        M = Modified
        D = Deleted
        R<n> = Renamed (old_path → new_path, similarity n%)
    """
    name       = repo_cfg["name"]
    local_path = repo_cfg["local_path"]
    branch     = repo_cfg["branch"]
    parser     = repo_cfg["parser"]
    last_sha   = repo_cfg["last_sha"]
    paths      = json.loads(repo_cfg["paths"])
    owner      = repo_cfg["owner"]
    repo       = repo_cfg["repo"]

    local = Path(local_path)
    if not local.exists():
        print(f"  [{name}] Local clone missing — re-queuing for clone", flush=True)
        db.update_repo_status(name, "pending")
        return 0, 0, []

    print(f"  [{name}] Fetching updates…", flush=True)
    rc, out = git_run(["fetch", "--depth=1", "origin", branch], cwd=str(local))
    if rc != 0:
        msg = f"Fetch failed: {out[:300]}"
        print(f"  [{name}] {msg}", file=sys.stderr)
        fail_count = db.increment_repo_fail_count(name)

        if fail_count >= MAX_CONSECUTIVE_FETCH_FAILURES:
            # Retrying against the same local clone hasn't worked — it's
            # likely the shallow clone itself that's stuck, not the remote.
            # Queue a fresh clone instead of failing the same way forever.
            recover_msg = (
                f"Auto-recovering after {fail_count} consecutive fetch "
                f"failures (re-cloning from scratch): {msg}"
            )
            print(f"  [{name}] {recover_msg}", flush=True)
            db.update_repo_status(name, "pending", recover_msg)
            db.reset_repo_fail_count(name)
            db.log_activity(
                "scan", f"Auto-recovering {name} — re-cloning from scratch",
                actor="system",
                detail=f"{fail_count} consecutive fetch failures: {msg}",
                level="warning",
            )
        else:
            db.update_repo_status(name, "error", msg)
            db.log_activity(
                "scan", f"Fetch failed for {name} ({fail_count}/{MAX_CONSECUTIVE_FETCH_FAILURES})",
                actor="system", detail=msg, level="warning",
            )
        return 0, 0, []

    # Check for new commits
    rc, new_sha = git_run(["rev-parse", "FETCH_HEAD"], cwd=str(local))
    new_sha = new_sha.strip()

    if not new_sha or new_sha == last_sha:
        print(f"  [{name}] No changes (SHA unchanged)", flush=True)
        # Update timestamp even if nothing changed
        db.update_repo_sha(name, new_sha or last_sha)
        db.update_repo_status(name, "ready")
        return 0, 0, []

    # Compute the diff before updating the working tree
    diff_ok = False
    changed_files: list[tuple[str, str, str]] = []  # (status_char, old_path, new_path)

    if last_sha:
        rc_diff, diff_out = git_run(
            ["diff", "--name-status", last_sha, "FETCH_HEAD"],
            cwd=str(local),
        )
        if rc_diff == 0:
            diff_ok = True
            for line in diff_out.splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                status_char = parts[0][0].upper()   # first letter: A, M, D, R, C, …
                if status_char == "R" and len(parts) >= 3:
                    changed_files.append((status_char, parts[1], parts[2]))
                else:
                    changed_files.append((status_char, parts[-1], parts[-1]))

    # Apply the fetch to the working tree
    git_run(["reset", "--hard", "FETCH_HEAD"], cwd=str(local))

    new_count, mod_count = 0, 0
    recent_titles: list[tuple[str, str]] = []  # (title, change_type)

    def _in_scope(fp: str) -> bool:
        """Return True if fp is an in-scope rule file inside a monitored path."""
        if not any(fp.startswith(p) for p in paths):
            return False
        if parser == "elastic":
            return fp.endswith(".toml")
        return fp.endswith((".yml", ".yaml"))

    if diff_ok and changed_files:
        for status_char, old_fp, new_fp in changed_files:

            if status_char == "D":
                if _in_scope(old_fp):
                    old_row = db.get_detection(name, old_fp)
                    old_content = old_row["raw_content"] if old_row else ""
                    db.delete_detection(name, old_fp)
                    db.record_update(
                        name, old_fp, old_fp, "deleted",
                        f"https://github.com/{owner}/{repo}/blob/{branch}/{old_fp}",
                        diff_text=compute_file_diff(old_content, "", old_fp),
                    )
                continue

            # Capture the file's previously stored content before processing
            # overwrites it -- this is the "old" side of the modified/renamed
            # diff. For a rename, the old content lives under old_fp.
            old_row     = db.get_detection(name, old_fp if status_char == "R" else new_fp)
            old_content = old_row["raw_content"] if old_row else ""

            if status_char == "R":
                # Handle rename: remove old, process new path
                if _in_scope(old_fp):
                    db.delete_detection(name, old_fp)
                target_fp = new_fp
            else:
                target_fp = new_fp

            if not _in_scope(target_fp):
                continue

            full = local / target_fp
            if not full.exists():
                continue

            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"  [{name}] Read error {target_fp}: {e}", file=sys.stderr)
                continue

            rule_url = f"https://github.com/{owner}/{repo}/blob/{branch}/{target_fp}"

            # Skip non-rule Panther files before parsing
            if parser == "panther":
                _at_line = next(
                    (l for l in text.splitlines()[:20]
                     if l.startswith("AnalysisType:")), ""
                )
                if _at_line:
                    _at_val = _at_line.partition(":")[2].strip().strip("'\"").lower()
                    if _at_val and _at_val != "rule":
                        continue

            try:
                if parser == "sigma":
                    is_new, title = _process_sigma(name, target_fp, text, rule_url)
                elif parser == "elastic":
                    is_new, title = _process_elastic(name, target_fp, text, rule_url)
                elif parser == "panther":
                    result = _process_panther(name, target_fp, text, rule_url)
                    if result is None:
                        continue
                    is_new, title = result
                elif parser == "sublime":
                    is_new, title = _process_sublime(name, target_fp, text, rule_url)
                elif parser == "anvilogic":
                    is_new, title = _process_anvilogic(name, target_fp, text, rule_url)
                else:
                    is_new, title = _process_splunk(name, target_fp, text, rule_url)
            except Exception as e:
                print(f"  [{name}] Parse error {target_fp}: {e}", file=sys.stderr)
                continue

            # Determine change type for the update log
            if status_char == "A" or (status_char == "R" and is_new):
                change_type = "new"
                new_count += 1
            elif status_char == "R":
                change_type = "renamed"
                mod_count += 1
            else:
                change_type = "modified"
                mod_count += 1

            # Diff only matters for modified/renamed — "new" entries show the
            # same Description/MITRE/References/full-file view as the
            # Detections page instead (nothing to diff against).
            diff_text = (
                compute_file_diff(old_content, text, target_fp)
                if change_type in ("modified", "renamed")
                else ""
            )

            db.record_update(name, target_fp, title, change_type, rule_url, diff_text=diff_text)
            if len(recent_titles) < 5 and title:
                recent_titles.append((title, change_type))

    elif not diff_ok and last_sha:
        # diff failed (e.g. last_sha was garbage-collected from shallow history).
        # Fall back: full re-index so DB stays consistent with working tree.
        print(
            f"  [{name}] diff unavailable — performing full re-index",
            flush=True,
        )
        index_repo(repo_cfg)
        db.log_activity(
            "scan", f"Full re-index performed for {name}",
            actor="system",
            detail="git diff unavailable (shallow history may have been garbage-collected) — re-indexed to keep DB consistent",
            level="warning",
        )
        db.update_repo_sha(name, new_sha)
        return 0, 0, []  # counts not meaningful for full re-index

    db.update_repo_sha(name, new_sha)
    db.update_repo_status(name, "ready")
    print(f"  [{name}] Sync complete — {new_count} new / {mod_count} modified", flush=True)
    return new_count, mod_count, recent_titles


# ── Discord notification ───────────────────────────────────────────────────────

def send_discord(webhook_url: str, message: str):
    """Send a plain-text Discord notification. Raises on any HTTP or network error."""
    payload = json.dumps({"content": message, "username": "RuleRadar"}).encode()
    req = urllib.request.Request(webhook_url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "RuleRadar/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"  Discord: {r.status}", flush=True)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  Discord error {e.code}: {body}", file=sys.stderr)
        raise RuntimeError(f"Discord returned HTTP {e.code}: {body}") from e


# ── Main scan entry point ──────────────────────────────────────────────────────

def run_scan(triggered_by: str = "scheduler") -> dict:
    """
    Run a full scan cycle across all enabled repositories.

    For each repo:
      - status='pending'       → clone then full index
      - status='ready'/'error' → git fetch + diff (incremental sync)
      - status='cloning'/'indexing' → skip (already in progress)

    The GitHub REST API is called only for releases metadata (2 unauthenticated
    requests/scan).

    Thread-safe: returns {"skipped": True} if a scan is already running.
    triggered_by : free-text label for the activity log.
    """
    if not _scan_lock.acquire(blocking=False):
        print("  Scan already in progress — skipping.", flush=True)
        db.log_activity("scan", "Scan skipped — already in progress",
                        actor=triggered_by, level="warning")
        return {"skipped": True}

    try:
        db.set_scanning(True)
        db.prune_activity_log(keep_days=180)
        _tz_name  = db.get_app_setting("timezone", "UTC")
        try:
            _tz = ZoneInfo(_tz_name)
        except (ZoneInfoNotFoundError, KeyError):
            _tz = ZoneInfo("UTC")
            _tz_name = "UTC"
        timestamp = datetime.now(timezone.utc).astimezone(_tz).strftime("%Y-%m-%d %H:%M") + f" {_tz_name}"
        print(f"[{timestamp}] Scan started (triggered by: {triggered_by})", flush=True)

        if not YAML_AVAILABLE:
            print(
                "  WARNING: pyyaml not installed — using basic parser. "
                "Run: pip install -r requirements.txt",
                flush=True,
            )
        if not TOML_AVAILABLE:
            print(
                "  WARNING: tomli / tomllib not available — "
                "Elastic rule parsing disabled. Run: pip install -r requirements.txt",
                flush=True,
            )

        repos = db.get_active_repos()
        if not repos:
            print("  No active repos configured — nothing to scan.", flush=True)
            db.finish_scan(0, 0)
            return {"new": 0, "modified": 0, "skipped": False}

        total_new, total_mod = 0, 0
        repo_summary: list[str] = []
        repo_titles: dict[str, list[str]] = {}  # repo name → up to 5 rule titles

        for repo_cfg in repos:
            name   = repo_cfg["name"]
            status = repo_cfg["status"]

            try:
                if status == "pending":
                    if clone_repo(repo_cfg):
                        # Reload config so local_path is current
                        fresh = db.get_repo_by_name(name)
                        if fresh:
                            added = index_repo(fresh)
                            repo_summary.append(f"{name}: initial index of {added} rules")
                            total_new += added
                        else:
                            repo_summary.append(f"{name}: clone OK but reload failed")
                    else:
                        repo_summary.append(f"{name}: clone FAILED")

                elif status in ("ready", "error"):
                    n, m, titles = sync_repo(repo_cfg)
                    repo_summary.append(f"{name}: {n} new / {m} modified")
                    if titles:
                        repo_titles[name] = titles
                    total_new += n
                    total_mod += m

                elif status in ("cloning", "indexing"):
                    print(f"  [{name}] Already {status} — skipping", flush=True)
                    repo_summary.append(f"{name}: {status} (skipped)")

            except Exception as e:
                msg = str(e)
                print(f"  [{name}] Unexpected error: {msg}", file=sys.stderr)
                db.update_repo_status(name, "error", msg[:300])
                db.log_activity("scan", f"Error processing {name}",
                                actor=triggered_by, detail=msg, level="error")
                repo_summary.append(f"{name}: ERROR — {msg[:80]}")

        # Fetch GitHub releases for each active repo (unauthenticated REST call)
        since_dt = datetime.now(timezone.utc) - timedelta(hours=2)
        for repo_cfg in repos:
            try:
                for rel in releases_since(
                    repo_cfg["owner"], repo_cfg["repo"], since_dt
                ):
                    db.upsert_release(
                        repo_cfg["name"],
                        rel["tag_name"],
                        rel.get("name", ""),
                        (rel.get("body") or "")[:1000],
                        rel.get("published_at", ""),
                        rel.get("html_url", ""),
                    )
            except Exception as e:
                print(f"  [{repo_cfg['name']}] Releases fetch error: {e}", file=sys.stderr)

        summary_str = " | ".join(repo_summary)
        print(f"  Summary: {summary_str}", flush=True)
        print("Done.", flush=True)

        db.finish_scan(total_new, total_mod)
        db.log_activity(
            "scan",
            f"Scan complete — {total_new} new, {total_mod} modified",
            actor=triggered_by,
            detail=summary_str,
        )

        # Discord notifications (only when there is something to report).
        # Each webhook is isolated — one failure does not abort the rest.
        if total_new + total_mod > 0:
            site_url = os.environ.get("RULERADAR_SITE_URL", "").rstrip("/")
            msg_parts = [f"**RuleRadar — {timestamp}**"]
            for line in repo_summary:
                repo_name = line.split(":")[0]
                msg_parts.append(f"• {line}")
                for title, change_type in repo_titles.get(repo_name, []):
                    label = "modified" if change_type in ("modified", "renamed") else "new"
                    msg_parts.append(f"  ↳ {title} ({label})")
            if site_url:
                msg_parts.append(f"\n🔗 View updates: {site_url}/updates")
            msg = "\n".join(msg_parts)
            for webhook_url in db.get_all_user_webhooks():
                try:
                    send_discord(webhook_url, msg)
                except Exception as disc_err:
                    print(f"  Discord notification failed: {disc_err}", file=sys.stderr)
                    db.log_activity(
                        "scan", "Discord notification failed",
                        actor=triggered_by, detail=str(disc_err), level="warning",
                    )

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

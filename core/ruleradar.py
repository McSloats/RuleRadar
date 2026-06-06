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

# MITRE ATT&CK tactic ID (TA####) → display name
# Used by the Panther parser which stores tactic IDs rather than slugs.
MITRE_TACTIC_IDS: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Regex matching a MITRE technique ID: t1234 or t1234.567
_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


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


# ── MITRE extraction helpers ───────────────────────────────────────────────────

def extract_sigma_mitre(meta: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK tags from a Sigma rule's 'tags' list.

    Sigma tags look like:
        tags:
          - attack.execution           ← tactic slug
          - attack.t1059               ← technique
          - attack.t1059.001           ← technique + sub-technique

    Returns (pipe-joined techniques, pipe-joined tactic display names).
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
        part = tag[7:]
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
    Parse MITRE ATT&CK data from a Splunk security_content detection.

    Newer security_content files (post-2024 refactor) place mitre_attack_id and
    mitre_attack_enrichments at the TOP LEVEL of the YAML document.  Older files
    nested both fields inside a 'tags' dict.  Both formats are supported: the
    top-level keys are checked first, with the tags dict as a fallback.

    Technique IDs are a list of strings, e.g. ['T1059', 'T1059.001'].
    A single rule can have multiple IDs; all are stored pipe-separated.

    Returns (pipe-joined techniques, pipe-joined tactic names).
    """
    # Support both new (top-level) and old (under tags:) field locations
    tags = meta.get("tags") or {}
    if not isinstance(tags, dict):
        tags = {}

    # ── Technique IDs ─────────────────────────────────────────────────────────
    raw_ids = meta.get("mitre_attack_id") or tags.get("mitre_attack_id") or []
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    seen_t: set[str] = set()
    techniques: list[str] = []
    for t in raw_ids:
        uid = str(t).strip().upper()
        if uid and uid not in seen_t:
            seen_t.add(uid)
            techniques.append(uid)

    # ── Tactics from enrichments ───────────────────────────────────────────────
    # Newer security_content uses "mitre_attack_tactics" (plural);
    # older files used "mitre_attack_tactic" (singular). Check both.
    enrichments = (
        meta.get("mitre_attack_enrichments")
        or tags.get("mitre_attack_enrichments")
        or []
    )
    seen_ta: set[str] = set()
    tactics: list[str] = []
    if isinstance(enrichments, list):
        for enr in enrichments:
            if not isinstance(enr, dict):
                continue
            tactic_list = (
                enr.get("mitre_attack_tactics")
                or enr.get("mitre_attack_tactic")
                or []
            )
            if isinstance(tactic_list, str):
                tactic_list = [tactic_list]
            for t in tactic_list:
                name = str(t).strip()
                if name and name not in seen_ta:
                    seen_ta.add(name)
                    tactics.append(name)

    return "|".join(techniques), "|".join(tactics)


def extract_elastic_mitre(rule: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK data from an Elastic detection rule's 'threat' array.

    Elastic TOML structure:
        [[rule.threat]]
        framework = "MITRE ATT&CK"
        [rule.threat.tactic]
        name = "Privilege Escalation"
        [[rule.threat.technique]]
        id = "T1055"
        [[rule.threat.technique.subtechnique]]
        id = "T1055.001"

    Returns (pipe-joined technique IDs, pipe-joined tactic names).
    """
    threats = rule.get("threat") or []
    if not isinstance(threats, list):
        return "", ""

    techniques: list[str] = []
    tactics: list[str]    = []
    seen_t: set[str]      = set()
    seen_ta: set[str]     = set()

    for threat in threats:
        if not isinstance(threat, dict):
            continue
        tactic = threat.get("tactic") or {}
        tactic_name = str(tactic.get("name", "")).strip()
        if tactic_name and tactic_name not in seen_ta:
            seen_ta.add(tactic_name)
            tactics.append(tactic_name)
        for tech in (threat.get("technique") or []):
            if not isinstance(tech, dict):
                continue
            tid = str(tech.get("id", "")).strip().upper()
            if tid and tid not in seen_t:
                seen_t.add(tid)
                techniques.append(tid)
            for sub in (tech.get("subtechnique") or []):
                if not isinstance(sub, dict):
                    continue
                sid = str(sub.get("id", "")).strip().upper()
                if sid and sid not in seen_t:
                    seen_t.add(sid)
                    techniques.append(sid)

    return "|".join(techniques), "|".join(tactics)


def extract_panther_mitre(meta: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK data from a Panther rule's Reports section.

    Reports.MITRE ATT&CK entries use the format "TA0005:T1562" where
    TA#### is the tactic ID and T#### is the technique ID.

    Returns (pipe-joined techniques, pipe-joined tactic names).
    """
    reports = meta.get("Reports") or {}
    mitre_entries: list = []
    if isinstance(reports, dict):
        mitre_entries = reports.get("MITRE ATT&CK") or []
    if not isinstance(mitre_entries, list):
        mitre_entries = []

    seen_t:  set[str] = set()
    seen_ta: set[str] = set()
    techniques: list[str] = []
    tactics:    list[str] = []

    for entry in mitre_entries:
        # Expected format: "TA0005:T1562" or "TA0005:T1562.001"
        parts = str(entry).split(":")
        if len(parts) >= 2:
            tactic_id    = parts[0].strip().upper()
            technique_id = parts[1].strip().upper()
            if technique_id and technique_id not in seen_t:
                seen_t.add(technique_id)
                techniques.append(technique_id)
            tactic_name = MITRE_TACTIC_IDS.get(tactic_id, "")
            if tactic_name and tactic_name not in seen_ta:
                seen_ta.add(tactic_name)
                tactics.append(tactic_name)

    return "|".join(techniques), "|".join(tactics)


def extract_anvilogic_mitre(meta: dict) -> tuple[str, str]:
    """
    Parse MITRE ATT&CK data from an Anvilogic Armory detection YAML.

    technique_id: list of standard T-numbers, e.g. ["T1218", "T1204.002"]
    techniques:   list of tactic:technique slugs, e.g.
                  ["defense-evasion:system binary proxy execution",
                   "execution:user execution:malicious file"]
    Tactics are extracted from the segment before the first ":" in each
    techniques entry, then looked up (or title-cased as a fallback).

    Returns (pipe-joined techniques, pipe-joined tactic names).
    """
    raw_ids = meta.get("technique_id") or []
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]

    seen_t: set[str] = set()
    techniques: list[str] = []
    for t in raw_ids:
        uid = str(t).strip().upper()
        if uid and uid not in seen_t:
            seen_t.add(uid)
            techniques.append(uid)

    raw_tactics = meta.get("techniques") or []
    if isinstance(raw_tactics, str):
        raw_tactics = [raw_tactics]

    seen_ta: set[str] = set()
    tactics: list[str] = []
    for entry in raw_tactics:
        # First segment before ":" is the tactic slug (hyphenated, lower-case)
        slug = str(entry).split(":")[0].strip().lower()
        if not slug:
            continue
        # Look up in MITRE_TACTICS (uses underscores), fall back to title-case
        tactic_name = MITRE_TACTICS.get(slug.replace("-", "_"), "")
        if not tactic_name:
            tactic_name = slug.replace("-", " ").title()
        if tactic_name and tactic_name not in seen_ta:
            seen_ta.add(tactic_name)
            tactics.append(tactic_name)

    return "|".join(techniques), "|".join(tactics)


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
    techniques, tactics = extract_sigma_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
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
    techniques, tactics = extract_splunk_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, "", search[:500], rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
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
        is_new = db.upsert_detection(source, rel_path, title, "", "", "", rule_url)
        return is_new, title

    try:
        data = tomllib.loads(text)
    except Exception:
        title  = clean_title_fallback(rel_path)
        is_new = db.upsert_detection(source, rel_path, title, "", "", "", rule_url)
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

    techniques, tactics = extract_elastic_mitre(rule)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status,
        rule_date=rule_date, refs=refs, rule_id=rule_id,
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

    techniques, tactics = extract_panther_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, "", "", rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author="", rule_status=rule_status,
        rule_date="", refs=refs, rule_id=rule_id,
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

    Sublime rules are email-focused and use MQL; no MITRE technique IDs are
    present.  tactics_and_techniques is stored as mitre_tactics for display.
    """
    meta = parse_yaml(text)

    title       = str(meta.get("name",        "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    rule_id     = str(meta.get("id",          ""))[:64]
    rule_status = str(meta.get("severity",    ""))[:50]

    # MQL detection logic stored in the 'source' field
    logic = str(meta.get("source", "")).strip()[:600]

    # Sublime uses its own tactic/technique taxonomy — store as mitre_tactics
    tac_raw = meta.get("tactics_and_techniques") or []
    if isinstance(tac_raw, str):
        tac_raw = [tac_raw]
    tactics = "|".join(str(t).strip() for t in tac_raw if str(t).strip())

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, "", rule_url,
        mitre_techniques="", mitre_tactics=tactics,
        author="", rule_status=rule_status,
        rule_date="", refs="", rule_id=rule_id,
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

    techniques, tactics = extract_anvilogic_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, detection_logic, spl, rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author="", rule_status="",
        rule_date="", refs=refs, rule_id=rule_id,
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
        db.update_repo_status(name, "error", msg)
        return 0, 0, []

    # Check for new commits
    rc, new_sha = git_run(["rev-parse", "FETCH_HEAD"], cwd=str(local))
    new_sha = new_sha.strip()

    if not new_sha or new_sha == last_sha:
        print(f"  [{name}] No changes (SHA unchanged)", flush=True)
        # Update timestamp even if nothing changed
        db.update_repo_sha(name, new_sha or last_sha)
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
                    db.delete_detection(name, old_fp)
                    db.record_update(
                        name, old_fp, old_fp, "deleted", "", "",
                        f"https://github.com/{owner}/{repo}/blob/{branch}/{old_fp}",
                    )
                continue

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

            # Build appropriate logic/spl for the update record
            if parser == "sigma":
                logic   = sigma_detection_block(text)
                spl_val = ""
            elif parser == "elastic" and TOML_AVAILABLE:
                try:
                    _edata   = tomllib.loads(text)
                    _erule   = _edata.get("rule") or {}
                    _q       = str(_erule.get("query", "")).strip()
                    _lang    = str(_erule.get("language", "")).upper()
                    logic    = (f"[{_lang}]\n{_q}" if _lang else _q)[:600]
                    spl_val  = ""
                except Exception:
                    logic   = ""
                    spl_val = ""
            elif parser == "sublime":
                _meta   = parse_yaml(text)
                logic   = str(_meta.get("source", "")).strip()[:600]
                spl_val = ""
            elif parser == "anvilogic":
                _meta  = parse_yaml(text)
                _lraw  = str(_meta.get("logic", "")).strip()
                _lfmt  = str(_meta.get("logic_format", "")).strip()
                if _lfmt.lower() == "splunk":
                    logic   = ""
                    spl_val = _lraw[:500]
                else:
                    _lbl    = f"[{_lfmt}]\n" if _lfmt else ""
                    logic   = (_lbl + _lraw)[:600]
                    spl_val = ""
            elif parser == "panther":
                logic   = ""
                spl_val = ""
            else:
                meta    = parse_yaml(text)
                logic   = ""
                spl_val = str(meta.get("search", ""))[:500]

            db.record_update(name, target_fp, title, change_type, logic, spl_val, rule_url)
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
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
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

        db.finish_scan(total_new, total_mod)

        summary_str = " | ".join(repo_summary)
        print(f"  Summary: {summary_str}", flush=True)
        print("Done.", flush=True)

        db.log_activity(
            "scan",
            f"Scan complete — {total_new} new, {total_mod} modified",
            actor=triggered_by,
            detail=summary_str,
        )

        # Discord notifications (only when there is something to report)
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
                send_discord(webhook_url, msg)

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

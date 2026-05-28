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

import database as db

# ── Optional Python dependencies ───────────────────────────────────────────────
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    SIGMA_BACKEND_AVAILABLE = True
except ImportError:
    SIGMA_BACKEND_AVAILABLE = False

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
    Parse MITRE ATT&CK data from a Splunk security_content detection's 'tags' dict.

    Returns (pipe-joined techniques, pipe-joined tactic names).
    """
    tags = meta.get("tags") or {}
    if not isinstance(tags, dict):
        return "", ""

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


# ── Elastic ECS → Splunk CIM field mapping ─────────────────────────────────────

# Maps Elastic Common Schema (ECS) field names to the closest Splunk CIM equivalent.
# Used to produce readable SPL templates from EQL/KQL Elastic detection rules.
_ECS_TO_SPL: dict[str, str] = {
    # Process
    "process.name":                  "process_name",
    "process.executable":            "process_path",
    "process.command_line":          "process_exec",
    "process.args":                  "process_args",
    "process.args_count":            "process_args_count",
    "process.pid":                   "pid",
    "process.ppid":                  "parent_pid",
    "process.entity_id":             "process_guid",
    "process.parent.name":           "parent_process_name",
    "process.parent.executable":     "parent_process_path",
    "process.parent.pid":            "parent_pid",
    "process.parent.command_line":   "parent_process_exec",
    "process.hash.md5":              "process_hash",
    "process.hash.sha256":           "process_hash",
    "process.hash.sha1":             "process_hash",
    "process.code_signature.status": "signature_status",
    "process.code_signature.trusted": "signature_trusted",
    # Host
    "host.name":                     "host",
    "host.hostname":                 "host",
    "host.os.type":                  "os",
    "host.os.name":                  "os_name",
    "host.ip":                       "host_ip",
    # User
    "user.name":                     "user",
    "user.domain":                   "user_domain",
    "user.id":                       "user_id",
    # Network
    "destination.ip":                "dest_ip",
    "destination.port":              "dest_port",
    "destination.domain":            "dest",
    "destination.address":           "dest",
    "destination.bytes":             "bytes_out",
    "source.ip":                     "src_ip",
    "source.port":                   "src_port",
    "source.address":                "src",
    "source.bytes":                  "bytes_in",
    "network.protocol":              "app",
    "network.transport":             "transport",
    "network.direction":             "direction",
    "network.bytes":                 "bytes",
    "network.community_id":          "network_id",
    # File
    "file.name":                     "file_name",
    "file.path":                     "file_path",
    "file.extension":                "file_extension",
    "file.directory":                "file_dir",
    "file.hash.md5":                 "file_hash",
    "file.hash.sha256":              "file_hash",
    "file.hash.sha1":                "file_hash",
    "file.pe.imphash":               "imphash",
    "file.size":                     "file_size",
    # DNS
    "dns.question.name":             "query",
    "dns.question.type":             "record_type",
    "dns.answers.data":              "answer",
    "dns.answers.type":              "record_type",
    # URL / HTTP
    "url.full":                      "url",
    "url.domain":                    "url_domain",
    "url.path":                      "uri_path",
    "url.query":                     "uri_query",
    "http.request.method":           "http_method",
    "http.response.status_code":     "status",
    "http.request.body.bytes":       "bytes_in",
    "http.response.body.bytes":      "bytes_out",
    # Windows event log
    "winlog.event_id":               "EventCode",
    "winlog.task":                   "TaskCategory",
    "winlog.channel":                "Channel",
    "winlog.provider_name":          "SourceName",
    "winlog.record_id":              "RecordNumber",
    "winlog.computer_name":          "ComputerName",
    # Registry
    "registry.path":                 "registry_path",
    "registry.key":                  "registry_key_name",
    "registry.value.name":           "registry_value_name",
    "registry.value.data":           "registry_value_data",
    "registry.value.type":           "registry_value_type",
    "registry.hive":                 "registry_hive",
    # Event metadata
    "event.action":                  "action",
    "event.category":                "category",
    "event.code":                    "EventCode",
    "event.type":                    "type",
    "event.outcome":                 "result",
    "event.dataset":                 "source",
    # Service
    "service.name":                  "service_name",
    "service.type":                  "service_type",
    # TLS / certificates
    "tls.client.ja3":                "ja3",
    "tls.server.ja3s":               "ja3s",
    "tls.server.certificate.subject": "ssl_subject",
    # Email
    "email.from.address":            "src_user",
    "email.to.address":              "recipient",
    "email.subject":                 "subject",
    # Cloud
    "cloud.provider":                "cloud_provider",
    "cloud.account.id":              "account_id",
    "cloud.region":                  "region",
}


def _apply_ecs_mapping(query: str) -> str:
    """Replace ECS field names with Splunk CIM equivalents (longest match first)."""
    for ecs, spl_field in sorted(_ECS_TO_SPL.items(), key=lambda x: -len(x[0])):
        query = query.replace(ecs, spl_field)
    return query


def _guess_splunk_index(rule: dict) -> str:
    """Suggest a Splunk index based on Elastic rule tags and index patterns."""
    tags  = [str(t).lower() for t in (rule.get("tags") or [])]
    index = [str(i).lower() for i in (rule.get("index") or [])]
    if any("windows" in t for t in tags) or any("winlog" in i or "windows" in i for i in index):
        return "index=wineventlog OR index=sysmon"
    if any("linux" in t for t in tags) or any("auditd" in i or "syslog" in i for i in index):
        return "index=linux_secure OR index=syslog"
    if any("macos" in t for t in tags):
        return "index=osquery OR index=endpoint"
    if any("network" in t for t in tags) or any("flow" in i or "zeek" in i for i in index):
        return "index=netflow OR index=zeek"
    if any("aws" in t or "azure" in t or "gcp" in t or "cloud" in t for t in tags):
        return "index=cloudtrail OR index=azure_activity OR index=gcp_audit"
    return "index=*"


def _eql_to_spl(query: str, rule: dict) -> str:
    """Convert an EQL query to a best-effort Splunk SPL template."""
    mapped = _apply_ecs_mapping(query)
    index  = _guess_splunk_index(rule)

    # EQL sequence → multi-event SPL hint (transaction or join)
    if re.search(r"\bsequence\b", mapped, re.IGNORECASE):
        lines = [
            "* EQL sequence — use transaction or join in Splunk",
            index,
        ]
        for line in mapped.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("[") or stripped.startswith("by "):
                continue
            # Drop event-category prefix ("process where", "network where", etc.)
            stripped = re.sub(r"^\w+\s+where\s+", "", stripped, flags=re.IGNORECASE)
            stripped = re.sub(r"\s*==\s*", "=", stripped)
            stripped = re.sub(r"\s+and\s+", " AND ", stripped, flags=re.IGNORECASE)
            stripped = re.sub(r"\s+or\s+", " OR ",  stripped, flags=re.IGNORECASE)
            stripped = re.sub(r"(?<!\w)not\s+", "NOT ", stripped, flags=re.IGNORECASE)
            lines.append(f"| search {stripped}")
        return "\n".join(lines)

    # Standard EQL event query
    normalized = re.sub(r"^\w+\s+where\s+", "", mapped.strip(), flags=re.IGNORECASE)
    normalized = re.sub(r"\s*==\s*",  "=",   normalized)
    normalized = re.sub(r"\s*!=\s*",  "!=",  normalized)
    normalized = re.sub(r"\s+like~?\s+", " LIKE ", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+and\s+", " AND ", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+or\s+",  " OR ",  normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"(?<!\w)not\s+", "NOT ", normalized, flags=re.IGNORECASE)

    return f"{index}\n| search {normalized}"


def _kuery_to_spl(query: str, rule: dict) -> str:
    """Convert a KQL / Lucene query to a best-effort Splunk SPL template."""
    mapped = _apply_ecs_mapping(query)
    index  = _guess_splunk_index(rule)

    # KQL field:value  →  SPL field=value
    normalized = re.sub(r'(\w[\w._-]*)\s*:\s*"([^"]*)"', r'\1="\2"', mapped)
    normalized = re.sub(r'(\w[\w._-]*)\s*:\s*([^\s()]+)', r'\1=\2', normalized)
    # Boolean operators
    normalized = re.sub(r"\band\b", "AND", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bor\b",  "OR",  normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bnot\b", "NOT", normalized, flags=re.IGNORECASE)

    return f"{index}\n| search {normalized}"


def elastic_to_spl(rule: dict) -> str:
    """
    Generate a best-effort Splunk SPL template from an Elastic rule dict
    (the [rule] section of a parsed TOML file).

    Output is clearly marked as a template requiring review — it is NOT a
    verified, production-ready query.  Field names are translated from ECS
    to Splunk CIM conventions; index hints are derived from rule tags.
    Returns an empty string if the rule has no query.
    """
    query    = str(rule.get("query", "")).strip()
    language = str(rule.get("language", "kuery")).lower()
    if not query:
        return ""

    try:
        if language == "eql":
            body = _eql_to_spl(query, rule)
        elif language in ("kuery", "lucene"):
            body = _kuery_to_spl(query, rule)
        elif language == "esql":
            # ES|QL has pipeline syntax similar to SPL but different semantics
            body = (
                "* ES|QL — manual conversion required\n"
                + _apply_ecs_mapping(query)
            )
        else:
            body = f"index=*\n| search {_apply_ecs_mapping(query)}"

        return (
            f"* SPL TEMPLATE — auto-translated from Elastic {language.upper()}\n"
            "* Review field names and index expressions before use in production\n"
            f"{body}"
        )
    except Exception:
        return ""


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
    spl   = sigma_to_spl(text)
    logic = sigma_detection_block(text)

    title       = str(meta.get("title",       "")).strip() or clean_title_fallback(rel_path)
    description = str(meta.get("description", ""))[:350]
    author      = str(meta.get("author",      ""))[:200]
    rule_status = str(meta.get("status",      ""))[:50]
    severity    = str(meta.get("level",       ""))[:50]
    rule_date   = str(meta.get("date",        ""))[:20]
    refs_raw    = meta.get("references") or []
    refs        = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]
    techniques, tactics = extract_sigma_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, spl or "", rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status, severity=severity,
        rule_date=rule_date, refs=refs,
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
    refs_raw    = meta.get("references") or []
    refs        = (
        "\n".join(str(r) for r in refs_raw)
        if isinstance(refs_raw, list) else str(refs_raw)
    )[:500]
    techniques, tactics = extract_splunk_mitre(meta)

    is_new = db.upsert_detection(
        source, rel_path, title, description, "", search[:500], rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status, severity="",
        rule_date=rule_date, refs=refs,
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
    severity    = str(rule.get("severity", ""))[:50]

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

    # SPL template generated from the Elastic query
    spl = elastic_to_spl(rule) or ""

    techniques, tactics = extract_elastic_mitre(rule)

    is_new = db.upsert_detection(
        source, rel_path, title, description, logic, spl, rule_url,
        mitre_techniques=techniques, mitre_tactics=tactics,
        author=author, rule_status=rule_status, severity=severity,
        rule_date=rule_date, refs=refs,
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
                    if parser == "sigma":
                        _process_sigma(name, rel, text, rule_url)
                    elif parser == "elastic":
                        _process_elastic(name, rel, text, rule_url)
                    else:
                        _process_splunk(name, rel, text, rule_url)
                    indexed += 1
                except Exception as e:
                    print(f"  [{name}] Parse error {rel}: {e}", file=sys.stderr)

                if indexed % 500 == 0:
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
        return 0, 0

    print(f"  [{name}] Fetching updates…", flush=True)
    rc, out = git_run(["fetch", "--depth=1", "origin", branch], cwd=str(local))
    if rc != 0:
        msg = f"Fetch failed: {out[:300]}"
        print(f"  [{name}] {msg}", file=sys.stderr)
        db.update_repo_status(name, "error", msg)
        return 0, 0

    # Check for new commits
    rc, new_sha = git_run(["rev-parse", "FETCH_HEAD"], cwd=str(local))
    new_sha = new_sha.strip()

    if not new_sha or new_sha == last_sha:
        print(f"  [{name}] No changes (SHA unchanged)", flush=True)
        # Update timestamp even if nothing changed
        db.update_repo_sha(name, new_sha or last_sha)
        return 0, 0

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
            try:
                if parser == "sigma":
                    is_new, title = _process_sigma(name, target_fp, text, rule_url)
                elif parser == "elastic":
                    is_new, title = _process_elastic(name, target_fp, text, rule_url)
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
                spl_val = sigma_to_spl(text) or ""
            elif parser == "elastic" and TOML_AVAILABLE:
                try:
                    _edata   = tomllib.loads(text)
                    _erule   = _edata.get("rule") or {}
                    _q       = str(_erule.get("query", "")).strip()
                    _lang    = str(_erule.get("language", "")).upper()
                    logic    = (f"[{_lang}]\n{_q}" if _lang else _q)[:600]
                    spl_val  = elastic_to_spl(_erule) or ""
                except Exception:
                    logic   = ""
                    spl_val = ""
            else:
                meta    = parse_yaml(text)
                logic   = ""
                spl_val = str(meta.get("search", ""))[:500]

            db.record_update(name, target_fp, title, change_type, logic, spl_val, rule_url)

    elif not diff_ok and last_sha:
        # diff failed (e.g. last_sha was garbage-collected from shallow history).
        # Fall back: full re-index so DB stays consistent with working tree.
        print(
            f"  [{name}] diff unavailable — performing full re-index",
            flush=True,
        )
        index_repo(repo_cfg)
        db.update_repo_sha(name, new_sha)
        return 0, 0  # counts not meaningful for full re-index

    db.update_repo_sha(name, new_sha)
    db.update_repo_status(name, "ready")
    print(f"  [{name}] Sync complete — {new_count} new / {mod_count} modified", flush=True)
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
        print(f"  Discord error {e.code}: {e.read().decode(errors='replace')}",
              file=sys.stderr)


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
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        print(f"[{timestamp}] Scan started (triggered by: {triggered_by})", flush=True)

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
                    n, m = sync_repo(repo_cfg)
                    repo_summary.append(f"{name}: {n} new / {m} modified")
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
            msg_parts = [f"**RuleRadar — {timestamp}**"]
            for line in repo_summary:
                msg_parts.append(f"• {line}")
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

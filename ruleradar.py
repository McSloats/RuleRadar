#!/usr/bin/env python3
"""
RuleRadar — daily security detection monitor for:
  - SigmaHQ/sigma (rules directories)
  - splunk/security_content (develop branch, detections/)

Checks the past 24 hours for new/modified rules and releases, then:
  1. Builds a Markdown report
  2. Posts it to Discord as a file attachment
  3. Uploads it to a GitHub repository under reports/
"""

import base64
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
CONFIG_PATH = Path(__file__).parent / "config.json"

SIGMA_REPO  = {"owner": "SigmaHQ", "repo": "sigma",            "branch": "master"}
SPLUNK_REPO = {"owner": "splunk",  "repo": "security_content",  "branch": "develop"}

SIGMA_PATHS  = [
    "rules/", "rules-emerging-threats/",
    "rules-threat-hunting/", "rules-compliance/", "rules-placeholder/",
]
SPLUNK_PATHS = ["detections/"]


# ── GitHub read helpers ────────────────────────────────────────────────────────

def gh(url: str, token: str) -> "dict | list | None":
    req = urllib.request.Request(url)
    if token:
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
    data = gh(f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=10", token) or []
    cutoff = since_dt.isoformat().replace("+00:00", "Z")
    return [r for r in data if (r.get("published_at") or "") >= cutoff]


def file_content(owner, repo, path, ref, token) -> "str | None":
    data = gh(f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}", token)
    if data and "content" in data:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return None


# ── GitHub write helper ────────────────────────────────────────────────────────

def gh_put(url: str, payload: dict, token: str) -> "dict | None":
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "ruleradar/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  GitHub PUT {e.code}: {url}\n  {body}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  GitHub PUT error: {e}", file=sys.stderr)
        return None


def upload_report(cfg: dict, token: str, filename: str, md_content: str):
    owner  = cfg["github_reports_owner"]
    repo   = cfg["github_reports_repo"]
    branch = cfg.get("github_reports_branch", "main")
    path   = f"reports/{filename}"
    url    = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    # Fetch existing SHA if file already exists (needed for updates)
    existing = gh(f"{url}?ref={branch}", token)
    payload = {
        "message": f"chore: add RuleRadar report {filename}",
        "content": base64.b64encode(md_content.encode()).decode(),
        "branch":  branch,
    }
    if isinstance(existing, dict) and "sha" in existing:
        payload["sha"] = existing["sha"]

    result = gh_put(url, payload, token)
    if result:
        html_url = result.get("content", {}).get("html_url", "")
        print(f"  GitHub upload OK: {html_url}")
    return result


# ── YAML / content helpers ─────────────────────────────────────────────────────

def parse_yaml(text: str) -> dict:
    if YAML_AVAILABLE and text:
        try:
            return yaml.safe_load(text) or {}
        except Exception:
            pass
    result = {}
    for line in (text or "").splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


def sigma_detection_block(text: str) -> str:
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


def sigma_to_spl(yaml_text: str) -> "str | None":
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


# ── repository scanners ────────────────────────────────────────────────────────

def scan_sigma(since_iso: str, token: str) -> dict:
    owner, repo, branch = SIGMA_REPO["owner"], SIGMA_REPO["repo"], SIGMA_REPO["branch"]
    commits = commits_since(owner, repo, branch, since_iso, token)
    print(f"  SigmaHQ/sigma: {len(commits)} commits in window")

    new_rules, modified_rules, seen = [], [], set()
    for c in commits:
        for f in commit_files(owner, repo, c["sha"], token):
            fname = f.get("filename", "")
            if fname in seen or not is_rule_file(fname, SIGMA_PATHS):
                continue
            seen.add(fname)
            text = file_content(owner, repo, fname, branch, token)
            meta = parse_yaml(text) if text else {}
            entry = {
                "file":        fname,
                "title":       str(meta.get("title", fname.split("/")[-1])),
                "description": str(meta.get("description", ""))[:350],
                "detection":   sigma_detection_block(text or ""),
                "spl":         sigma_to_spl(text) if text else None,
                "url":         f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}",
            }
            if f["status"] == "added":
                new_rules.append(entry)
            elif f["status"] in ("modified", "renamed", "changed"):
                modified_rules.append(entry)

    return {"new": new_rules, "modified": modified_rules}


def scan_splunk(since_iso: str, token: str) -> dict:
    owner, repo, branch = SPLUNK_REPO["owner"], SPLUNK_REPO["repo"], SPLUNK_REPO["branch"]
    commits = commits_since(owner, repo, branch, since_iso, token)
    print(f"  splunk/security_content: {len(commits)} commits in window")

    new_dets, mod_dets, seen = [], [], set()
    for c in commits:
        for f in commit_files(owner, repo, c["sha"], token):
            fname = f.get("filename", "")
            if fname in seen or not is_rule_file(fname, SPLUNK_PATHS):
                continue
            seen.add(fname)
            text = file_content(owner, repo, fname, branch, token)
            meta = parse_yaml(text) if text else {}
            search = str(meta.get("search", ""))
            if not search and text:
                for line in text.splitlines():
                    if line.startswith("search:"):
                        search = line[7:].strip()
                        break
            entry = {
                "file":        fname,
                "title":       str(meta.get("name", fname.split("/")[-1].replace("_", " ").title())),
                "description": str(meta.get("description", ""))[:350],
                "search":      search[:500],
                "url":         f"https://github.com/{owner}/{repo}/blob/{branch}/{fname}",
            }
            if f["status"] == "added":
                new_dets.append(entry)
            elif f["status"] in ("modified", "renamed", "changed"):
                mod_dets.append(entry)

    return {"new": new_dets, "modified": mod_dets}


# ── markdown builder ───────────────────────────────────────────────────────────

def md_rule(entry: dict, label: str, code_field: str, code_lang: str, code_label: str) -> str:
    lines = [
        f"### {label} [{entry['title']}]({entry['url']})",
        f"`{entry['file']}`",
    ]
    if entry.get("description"):
        lines += ["", entry["description"]]
    if entry.get(code_field):
        lines += ["", f"**{code_label}**", f"```{code_lang}", entry[code_field], "```"]
    lines.append("")
    return "\n".join(lines)


def md_release(rel: dict) -> str:
    body = (rel.get("body") or "").strip()[:600]
    lines = [
        f"### 🔖 [{rel.get('name') or rel['tag_name']}]({rel['html_url']})",
        f"Published: {rel.get('published_at', '')[:10]}",
    ]
    if body:
        lines += ["", body]
    lines.append("")
    return "\n".join(lines)


def build_markdown(
    sigma: dict, splunk: dict,
    sigma_rels: list, splunk_rels: list,
    timestamp: str,
) -> "str | None":
    total = (
        len(sigma["new"]) + len(sigma["modified"]) +
        len(splunk["new"]) + len(splunk["modified"]) +
        len(sigma_rels) + len(splunk_rels)
    )
    if total == 0:
        return None

    spl_note = (
        ""
        if SIGMA_BACKEND_AVAILABLE
        else "\n> ⚠️ `pySigma-backend-splunk` not installed — showing raw Sigma detection instead of SPL.\n"
    )

    lines = [
        f"# RuleRadar — {timestamp}",
        "",
        "## Summary",
        "",
        f"| Repository | New | Modified | Releases |",
        f"|---|---|---|---|",
        f"| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) "
        f"| {len(sigma['new'])} | {len(sigma['modified'])} | {len(sigma_rels)} |",
        f"| [splunk/security_content](https://github.com/splunk/security_content/tree/develop/detections) "
        f"| {len(splunk['new'])} | {len(splunk['modified'])} | {len(splunk_rels)} |",
        "",
        spl_note,
        "---",
        "",
        "## SigmaHQ / sigma",
        "",
    ]

    if sigma_rels:
        lines += ["### Releases", ""]
        lines += [md_release(r) for r in sigma_rels]

    if sigma["new"]:
        lines += ["### New Detection Rules", ""]
        for e in sigma["new"]:
            if e.get("spl"):
                lines.append(md_rule(e, "🆕", "spl", "spl", "Splunk SPL (auto-converted from Sigma):"))
            else:
                lines.append(md_rule(e, "🆕", "detection", "yaml", "Sigma Detection Logic:"))

    if sigma["modified"]:
        lines += ["### Modified Detection Rules", ""]
        for e in sigma["modified"][:15]:
            lines.append(md_rule(e, "✏️", "detection", "yaml", "Sigma Detection Logic:"))

    if not sigma_rels and not sigma["new"] and not sigma["modified"]:
        lines += ["*No changes in the last 24 hours.*", ""]

    lines += ["---", "", "## splunk / security_content — develop/detections", ""]

    if splunk_rels:
        lines += ["### Releases", ""]
        lines += [md_release(r) for r in splunk_rels]

    if splunk["new"]:
        lines += ["### New Detections", ""]
        for e in splunk["new"]:
            lines.append(md_rule(e, "🆕", "search", "spl", "SPL Search:"))

    if splunk["modified"]:
        lines += ["### Modified Detections", ""]
        for e in splunk["modified"][:15]:
            lines.append(md_rule(e, "✏️", "search", "spl", "SPL Search:"))

    if not splunk_rels and not splunk["new"] and not splunk["modified"]:
        lines += ["*No changes in the last 24 hours.*", ""]

    lines += [
        "---",
        "",
        "*Generated by RuleRadar*",
    ]

    return "\n".join(lines)


# ── Discord sender ─────────────────────────────────────────────────────────────

def send_discord(webhook_url: str, summary: str, filename: str, md_content: str):
    boundary = "RuleRadarBoundary47x"
    payload  = json.dumps({"content": summary, "username": "RuleRadar"})
    file_bytes = md_content.encode("utf-8")

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="payload_json"\r\n'
        f"Content-Type: application/json\r\n\r\n"
        f"{payload}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'
        f"Content-Type: text/markdown\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(webhook_url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"  Discord: {r.status} {r.reason}")
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")
        print(f"  Discord error {e.code}: {err}", file=sys.stderr)
        raise


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    if not CONFIG_PATH.exists():
        print(f"ERROR: config.json not found at {CONFIG_PATH}", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        cfg = json.load(f)

    token     = cfg.get("github_token", "")
    since_dt  = datetime.now(timezone.utc) - timedelta(hours=24)
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_et    = datetime.now()  # cron runs in TZ=America/New_York
    timestamp = now_et.strftime("%Y-%m-%d %H:%M ET")
    filename  = now_et.strftime("%Y-%m-%d_%H-%M") + ".md"

    print(f"[{now_et.isoformat()}] Running RuleRadar")
    print(f"  Checking commits since {since_iso}")
    if not YAML_AVAILABLE:
        print("  WARNING: pyyaml not installed — using basic parser. Run: pip install -r requirements.txt")
    if not SIGMA_BACKEND_AVAILABLE:
        print("  WARNING: pySigma-backend-splunk not installed — Sigma→SPL conversion disabled. Run: pip install -r requirements.txt")

    sigma_data  = scan_sigma(since_iso, token)
    splunk_data = scan_splunk(since_iso, token)
    sigma_rels  = releases_since(SIGMA_REPO["owner"],  SIGMA_REPO["repo"],  since_dt, token)
    splunk_rels = releases_since(SPLUNK_REPO["owner"], SPLUNK_REPO["repo"], since_dt, token)

    print(
        f"  sigma  → new={len(sigma_data['new'])}  mod={len(sigma_data['modified'])}  releases={len(sigma_rels)}\n"
        f"  splunk → new={len(splunk_data['new'])}  mod={len(splunk_data['modified'])}  releases={len(splunk_rels)}"
    )

    md = build_markdown(sigma_data, splunk_data, sigma_rels, splunk_rels, timestamp)

    if md is None:
        print("  No changes detected. Nothing to send.")
        return

    total_new = len(sigma_data["new"]) + len(splunk_data["new"])
    total_mod = len(sigma_data["modified"]) + len(splunk_data["modified"])

    parts = [f"**RuleRadar — {timestamp}**"]
    parts.append(
        f"Sigma: **{len(sigma_data['new'])}** new / **{len(sigma_data['modified'])}** modified"
        + (f" / **{len(sigma_rels)}** release(s)" if sigma_rels else "")
    )
    parts.append(
        f"Splunk: **{len(splunk_data['new'])}** new / **{len(splunk_data['modified'])}** modified"
        + (f" / **{len(splunk_rels)}** release(s)" if splunk_rels else "")
    )
    discord_msg = "\n".join(parts)

    print(f"  Sending to Discord (file: {filename})...")
    send_discord(cfg["discord_webhook_url"], discord_msg, filename, md)

    print(f"  Uploading to GitHub ({cfg['github_reports_owner']}/{cfg['github_reports_repo']})...")
    upload_report(cfg, token, filename, md)

    print("Done.")


if __name__ == "__main__":
    main()

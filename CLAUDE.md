# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RuleRadar is a Flask + SQLite security detection rule monitor. It clones detection rule repositories — including [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), [splunk/security_content](https://github.com/splunk/security_content), [elastic/detection-rules](https://github.com/elastic/detection-rules), [panther-labs/panther-analysis](https://github.com/panther-labs/panther-analysis), [sublime-security/sublime-rules](https://github.com/sublime-security/sublime-rules), and [anvilogic-forge/armory](https://github.com/anvilogic-forge/armory) — locally via git and tracks new, modified, deleted, and renamed detection rules through a dark-themed web interface.

## Commands

### Local development
```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 start.py          # starts web (port 5000) + bi-hourly scheduler together
python3 start.py --run-now  # also fires one immediate scan on startup
```

### Run components individually
```bash
python3 webapp/app.py        # web only, Flask dev server (debugging only)
python3 core/scheduler.py    # scheduler only
python3 core/ruleradar.py    # run one scan cycle immediately
```

### Docker
```bash
docker build -t tsloats/ruleradar:latest .   # build image (runs web + scheduler via start.py)
docker push tsloats/ruleradar:latest         # push to Docker Hub
docker compose pull             # pull latest image from Docker Hub (tsloats/ruleradar)
docker compose up -d            # start single container (web + scheduler together)
docker compose logs -f          # stream logs in real-time (PYTHONUNBUFFERED=1 is set)
docker compose down             # stop
docker compose down -v          # stop + delete all data volume
```

### Process model (Docker)
The Dockerfile `CMD` runs `start.py`, which launches the web app (under gunicorn) and `core/scheduler.py` as sub-processes in a single container. There is no separate scheduler container — docker-compose has one service (`web`). `start.py` auto-restarts either process if it crashes.

### Database path
Controlled by env var `RULERADAR_DB` (defaults to `./ruleradar.db`). In Docker it is `/app/data/ruleradar.db` — must be set via environment variable or the DB writes to `/app/ruleradar.db` inside the container (not persisted).

## Deployment notes

- The image needs only `RULERADAR_DB=/app/data/ruleradar.db` (plus `PYTHONUNBUFFERED=1` for live logs) and a persistent volume or host folder mounted at `/app/data`. No command override is needed — the default `start.py` runs web + scheduler.
- The container runs as UID/GID 568 (`ruleradar`). A bind-mounted host folder must be writable by that UID/GID, or the app can't write the database or clone repos. Named Docker volumes get the right ownership automatically.
- After deploying, `/app/data` should contain `ruleradar.db`, `.secret_key` and `repos/`.
- **Never commit details of a specific deployment** (host names or paths, NAS/container names, LAN IPs, tunnel setup) to this public repo, the wiki or the image.

## Architecture

### Process model
Two processes share one SQLite database (WAL mode):
- **`webapp/app.py`** — Flask web app; never triggers scans automatically. `start.py` serves it with **gunicorn** (`webapp/gunicorn.conf.py`); `python3 webapp/app.py` runs Flask's dev server for debugging, and `start.py` falls back to it on Windows (no gunicorn).
  - Gunicorn runs **1 worker process, gthread, 8 threads — keep `workers = 1`**: the API and login rate limiters are in-process memory (more workers multiply the limits) and the initial setup scan runs in a web-process thread (don't set `max_requests`).
  - gthread has no slow-header timeout, so 8 stalled connections can block it. That's acceptable only behind a reverse proxy or tunnel that buffers client requests; never expose gunicorn's port directly to the internet.
- **`core/scheduler.py`** — fires `ruleradar.run_scan()` at every even UTC hour via APScheduler `CronTrigger(hour="*/2")`. Has a 90-minute staleness guard to skip if a scan completed recently.

The initial scan is always triggered by an admin on `/setup-repos`, which calls `_start_background_scan()` (daemon thread in the web process).

### Scanning flow (`core/ruleradar.py`)
```
repos.status = 'pending'  →  clone_repo()  [git clone --depth=1]
                           →  index_repo()  [os.walk all YAML files]

repos.status = 'ready'    →  sync_repo()   [git fetch --depth=1]
                                           [git diff --name-status <last_sha> FETCH_HEAD]
                                           [git reset --hard FETCH_HEAD]
```
Changed-file status codes from `git diff --name-status`: A=Added, M=Modified, D=Deleted, R=Renamed. Renamed files delete the old DB row and process the new path.

All clones live at `REPOS_DIR = db.DB_PATH.parent / "repos"` (i.e. `/app/data/repos` in Docker).

### Database schema (`core/database.py`)
Key tables:
- **`detections`** — current state of every known rule: `source`, `file_path`, `title`, `description`, `detection_logic`, `spl`, `author`, `rule_status`, `rule_date`, `refs`, `mitre_techniques`, `rule_url` (a `mitre_tactics` column also exists but is never populated — don't surface it)
- **`updates`** — append-only change log: `source`, `file_path`, `title`, `change_type` (new/modified/deleted/renamed), `detection_logic`, `spl`, `rule_url`, `detected_at`
- **`repos`** — monitored repositories with status machine: `pending → cloning → indexing → ready / error`
- **`scan_status`** — singleton row tracking last scan time and `is_scanning` flag
- **`api_keys`** — one row per user with an API key: `key_hash` (SHA-256), `key_prefix`, `created_at`, `expires_at` ('' = never), `last_used_at`, `last_used_ip`

`refs` is stored as newline-separated URLs. `mitre_techniques` is a pipe-separated string of ATT&CK technique IDs (`T1059|T1059.001`).

**MITRE:** every parser fills `mitre_techniques` the same way — `extract_mitre_techniques()` regex-scans the raw file for `T####` / `T####.###` IDs, regardless of the source's own schema. RuleRadar tracks **techniques only, not tactics**: UI labels say "MITRE Technique(s)", the `mitre` filter (web and API) matches technique IDs only, and the API has no tactics field.

`get_updates()` LEFT JOINs `detections` to enrich rows with `author`, `rule_status`, `rule_date`, `description`, `refs` — these are not stored in `updates` itself.

Schema migrations live in `_migrate_schema()` using try/except ALTER TABLE (idempotent).

### Parser differences
- **Sigma** (`_process_sigma`): `detection_logic` = the YAML `detection:` block (first 600 chars); `spl` = "" (empty — SPL auto-translation was removed)
- **Splunk** (`_process_splunk`): `detection_logic` = "" (empty); `spl` = the `search:` field
- **Elastic** (`_process_elastic`): parses TOML rule files (`.toml`) via `tomllib` (Python 3.11+ stdlib) or `tomli` backport; `detection_logic` = `[<LANGUAGE>]\nquery`, labelled with `rule.language` upper-cased: `[EQL]`, `[KUERY]` (KQL), `[ESQL]`, `[LUCENE]`, or no label when the rule has no language (e.g. machine-learning rules); `spl` = "" (empty — SPL auto-translation was removed)
- **Panther** (`_process_panther`): YAML rules from `panther-labs/panther-analysis` (`rules/`). Only files with `AnalysisType: rule` are indexed (policies, scheduled_rules, data_models are skipped — parser returns `None`). Title = `DisplayName`, ID = `RuleID`, `rule_status` = `Severity`. Detection logic is Python in a separate `.py` file — `detection_logic` and `spl` are both empty.
- **Sublime** (`_process_sublime`): YAML rules from `sublime-security/sublime-rules` (`detection-rules/`). Email detection rules using MQL (Message Query Language). `detection_logic` = `source` field (MQL expression); `spl` = empty; `rule_status` = `severity`. Sublime's `tactics_and_techniques` is its own taxonomy, not ATT&CK IDs, and isn't stored, so almost no Sublime rules have techniques.
- **Anvilogic** (`_process_anvilogic`): YAML rules from `anvilogic-forge/armory` (`detections/`). Detections live inside per-detection directories; each YAML is a platform variant. `logic_format` is `"Splunk"` or `"snowflake"` (case varies). For Splunk: `detection_logic` = "", `spl` = `logic` field. For others: `detection_logic` = `[format]\nlogic`, `spl` = "".

Templates branch on `row.source` to label logic correctly: `'splunk'` → "Detection Logic (SPL)", `'elastic'` → "Detection Logic (EQL / KQL)", otherwise plain "Detection Logic".

### Web app (`webapp/app.py`)
- Flask-Login with bcrypt. First visit → `/setup` (create admin). No repos configured → `/setup-repos`.
- `before_request` gate uses `_REPO_GATE_SKIP` set to allow auth/admin/health routes through before setup is complete.
- `api_scan_status` endpoint polled every 15 s by the nav-bar scan badge (defined in `layout.html`). The `/api/scan/*`, `/api/rule-suggest`, `/api/dashboard/*` and `/api/repo-sizes` endpoints are internal (browser session auth) — distinct from the public API below.

### Public API (`/api/v1`, `api_v1` blueprint in `webapp/app.py`)
- Read-only JSON. Auth is **only** `Authorization: Bearer rr_...` — session cookies are never accepted, so CSRF doesn't apply. The blueprint skips the repo-setup gate.
- **One key per user**, enforced by `UNIQUE(user_id)` on `api_keys`. Only `sha256(key)` is stored (plus a non-secret 11-char `key_prefix` for display); the plaintext is shown once by `settings_api_key_generate`, which renders the page directly with `Cache-Control: no-store` — never flash the key (Flask's session cookie is signed, not encrypted). Lost key → **Regenerate** (`db.replace_api_key`: delete + insert in one transaction, so two keys never coexist) or revoke → generate. Expiry chosen per key (`db.API_KEY_EXPIRY_CHOICES`: 1/7/30/90/365 days or never, default 30) and stored in `expires_at` ('' = never); `authenticate_api_key` returns `expired` and the API answers 401 "API key has expired". Expired keys stay listed until regenerated/revoked. Admins can revoke any user's key; deleting a user cascades.
- In-memory limits: 120 req/min per key, 10 failed auths/min per IP (429 + `Retry-After`). `last_used_at`/`last_used_ip` are written at most once a minute.
- Errors are `{"error": {"status", "message"}}`; an `HTTPException` handler returns JSON for any `/api/v1/*` path. Bad query params raise `_BadParam` → 400.
- List endpoints reuse `db.search_detections` / `db.get_updates` (which take a `since` UTC ISO string). Keep query logic in `core/database.py` so the web pages and API share it.
- The endpoint/parameter reference lives in the GitHub wiki (`API` page, `API_DOCS_URL` in `app.py`, linked from Settings and the README) — not in the app or README. **When an endpoint, parameter or response field changes, update the wiki page too** (wiki repo: `https://github.com/McSloats/RuleRadar.wiki.git`).

### Frontend (`webapp/templates/`)
All CSS (~880 lines) and JS are inline in `layout.html` — no external dependencies. Templates extend `layout.html` with `{% block title %}` and `{% block content %}`.

**Colour palette:**
| Token | Value | Usage |
|---|---|---|
| Body bg | `#0d0a18` | `<body>` |
| Surface | `#160f2a` | Cards, nav |
| Deep | `#0a0716` | Inputs, code blocks |
| Border | `#2b1e4a` | Dividers |
| Muted text | `#9080b8` | Secondary text, labels |
| Accent | `#d4a017` | Gold — links, headings, brand |
| Danger | `#fc8181` / `#3b1818` | Deleted badge, errors |

Form field wrappers must use `class="form-group"` (not `form-field` — that class does not exist).

**Badge classes for activity log categories:** `.badge-auth`, `.badge-admin`, `.badge-user`, `.badge-system`, `.badge-new` (scan). Level badges: `.badge-deleted` (error/red), `.badge-warning` (warning/gold), `.badge-user` (info).

**Saved filters** are stored as a JSON array in `user_settings.saved_filters`. Each filter object has keys: `id`, `name`, `source`, `change_type`, `title`, `mitre`, `days`. Old filters with a stale `severity` key are harmless — they are silently ignored.

### Static assets
- `webapp/static/icon.svg` — Shield Radar icon (44×48), used in nav and auth page headers
- `webapp/static/favicon.svg` — same icon on `<rect rx="9" fill="#160f2a">` background

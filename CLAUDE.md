# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RuleRadar is a Flask + SQLite security detection rule monitor. It clones [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) locally via git and tracks new, modified, deleted, and renamed detection rules through a dark-themed web interface.

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
python3 webapp/app.py     # web only
python3 scheduler.py      # scheduler only
python3 ruleradar.py      # run one scan cycle immediately
```

### Docker
```bash
docker compose up --build -d   # build and start both services
docker compose logs -f          # stream logs in real-time (PYTHONUNBUFFERED=1 is set)
docker compose down             # stop
docker compose down -v          # stop + delete all data volume
```

### Database path
Controlled by env var `RULERADAR_DB` (defaults to `./ruleradar.db`). In Docker it is `/app/data/ruleradar.db` on the named volume `ruleradar-db`, shared between both containers.

## Architecture

### Process model
Two processes share one SQLite database (WAL mode):
- **`webapp/app.py`** — Flask web server; never triggers scans automatically
- **`scheduler.py`** — fires `ruleradar.run_scan()` at every even UTC hour via APScheduler `CronTrigger(hour="*/2")`. Has a 90-minute staleness guard to skip if a scan completed recently.

The initial scan is always triggered by an admin on `/setup-repos`, which calls `_start_background_scan()` (daemon thread in the web process).

### Scanning flow (`ruleradar.py`)
```
repos.status = 'pending'  →  clone_repo()  [git clone --depth=1]
                           →  index_repo()  [os.walk all YAML files]

repos.status = 'ready'    →  sync_repo()   [git fetch --depth=1]
                                           [git diff --name-status <last_sha> FETCH_HEAD]
                                           [git reset --hard FETCH_HEAD]
```
Changed-file status codes from `git diff --name-status`: A=Added, M=Modified, D=Deleted, R=Renamed. Renamed files delete the old DB row and process the new path.

All clones live at `REPOS_DIR = db.DB_PATH.parent / "repos"` (i.e. `/app/data/repos` in Docker).

### Database schema (`database.py`)
Key tables:
- **`detections`** — current state of every known rule: `source`, `file_path`, `title`, `description`, `detection_logic`, `spl`, `author`, `rule_status`, `severity`, `rule_date`, `refs`, `mitre_techniques`, `mitre_tactics`, `rule_url`
- **`updates`** — append-only change log: `source`, `file_path`, `title`, `change_type` (new/modified/deleted/renamed), `detection_logic`, `spl`, `rule_url`, `detected_at`
- **`repos`** — monitored repositories with status machine: `pending → cloning → indexing → ready / error`
- **`scan_status`** — singleton row tracking last scan time and `is_scanning` flag

`refs` is stored as newline-separated URLs. `mitre_techniques` and `mitre_tactics` are pipe-separated strings.

`get_updates()` LEFT JOINs `detections` to enrich rows with `author`, `rule_status`, `rule_date`, `description`, `refs` — these are not stored in `updates` itself.

Schema migrations live in `_migrate_schema()` using try/except ALTER TABLE (idempotent).

### Parser differences
- **Sigma** (`_process_sigma`): `detection_logic` = the YAML `detection:` block; `spl` = pySigma SPL translation (may be empty if library unavailable)
- **Splunk** (`_process_splunk`): `detection_logic` = "" (empty); `spl` = the `search:` field

Templates branch on `row.source == 'splunk'` to label logic correctly.

### Web app (`webapp/app.py`)
- Flask-Login with bcrypt. First visit → `/setup` (create admin). No repos configured → `/setup-repos`.
- `before_request` gate uses `_REPO_GATE_SKIP` set to allow auth/admin/health routes through before setup is complete.
- `api_scan_status` endpoint polled every 15 s by the nav-bar scan badge (defined in `layout.html`).

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

### Static assets
- `webapp/static/icon.svg` — Shield Radar icon (44×48), used in nav and auth page headers
- `webapp/static/favicon.svg` — same icon on `<rect rx="9" fill="#160f2a">` background

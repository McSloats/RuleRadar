# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules. All data is stored in a local SQLite database and browsable through a built-in web interface. No config files required — everything is configured through the web UI.

## What it does

Every two hours RuleRadar:
1. Fetches changes from both repos via `git fetch` and diffs against the last known commit
2. Parses new and modified rule files (`.yml` / `.yaml`)
3. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
4. Persists every detection and change event to SQLite
5. Sends a summary to every user who has a personal Discord webhook configured

The web interface provides:
- **Detections** — full-text search across every known rule (title, description, logic, SPL) with saved filter presets
- **Updates** — chronological feed of new, modified, deleted, and renamed rules, filterable by source and change type
- **Settings** — per-user Discord webhook, saved filter presets, password change
- **Admin** — add/remove users, reset passwords, grant/revoke admin access, manage monitored repositories

---

## First run

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Start everything

```bash
python3 start.py
```

Opens the **web interface** at **http://localhost:5000** and starts the **bi-hourly scheduler**.

On the very first visit you are prompted to create an admin account. After logging in:
- Go to **Admin** → enable the repositories you want to monitor (initial clone takes 2–5 minutes)
- Go to **Settings** → add a Discord webhook for personal notifications

### Run components individually

| Command | What it does |
|---------|-------------|
| `python3 ruleradar.py` | Run one scan cycle immediately |
| `python3 webapp/app.py` | Web interface only (port 5000) |
| `python3 scheduler.py` | Bi-hourly scheduler only |

---

## Running with Docker

```bash
docker compose up --build -d
```

Open **http://localhost:5000** and create your admin account.  
All settings (user accounts, Discord webhooks, repository data) are stored in a named Docker volume (`ruleradar-db`) and persist across restarts.

```bash
docker compose down          # stop
docker compose down -v       # stop + wipe all data
```

---

## Configuration (all via the web UI — no files needed)

| Setting | Where | Description |
|---------|-------|-------------|
| Monitored repos | Admin → Monitored Repositories | Enable SigmaHQ/sigma and/or splunk/security_content. Repos are cloned locally via git — no API token required. |
| Discord webhook | Settings → Discord Notifications | Per-user webhook for scan summaries. Create one in Discord: Server Settings → Integrations → Webhooks. |
| Saved filters | Settings → Saved Filters | Named presets (source, change type, keyword, MITRE TTP) that appear as quick-access buttons on the Detections and Updates pages. |
| Users | Admin → Users | Add users, reset passwords, grant/revoke admin, delete users. |

---

## Services

| Service | Description |
|---------|-------------|
| `web` | Flask web interface — login, browse, search, manage settings |
| `scheduler` | Runs a scan every two hours (00:00, 02:00 … 22:00 UTC) via APScheduler |

---

## First scan behaviour

On first setup an admin selects repositories to monitor. RuleRadar performs a shallow `git clone --depth=1` of each repo and indexes all matching rule files. Subsequent scans use `git fetch` and only process files that changed since the last indexed commit.

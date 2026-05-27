# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules. All data is stored in a local SQLite database and browsable through a built-in web interface. No config files required — everything is configured through the web UI.

## What it does

Every hour (and on page open) RuleRadar:
1. Fetches commits from both repos and filters for new/modified rule files (`.yml` / `.yaml`)
2. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
3. Persists every detection and change event to SQLite
4. Sends a summary to every user who has a personal Discord webhook configured

The web interface provides:
- **Detections** — full-text search across every known rule (title, description, logic, SPL) with saved filter presets
- **Updates** — chronological feed of new and modified rules, filterable by source and change type
- **Settings** — per-user Discord webhook, saved filter presets, password change
- **Admin** — GitHub token configuration, add/remove users, reset passwords, manage admin access

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

Opens the **web interface** at **http://localhost:5000** and starts the **hourly scheduler**.

On the very first visit you are prompted to create an admin account. After logging in:
- Go to **Admin** → paste your GitHub token (optional but recommended)
- Go to **Settings** → add a Discord webhook for personal notifications
- Click **↻ Scan Now** to seed the database immediately

### Optional: run a scan immediately on startup

```bash
python3 start.py --run-now
```

### Run components individually

| Command | What it does |
|---------|-------------|
| `python3 ruleradar.py` | Run one scan cycle immediately |
| `python3 webapp/app.py` | Web interface only (port 5000) |
| `python3 scheduler.py` | Hourly scheduler only |

---

## Running with Docker

```bash
docker compose up --build -d
```

Open **http://localhost:5000** and create your admin account.  
All settings (GitHub token, user accounts, Discord webhooks) are stored in a named Docker volume (`ruleradar-db`) and persist across restarts.

```bash
docker compose down          # stop
docker compose down -v       # stop + wipe all data
```

---

## Configuration (all via the web UI — no files needed)

| Setting | Where | Description |
|---------|-------|-------------|
| GitHub token | Admin → GitHub Configuration | Raises API rate limit to 5,000 req/hr. Optional — both repos are public. Scope: `public_repo` (classic) or `Contents: Read` (fine-grained). |
| Discord webhook | Settings → Discord Notifications | Per-user webhook for scan summaries. Create one in Discord: Server Settings → Integrations → Webhooks. |
| Saved filters | Settings → Saved Filters | Named presets (source, change type, keyword) that appear as quick-access buttons on the Detections and Updates pages. |
| Users | Admin → Users | Add users, reset passwords, grant/revoke admin, delete users. |

---

## Services

| Service | Description |
|---------|-------------|
| `web` | Flask web interface — login, browse, search, manage settings |
| `scheduler` | Runs a scan every hour via APScheduler |

---

## First scan behaviour

The very first scan uses a **30-day window** to seed the database with recent history from both repos. All subsequent scans use a **2-hour window**.

---

## Uninstall

```bash
bash cleanup.sh
```

Removes the virtual environment, log file, and optionally the project directory.

# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules. All data is stored locally in a SQLite database and browsable through a built-in web interface.

## What it does

Every hour (and on page open) RuleRadar:
1. Fetches commits from both repos and filters for new/modified rule files (`.yml` / `.yaml`)
2. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
3. Persists every detection and change event to a local SQLite database
4. Optionally posts a brief summary to a Discord channel

The web interface provides:
- **Detections** — full-text search across every known rule (title, description, detection logic, SPL)
- **Updates** — chronological feed of new and modified rules, filterable by source and change type

## Configuration

Fill in `config.json` before running:

| Key | Description |
|-----|-------------|
| `github_token` | Personal access token — needs **Contents: Read** on the monitored repos. Unauthenticated requests are rate-limited to 60/hour; a token raises this to 5,000/hour. |
| `discord_webhook_url` | *(Optional)* Discord webhook URL for change notifications. Leave as-is to disable. |

## Running manually

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Start everything at once

```bash
python3 start.py
```

Starts the **web interface** and **hourly scheduler** together.  
Open **http://localhost:5000** — you will be prompted to create an admin account on first visit.

### Optional: run a scan immediately on startup

```bash
python3 start.py --run-now
```

Runs one scan right away before starting the scheduler.

### Run components individually

| Command | What it does |
|---------|-------------|
| `python3 ruleradar.py` | Run one scan cycle immediately |
| `python3 webapp/app.py` | Web interface only (port 5000) |
| `python3 scheduler.py` | Hourly scheduler only |

---

## Running with Docker

### Build and launch

```bash
docker compose up --build -d
```

Open **http://localhost:5000** and create your admin account.  
The database is stored in a named Docker volume (`ruleradar-db`) so data persists across restarts.

### Stop

```bash
docker compose down
```

### Remove all data (including the database volume)

```bash
docker compose down -v
```

---

## Services

| Service | Description |
|---------|-------------|
| `web` | Flask web interface — login, browse detections, view updates |
| `scheduler` | Runs a scan every hour via APScheduler |

---

## First run

On the very first scan RuleRadar uses a **30-day window** to seed the database with recent history from both repos. All subsequent scans use a **2-hour window**.

---

## Uninstall

```bash
bash cleanup.sh
```

Removes the virtual environment, log file, and optionally the project directory.

---

## Required GitHub token scopes

The token only needs **read access** to public repositories:

- `public_repo` (classic token), **or**
- `Contents: Read` (fine-grained token scoped to the target repos)

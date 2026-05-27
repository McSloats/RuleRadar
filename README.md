# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules, then delivers a daily Markdown report to Discord, uploads it to a GitHub repository, and exposes a web interface for browsing and searching all reports.

## What it does

Every 24 hours RuleRadar:
1. Fetches commits from both repos and filters for new/modified rule files (`.yml`/`.yaml`)
2. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
3. Builds a Markdown report summarising all changes and releases
4. Posts the report to a Discord channel as a file attachment
5. Uploads the report to a GitHub repository under `reports/`

The web interface lets you browse all uploaded reports, filter by date range, full-text search across every report, and auto-refreshes every 5 minutes to surface new reports without a page reload.

## Configuration

Fill in `config.json` before running:

| Key | Description |
|-----|-------------|
| `github_token` | Personal access token — needs **Contents: Read and write** on the reports repo |
| `discord_webhook_url` | Discord webhook URL for the target channel |
| `github_reports_owner` | GitHub username / org that owns the reports repo |
| `github_reports_repo` | Name of the repo where reports will be uploaded |
| `github_reports_branch` | Branch to commit reports to (default: `main`) |

---

## Running manually

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Start everything at once

```bash
python3 start.py
```

This starts the **web interface** and **scheduler** together. Open http://localhost:5000.

### Optional: run the monitor immediately on startup

```bash
python3 start.py --run-now
```

Runs `ruleradar.py` once right away (generating a report and sending to Discord), then starts the scheduler for future daily runs.

### Run components individually

| Command | What it does |
|---------|-------------|
| `python3 ruleradar.py` | Run one monitor cycle immediately |
| `python3 webapp/app.py` | Web interface only (port 5000) |
| `python3 scheduler.py` | Scheduler only (fires `ruleradar.py` daily at 08:00 ET) |

---

## Running with Docker

### Build and launch

```bash
docker compose up --build -d
```

Open **http://localhost:5000**. The scheduler runs automatically inside the container.

### Stop

```bash
docker compose down
```

---

## Services

| Service | Description |
|---------|-------------|
| `web` | Flask web interface — browse, filter, and search reports |
| `scheduler` | Runs `ruleradar.py` daily at 08:00 ET via APScheduler |

---

## Uninstall

```bash
bash cleanup.sh
```

Removes any cron job, virtual environment, log file, and optionally the project directory.

# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules, then delivers a daily Markdown report to Discord, uploads it to a GitHub repository, and exposes a web interface for browsing and searching all reports.

## What it does

Every 24 hours RuleRadar:
1. Fetches commits from both repos and filters for new/modified rule files (`.yml`/`.yaml`)
2. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
3. Builds a Markdown report summarising all changes and releases
4. Posts the report to a Discord channel as a file attachment
5. Uploads the report to a GitHub repository under `reports/`

The web interface lets you browse all uploaded reports, filter by date range, and full-text search across every report.

## Quick start (Docker)

### 1. Configure

Fill in `config.json` with your values:

| Key | Description |
|-----|-------------|
| `github_token` | Personal access token — needs **Contents: Read and write** on the reports repo |
| `discord_webhook_url` | Discord webhook URL for the target channel |
| `github_reports_owner` | GitHub username / org that owns the reports repo |
| `github_reports_repo` | Name of the repo where reports will be uploaded |
| `github_reports_branch` | Branch to commit reports to (default: `main`) |

### 2. Build and launch

```bash
docker compose up --build -d
```

The web interface is available at **http://localhost:5000**

### 3. Stop

```bash
docker compose down
```

## Manual setup (without Docker)

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the monitor manually

```bash
python3 ruleradar.py
```

### 3. Run the web interface

```bash
python3 webapp/app.py
```

### 4. Schedule with cron (Linux)

```bash
bash setup_cron.sh
```

## Services

| Service | Description |
|---------|-------------|
| `web` | Flask web interface on port 5000 — browse and search reports |
| `scheduler` | APScheduler container — runs `ruleradar.py` daily at 8 AM ET |

## Uninstall

```bash
bash cleanup.sh
```

Removes the cron job, virtual environment, log file, and optionally the entire project directory.

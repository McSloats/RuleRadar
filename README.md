# RuleRadar

Monitors [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [splunk/security_content](https://github.com/splunk/security_content) for new and modified detection rules, then delivers a daily Markdown report to Discord and uploads it to a GitHub repository.

## What it does

Every 24 hours RuleRadar:
1. Fetches commits from both repos and filters for new/modified rule files (`.yml`/`.yaml`)
2. Converts Sigma rules to Splunk SPL via `pySigma-backend-splunk`
3. Builds a Markdown report summarising all changes and releases
4. Posts the report to a Discord channel as a file attachment
5. Uploads the report to a GitHub repository under `reports/`

## Setup

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

Fill in `config.json` with your values:

| Key | Description |
|-----|-------------|
| `github_token` | Personal access token — needs **Contents: Read and write** on the reports repo |
| `discord_webhook_url` | Discord webhook URL for the target channel |
| `github_reports_owner` | GitHub username / org that owns the reports repo |
| `github_reports_repo` | Name of the repo where reports will be uploaded |
| `github_reports_branch` | Branch to commit reports to (default: `main`) |

### 3. Run manually

```bash
python3 ruleradar.py
```

### 4. Schedule with cron (Linux)

```bash
bash setup_cron.sh
```

This installs a daily 8 AM ET cron job that calls `run_monitor.sh`, which activates the venv automatically and appends output to `monitor_log.txt`.

## Uninstall

```bash
bash cleanup.sh
```

Removes the cron job, virtual environment, log file, and optionally the entire project directory.

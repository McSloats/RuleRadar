#!/usr/bin/env bash
# Run once to install RuleRadar dependencies and register the 8 AM ET daily cron job.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_monitor.sh"

# ── 1. Virtual environment + dependencies ─────────────────────────────────────
echo ">>> Creating virtual environment..."
python3 -m venv "$SCRIPT_DIR/.venv"
source "$SCRIPT_DIR/.venv/bin/activate"

echo ">>> Installing dependencies..."
pip install --upgrade pip --quiet
pip install pyyaml pySigma-backend-splunk --quiet

deactivate
echo ">>> Dependencies installed."

# ── 2. Make the runner executable ─────────────────────────────────────────────
chmod +x "$RUNNER"

# ── 3. Register the cron job ──────────────────────────────────────────────────
# TZ=America/New_York lets cron honour Eastern time automatically
# (handles EST/EDT transitions). Supported on Linux with glibc.
CRON_LINE="TZ=America/New_York"
CRON_JOB="0 8 * * * $RUNNER"

# Remove any existing entry for this script, then add the fresh one
(
    crontab -l 2>/dev/null | grep -v "$RUNNER" || true
    echo "$CRON_LINE"
    echo "$CRON_JOB"
) | crontab -

echo ""
echo ">>> Cron job registered:"
crontab -l | grep -A1 "America/New_York"
echo ""
echo ">>> To run immediately for a test:"
echo "    bash \"$RUNNER\""
echo ""
echo ">>> To watch the log:"
echo "    tail -f \"$SCRIPT_DIR/monitor_log.txt\""

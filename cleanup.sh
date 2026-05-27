#!/usr/bin/env bash
# Uninstalls RuleRadar — removes the cron job, virtual environment,
# and optionally the entire project directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_monitor.sh"

echo "========================================"
echo "  RuleRadar — Cleanup / Uninstall"
echo "========================================"
echo ""

# ── 1. Remove cron job ────────────────────────────────────────────────────────
echo ">>> Removing cron job..."
EXISTING_CRON=$(crontab -l 2>/dev/null || true)

if echo "$EXISTING_CRON" | grep -q "$RUNNER"; then
    # Strip the TZ line immediately before the job and the job itself
    echo "$EXISTING_CRON" \
        | grep -v "TZ=America/New_York" \
        | grep -v "$RUNNER" \
        | crontab -
    echo "    Cron job removed."
else
    echo "    No cron job found — skipping."
fi

# ── 2. Remove virtual environment ─────────────────────────────────────────────
VENV="$SCRIPT_DIR/.venv"
echo ""
echo ">>> Removing virtual environment..."
if [[ -d "$VENV" ]]; then
    rm -rf "$VENV"
    echo "    .venv removed."
else
    echo "    No .venv found — skipping."
fi

# ── 3. Remove log file ────────────────────────────────────────────────────────
LOG="$SCRIPT_DIR/monitor_log.txt"
echo ""
echo ">>> Removing log file..."
if [[ -f "$LOG" ]]; then
    rm -f "$LOG"
    echo "    monitor_log.txt removed."
else
    echo "    No log file found — skipping."
fi

# ── 4. Optionally remove the project directory ────────────────────────────────
echo ""
echo ">>> Project directory: $SCRIPT_DIR"
read -r -p "    Delete the entire project directory (scripts, config, reports)? [y/N] " CONFIRM
echo ""

if [[ "${CONFIRM,,}" == "y" ]]; then
    # Move up one level before deleting so we're not inside the dir we remove
    PARENT="$(dirname "$SCRIPT_DIR")"
    DIRNAME="$(basename "$SCRIPT_DIR")"
    cd "$PARENT"
    rm -rf "$DIRNAME"
    echo "    Project directory deleted."
else
    echo "    Project directory kept. Your config.json and scripts are still in place."
fi

echo ""
echo "========================================"
echo "  Cleanup complete."
echo "========================================"

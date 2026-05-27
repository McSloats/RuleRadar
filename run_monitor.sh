#!/usr/bin/env bash
# Wrapper called by cron. Activates the venv if present, then runs RuleRadar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use a virtual environment if one exists alongside this script
VENV="$SCRIPT_DIR/.venv"
if [[ -f "$VENV/bin/python" ]]; then
    PYTHON="$VENV/bin/python"
else
    PYTHON="$(command -v python3)"
fi

"$PYTHON" "$SCRIPT_DIR/ruleradar.py" >> "$SCRIPT_DIR/monitor_log.txt" 2>&1

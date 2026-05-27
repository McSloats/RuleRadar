#!/usr/bin/env python3
"""
RuleRadar scheduler — runs ruleradar.py daily at 8:00 AM Eastern Time.
Designed to run as a long-lived Docker container alongside the web service.
Uses APScheduler so no system cron is needed inside the container.
"""

import subprocess
import sys
from pathlib import Path

import pytz
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

SCRIPT = Path(__file__).parent / "ruleradar.py"
ET     = pytz.timezone("America/New_York")


def run_ruleradar():
    print(">>> Starting RuleRadar run…", flush=True)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=False,
    )
    if result.returncode == 0:
        print(">>> RuleRadar completed successfully.", flush=True)
    else:
        print(f">>> RuleRadar exited with code {result.returncode}.", flush=True)


if __name__ == "__main__":
    scheduler = BlockingScheduler(timezone=ET)
    scheduler.add_job(
        run_ruleradar,
        CronTrigger(hour=8, minute=0, timezone=ET),
        id="ruleradar_daily",
        name="RuleRadar daily run",
    )

    print("RuleRadar scheduler started — will run daily at 08:00 ET.", flush=True)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("Scheduler stopped.", flush=True)

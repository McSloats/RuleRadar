#!/usr/bin/env python3
"""
RuleRadar scheduler — runs a scan every hour.
Imports run_scan() directly from ruleradar (no subprocess overhead).
Safe to run alongside the web service; threading.Lock in ruleradar
prevents overlapping scans if the webapp also triggers one.
"""

import sys
from pathlib import Path

# Allow importing from the project root
sys.path.insert(0, str(Path(__file__).parent))

import database as db
import ruleradar

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger


def run_job():
    print(">>> Scheduler: starting hourly RuleRadar scan…", flush=True)
    result = ruleradar.run_scan(triggered_by="scheduler")
    if result.get("skipped"):
        print(">>> Scheduler: scan skipped (already in progress).", flush=True)
    elif result.get("error"):
        print(f">>> Scheduler: scan error — {result['error']}", flush=True)
    else:
        print(
            f">>> Scheduler: done — new={result['new']}  modified={result['modified']}",
            flush=True,
        )


if __name__ == "__main__":
    db.init_db()

    scheduler = BlockingScheduler()
    scheduler.add_job(
        run_job,
        IntervalTrigger(hours=1),
        id="ruleradar_hourly",
        name="RuleRadar hourly scan",
    )

    print("RuleRadar scheduler started — scanning every hour.", flush=True)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("Scheduler stopped.", flush=True)

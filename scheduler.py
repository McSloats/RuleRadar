#!/usr/bin/env python3
"""
RuleRadar scheduler — fires a scan at every even UTC hour (00:00, 02:00, …, 22:00).

Design notes
------------
* Scans are NEVER triggered automatically from the web application — all
  automatic scanning is owned exclusively by this process.
* The first scan is triggered by an admin on the /setup-repos page when
  they enable one or more repositories (see setup_repos_submit in app.py).
  Repos are cloned with git — no GitHub token or API rate limits apply.
* The scheduler enforces a 90-minute staleness guard: if a scan completed
  less than 90 minutes ago (e.g. the initial clone+index just finished),
  the cron job silently skips its fire to avoid back-to-back scans.
* Imports run_scan() directly from ruleradar — no subprocess overhead.
* threading.Lock in ruleradar prevents overlapping scans if this process
  and the web process somehow fire simultaneously.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow importing from the project root
sys.path.insert(0, str(Path(__file__).parent))

import database as db
import ruleradar

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

# Minimum minutes between automated scans — prevents a double-scan when the
# cron fires shortly after the user's initial / manual scan.
_MIN_INTERVAL_MINUTES = 90


def run_job():
    """
    Scheduled scan job.

    Checks staleness before scanning to avoid running twice within 90 minutes.
    The initial scan is always triggered via the web UI, not here.
    """
    now = datetime.now(timezone.utc)

    # ── Staleness guard ──────────────────────────────────────────────────────
    status    = db.get_scan_status()
    last_scan = status.get("last_scan")
    if last_scan:
        last_dt     = datetime.fromisoformat(last_scan.replace("Z", "+00:00"))
        age_minutes = (now - last_dt).total_seconds() / 60
        if age_minutes < _MIN_INTERVAL_MINUTES:
            print(
                f">>> Scheduler: skipping {now.strftime('%H:%M')} UTC fire — "
                f"last scan was {age_minutes:.0f} min ago "
                f"(threshold {_MIN_INTERVAL_MINUTES} min).",
                flush=True,
            )
            return

    # ── Run scan ─────────────────────────────────────────────────────────────
    print(
        f">>> Scheduler: starting scan at {now.strftime('%Y-%m-%d %H:%M')} UTC…",
        flush=True,
    )
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

    # Fire at every even UTC hour: 00:00, 02:00, 04:00 … 22:00
    scheduler.add_job(
        run_job,
        CronTrigger(hour="*/2", minute=0, timezone="UTC"),
        id="ruleradar_bihourly",
        name="RuleRadar bi-hourly scan (even UTC hours)",
    )

    print(
        "RuleRadar scheduler started.\n"
        "  Fires at: 00:00, 02:00, 04:00, … 22:00 UTC\n"
        f"  Staleness guard: skips if last scan < {_MIN_INTERVAL_MINUTES} min ago.",
        flush=True,
    )
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("Scheduler stopped.", flush=True)

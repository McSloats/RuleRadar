#!/usr/bin/env python3
"""
RuleRadar launcher — starts the web interface and scheduler together.
Use this for a complete local setup without Docker.

Usage:
    python3 start.py            # start webapp + scheduler
    python3 start.py --run-now  # also run ruleradar.py immediately on startup
"""

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE   = Path(__file__).parent
PY     = sys.executable   # same interpreter that launched this script
WEBAPP = BASE / "webapp" / "app.py"
SCHED  = BASE / "scheduler.py"
RADAR  = BASE / "ruleradar.py"


def start(script: Path) -> subprocess.Popen:
    return subprocess.Popen([PY, str(script)])


def main():
    parser = argparse.ArgumentParser(description="RuleRadar launcher")
    parser.add_argument(
        "--run-now", action="store_true",
        help="Run ruleradar.py immediately before starting the scheduler",
    )
    opts = parser.parse_args()

    # ── Optional immediate run ─────────────────────────────────────────────────
    if opts.run_now:
        print(">>> Running ruleradar.py now…", flush=True)
        result = subprocess.run([PY, str(RADAR)])
        print(
            f">>> ruleradar.py finished (exit {result.returncode}).\n",
            flush=True,
        )

    # ── Start services ─────────────────────────────────────────────────────────
    procs = {
        "web":       start(WEBAPP),
        "scheduler": start(SCHED),
    }

    print("┌─────────────────────────────────────────┐", flush=True)
    print("│           RuleRadar is running          │", flush=True)
    print("├─────────────────────────────────────────┤", flush=True)
    print("│  Web        http://localhost:5000        │", flush=True)
    print("│  Scheduler  every 2 h, even UTC hours   │", flush=True)
    print("│  Press Ctrl+C to stop all services      │", flush=True)
    print("└─────────────────────────────────────────┘\n", flush=True)

    # ── Graceful shutdown on Ctrl+C / SIGTERM ──────────────────────────────────
    def shutdown(sig, frame):
        print("\n>>> Shutting down…", flush=True)
        for name, proc in procs.items():
            proc.terminate()
            print(f"    Stopped {name} (PID {proc.pid})", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Monitor and auto-restart crashed services ──────────────────────────────
    restart_map = {"web": WEBAPP, "scheduler": SCHED}
    while True:
        for name, proc in procs.items():
            if proc.poll() is not None:          # process has exited
                print(
                    f">>> {name} exited (code {proc.returncode}) — restarting…",
                    flush=True,
                )
                procs[name] = start(restart_map[name])
        time.sleep(5)


if __name__ == "__main__":
    main()

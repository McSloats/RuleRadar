#!/usr/bin/env python3
"""
RuleRadar launcher — starts the web interface and scheduler together.
Used by Docker (the image's default command) and for local setups.

The web interface runs under gunicorn, a production server (settings in
webapp/gunicorn.conf.py). On Windows, or if gunicorn isn't installed, it
falls back to Flask's development server, which is for local use only.

Usage:
    python3 start.py            # start webapp + scheduler
    python3 start.py --run-now  # also run ruleradar.py immediately on startup
"""

import argparse
import importlib.util
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE   = Path(__file__).parent
PY     = sys.executable   # same interpreter that launched this script
WEBAPP = BASE / "webapp" / "app.py"
GUNICORN_CONF = BASE / "webapp" / "gunicorn.conf.py"
SCHED  = BASE / "core" / "scheduler.py"
RADAR  = BASE / "core" / "ruleradar.py"


def _web_command() -> list[str]:
    if sys.platform != "win32" and importlib.util.find_spec("gunicorn"):
        return [PY, "-m", "gunicorn", "-c", str(GUNICORN_CONF)]
    print(">>> gunicorn unavailable — using Flask's development server "
          "(local use only, not for production)", flush=True)
    return [PY, str(WEBAPP)]


def start(script: Path) -> subprocess.Popen:
    cmd = _web_command() if script == WEBAPP else [PY, str(script)]
    return subprocess.Popen(cmd)


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
        for proc in procs.values():
            proc.terminate()
        # Wait for both to finish (gunicorn lets in-flight requests complete,
        # up to graceful_timeout) — in Docker the container ends when this exits
        for name, proc in procs.items():
            try:
                proc.wait(timeout=35)
            except subprocess.TimeoutExpired:
                proc.kill()
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

# ── RuleRadar ──────────────────────────────────────────────────────────────────
# Single image that runs the web interface and the bi-hourly scheduler
# together: the default command (start.py) launches both as sub-processes.

FROM python:3.14-slim

# Install curl (health-check) and git (repository scanning)
RUN apt-get update && apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached unless
# requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Create the data directory where the SQLite DB and secret key are stored.
# The docker-compose volume is mounted here so the DB and clones persist.
RUN mkdir -p /app/data

# Run as an unprivileged user rather than root (default container user
# otherwise). UID/GID 568 matches TrueNAS SCALE's "apps" user, which the
# TrueNAS deployment docs already require the host dataset to be owned by
# -- so this doesn't introduce a new permission mismatch there, and for
# plain `docker compose`/`docker run` the named volume is initialized with
# this ownership automatically, no host-side chown needed.
RUN groupadd -g 568 ruleradar && useradd -u 568 -g 568 -M -d /app ruleradar \
    && chown -R ruleradar:ruleradar /app
USER ruleradar

# Web service listens on 5000
EXPOSE 5000

# Default: run the web interface (gunicorn) + bi-hourly scheduler together
CMD ["python3", "start.py"]

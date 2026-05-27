# ── RuleRadar ──────────────────────────────────────────────────────────────────
# Single image used by both the web service and the scheduler service.
# Default command starts the web interface; docker-compose overrides it
# for the scheduler container.

FROM python:3.12-slim

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
# The docker-compose volume is mounted here, so both containers share the DB.
RUN mkdir -p /app/data

# Web service listens on 5000
EXPOSE 5000

# Default: run the web interface
CMD ["python3", "webapp/app.py"]

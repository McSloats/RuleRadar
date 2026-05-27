# ── RuleRadar ──────────────────────────────────────────────────────────────────
# Single image used by both the web service and the scheduler service.
# Default command starts the web interface; docker-compose overrides it
# for the scheduler container.

FROM python:3.12-slim

# Install curl for the web service health-check
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached unless
# requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Web service listens on 5000
EXPOSE 5000

# Default: run the web interface
CMD ["python3", "webapp/app.py"]

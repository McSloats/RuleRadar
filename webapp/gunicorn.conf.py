"""
Gunicorn settings for the RuleRadar web interface (production server).
start.py runs:  python -m gunicorn -c webapp/gunicorn.conf.py

One worker process with a pool of threads, on purpose:
  * The API rate limits and login limiter are kept in process memory.
    Several worker processes would each keep their own counts, multiplying
    the effective limits.
  * The initial repo-setup scan runs in a background thread of the web
    process; recycling workers (max_requests) would kill it mid-scan.
Threads handle the concurrency instead, which is plenty for this app:
requests are short SQLite reads.
"""

from pathlib import Path

# Import webapp/app.py as module "app" (it puts the project root on sys.path itself)
pythonpath = str(Path(__file__).parent)
wsgi_app   = "app:app"

bind = "0.0.0.0:5000"

# Gunicorn 26's runtime control socket isn't used, and its default path
# (/run/user/<uid>) doesn't exist inside the Docker image
control_socket_disable = True

worker_class = "gthread"
workers      = 1
threads      = 8

# Unlike the development server, slow or stuck clients can't hold resources
# forever: idle keep-alive connections close after 5 s, and a worker that
# stops responding is replaced. 120 s covers the slowest request,
# /api/repo-sizes (up to six GitHub calls with a 10 s timeout each).
timeout          = 120
graceful_timeout = 30
keepalive        = 5

# Request-size limits (gunicorn's defaults, stated explicitly)
limit_request_line         = 8190
limit_request_fields       = 100
limit_request_field_size   = 8190

# Access log in the same place the development server printed it (stdout,
# so `docker compose logs` shows it); errors to stderr
accesslog = "-"
errorlog  = "-"
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(M)sms'

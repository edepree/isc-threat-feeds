#!/bin/sh
set -e

echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Starting Gunicorn..."

exec gunicorn ics_threat_feeds:app \
    --bind 0.0.0.0:8080 \
    --workers $(( $(nproc)*2 + 1 )) \
    --log-level "${GUNICORN_LOGGING:-info}"

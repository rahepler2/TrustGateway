#!/usr/bin/env bash
set -e

echo "[entrypoint] Waiting for Nexus..."
until curl -sf http://nexus:8081/service/rest/v1/status >/dev/null 2>&1; do
    sleep 3
done
echo "[entrypoint] Nexus is up"

echo "[entrypoint] Waiting for Trivy server..."
until curl -sf http://trivy-server:8080/healthz >/dev/null 2>&1; do
    sleep 2
done
echo "[entrypoint] Trivy is up"

PORT="${FLASK_PORT:-5000}"
# Single process with multiple threads — keeps shared state (JOBS, thread pool)
# in one process while handling concurrent HTTP requests.
THREADS="${GUNICORN_THREADS:-8}"

echo "[entrypoint] Starting Trust Gateway (gunicorn, ${THREADS} threads, port ${PORT})..."
exec gunicorn \
    "gateway.app:create_app()" \
    --bind "0.0.0.0:${PORT}" \
    --workers 1 \
    --threads "${THREADS}" \
    --timeout 300 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile -

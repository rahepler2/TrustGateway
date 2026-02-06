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

echo "[entrypoint] Starting Trust Gateway..."
exec python -m gateway.app serve --port "${FLASK_PORT:-5000}"

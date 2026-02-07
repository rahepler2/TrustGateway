#!/usr/bin/env bash
# nexus-request — Bash wrapper for the Trust Gateway CLI
#
# Usage:
#   nexus-request scan python requests
#   nexus-request scan python requests 2.32.3
#   nexus-request scan docker nginx:1.25
#   nexus-request scan python -f requirements.txt
#   nexus-request rescan python
#   nexus-request rescan --all
#   nexus-request status <job_id>
#
# Environment:
#   TRUST_GATEWAY_URL  default: http://localhost:5002
#   TRUST_GATEWAY_KEY  optional API key (sent as X-API-Key header)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If Python + requests are available, delegate to the Python CLI
if command -v python3 &>/dev/null; then
    exec python3 "$SCRIPT_DIR/nexus-request.py" "$@"
fi

echo "[ERROR] Python 3 is required. Install Python 3 and the 'requests' library."
exit 2

#!/usr/bin/env bash
# nexus-request — Bash wrapper for the Trust Gateway CLI
#
# Usage:
#   ./nexus-request.sh submit -p "flask==3.0.0" -e pypi -w 120
#   ./nexus-request.sh submit-batch -r requirements.txt -w 600
#   ./nexus-request.sh status --job <job_id>
#
# Environment:
#   TRUST_GATEWAY_URL  default: http://localhost:5000
#   TRUST_GATEWAY_KEY  optional Bearer token

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If Python + requests are available, delegate to the Python CLI
if command -v python3 &>/dev/null; then
    exec python3 "$SCRIPT_DIR/nexus-request.py" "$@"
fi

echo "[ERROR] Python 3 is required. Install Python 3 and the 'requests' library."
exit 2

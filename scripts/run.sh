#!/usr/bin/env bash
# WiFiAIO Run Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Check for virtual environment
if [[ -d "${PROJECT_DIR}/venv" ]]; then
    source "${PROJECT_DIR}/venv/bin/activate"
elif [[ -d "${PROJECT_DIR}/.venv" ]]; then
    source "${PROJECT_DIR}/.venv/bin/activate"
elif [[ -d "/opt/wifiaio/venv" ]]; then
    source "/opt/wifiaio/venv/bin/activate"
fi

cd "${PROJECT_DIR}"

# Add project to Python path
export PYTHONPATH="${PROJECT_DIR}:${PYTHONPATH:-}"

# Check for root (needed for most WiFi operations)
if [[ $EUID -ne 0 ]]; then
    echo "[WARN] Not running as root. Some operations require sudo."
    echo "       Run: sudo $0"
    echo ""
fi

# Run WiFiAIO
exec python3 -m wifi_aio "$@"

#!/usr/bin/env bash
# Start the VulnBox local Web UI on Linux and macOS (100% repo-local setup).
# Usage: ./start-ui.sh [--port 8787] [--host 127.0.0.1] [--no-browser] [--install]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$SCRIPT_DIR/scripts/start_ui.py"

export UV_PROJECT_ENVIRONMENT="$SCRIPT_DIR/.venv"
export UV_CACHE_DIR="$SCRIPT_DIR/.vulnbox-cache/uv"
export UV_PYTHON_INSTALL_DIR="$SCRIPT_DIR/.vulnbox-cache/python"
export PIP_CACHE_DIR="$SCRIPT_DIR/.vulnbox-cache/pip"
export PIP_USER=0
export PYTHONNOUSERSITE=1

if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  exec "$SCRIPT_DIR/.venv/bin/python" "$LAUNCHER" "$@"
elif command -v python3 >/dev/null 2>&1; then
  exec python3 "$LAUNCHER" "$@"
elif command -v python >/dev/null 2>&1; then
  exec python "$LAUNCHER" "$@"
elif command -v uv >/dev/null 2>&1; then
  exec uv run --project "$SCRIPT_DIR" python "$LAUNCHER" "$@"
else
  echo "[vulnbox] Error: Python 3.11+ or uv is required to start the VulnBox Web UI." >&2
  exit 1
fi

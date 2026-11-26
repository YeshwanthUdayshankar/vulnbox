#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
DEFAULT_PROJECT="$(cd "$(dirname "${SCRIPT_PATH}")/../../.." && pwd)"
VULNBOX_PROJECT="${VULNBOX_PROJECT:-${DEFAULT_PROJECT}}"

if [[ -x "${VULNBOX_PROJECT}/.venv/bin/vulnbox" ]]; then
  exec "${VULNBOX_PROJECT}/.venv/bin/vulnbox" "$@"
fi
exec uv run --project "${VULNBOX_PROJECT}" vulnbox "$@"

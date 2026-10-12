#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${PAYINTLAB_REDTEAM_REPO:-https://github.com/PayIntLab/payintlab-redteam}"

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "git+${REPO_URL}.git"
elif command -v uv >/dev/null 2>&1; then
  uv tool install --force "git+${REPO_URL}.git"
else
  python3 -m pip install --user --upgrade "git+${REPO_URL}.git"
fi

echo "Installed payintlab-redteam. Run: payintlab-redteam --help"

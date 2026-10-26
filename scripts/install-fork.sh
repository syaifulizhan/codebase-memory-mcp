#!/usr/bin/env bash
set -euo pipefail

# Install or update the hardened fork from its latest GitHub release.
# Re-run the same command whenever a new fork release is published.
REPO="syaifulizhan/codebase-memory-mcp"
BRANCH="hoki-fork"
INSTALLER="https://raw.githubusercontent.com/${REPO}/${BRANCH}/install.sh"
RELEASES="https://github.com/${REPO}/releases/latest/download"

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required to install the hardened fork" >&2
    exit 1
fi

curl -fsSL --proto '=https' --proto-redir '=https' "$INSTALLER" |
    CBM_DOWNLOAD_URL="$RELEASES" bash -s -- "$@"

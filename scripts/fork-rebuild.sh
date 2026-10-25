#!/usr/bin/env bash
# Fork maintenance: pull upstream, merge our patches, rebuild, test, install.
# Usage: scripts/fork-rebuild.sh            (merge upstream/main (no history rewrite), then build)
#        scripts/fork-rebuild.sh --no-pull  (rebuild current tree only)
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" != "--no-pull" ]; then
    git fetch upstream
    git merge --no-edit upstream/main
fi

jobs=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
make -f Makefile.cbm -j"$jobs" cbm
make -f Makefile.cbm -j"$jobs" test-focused TEST_SUITES="discover secret_redact"

dest="$HOME/.local/bin/codebase-memory-mcp"
install -m 755 build/c/codebase-memory-mcp "$dest"
"$dest" --version
echo "installed: $dest (restart MCP clients to pick it up)"

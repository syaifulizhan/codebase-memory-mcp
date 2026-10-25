#!/usr/bin/env bash
# Fork maintenance: pull upstream, replay our patches, rebuild, test, install.
# Usage: scripts/fork-rebuild.sh            (rebase onto upstream/main, then build)
#        scripts/fork-rebuild.sh --no-pull  (rebuild current tree only)
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" != "--no-pull" ]; then
    git fetch upstream
    git rebase upstream/main
fi

jobs=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
make -f Makefile.cbm -j"$jobs" cbm
make -f Makefile.cbm -j"$jobs" test-focused TEST_SUITES=discover

dest="$HOME/.local/bin/codebase-memory-mcp"
install -m 755 build/c/codebase-memory-mcp "$dest"
"$dest" --version
echo "installed: $dest (Claude + Codex pick it up on next session)"

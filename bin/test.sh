#!/usr/bin/env bash
# `mise exec --` resolves uv via mise.toml's pinned version rather than a
# bare `uv` on PATH -- `uv` is only a broken interactive-shell alias
# (`uv='sfw uv'`) on this machine, invisible to a non-interactive run of
# this script anyway. Same convention already used by this repo's other
# bin/*.sh scripts for gitleaks (mise exec -- gitleaks).
set -euo pipefail
cd "$(dirname "$0")/.."
mise exec -- uv run pytest tests/ -v

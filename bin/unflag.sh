#!/usr/bin/env bash
# just unflag <content_hash> -- record an allow decision in the ledger,
# overriding a prior flag (last-entry-wins, plan §6).
set -euo pipefail
cd "$(dirname "$0")/.."
HASH="${1:?usage: unflag.sh <content_hash>}"
export UNFLAG_HASH="$HASH"
mise exec -- uv run python3 -c "
import os
from sanitize.ledger import unflag, DEFAULT_LEDGER_PATH
e = unflag(DEFAULT_LEDGER_PATH, os.environ['UNFLAG_HASH'])
print(f'unflagged {e.content_hash} at {e.at} ({DEFAULT_LEDGER_PATH})')
"

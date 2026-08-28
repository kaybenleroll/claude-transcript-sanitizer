#!/usr/bin/env bash
# just flag <content_hash> "<reason>" -- record a deny decision in the ledger.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
HASH="${1:?usage: flag.sh <content_hash> <reason>}"
REASON="${2:?usage: flag.sh <content_hash> <reason>}"
export FLAG_HASH="$HASH" FLAG_REASON="$REASON"

# shellcheck source=lib/lock.sh
source "$REPO_ROOT/bin/lib/lock.sh"

if ! lock_acquire_or_reentrant "flag"; then
  echo "flag.sh: could not acquire the sanitizer lock (result=$LOCK_RESULT) -- refusing to mutate the ledger" >&2
  exit 1
fi

mise exec -- uv run python3 -c "
import os
from sanitize.ledger import flag, DEFAULT_LEDGER_PATH
e = flag(DEFAULT_LEDGER_PATH, os.environ['FLAG_HASH'], os.environ['FLAG_REASON'])
print(f'flagged {e.content_hash} at {e.at} ({DEFAULT_LEDGER_PATH})')
"

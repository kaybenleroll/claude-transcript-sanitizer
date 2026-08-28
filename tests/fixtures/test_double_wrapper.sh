#!/usr/bin/env bash
# tests/fixtures/test_double_wrapper.sh — throwaway test-double wrapper for
# Phase A reentrancy tests ONLY (issue #48). Not production wrapper.sh —
# real backfill/wrapper batching stays deferred per the plan's scope
# decision. Acquires the sanitizer lock as role=wrapper, records its own
# run_id/pid to an info file so the test can assert on it, then execs the
# given command (typically one or more `git commit`s) while holding the
# lock. Lock release/outcome-record writing happen automatically via
# bin/lib/lock.sh's own installed EXIT trap.
set -euo pipefail

LOCK_SH="$1"; shift
INFO_FILE="$1"; shift

# shellcheck source=/dev/null
source "$LOCK_SH"

if ! lock_acquire_or_reentrant "wrapper"; then
  echo "test_double_wrapper: could not acquire lock (result=$LOCK_RESULT)" >&2
  exit 1
fi

printf '%s %s\n' "$LOCK_RUN_ID" "$$" > "$INFO_FILE"

export SANITIZER_RUN_ID="$LOCK_RUN_ID"

"$@"

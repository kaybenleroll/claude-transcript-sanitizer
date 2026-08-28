#!/usr/bin/env bash
# Plan §Verification step 2: dry-run report of files/lines a redaction pass
# would change, without writing anything. Sanity check: the known-credential
# files (re-derived from the gitleaks baseline, not hardcoded) should appear.
set -euo pipefail
cd "$(dirname "$0")/.."
mise exec -- uv run python3 -m sanitize.mirror check

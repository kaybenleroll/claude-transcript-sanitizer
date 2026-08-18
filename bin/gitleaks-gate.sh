#!/usr/bin/env bash
# Plan §5: the acceptance gate. Parameterized target dir so it can run
# against the sanitized mirror now, or the sync repo tree in a later phase.
# Fail-closed on exit 1. --redact is mandatory (bare form, no findings printed).
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$(cd ../.. && pwd)"
TARGET="${1:?usage: gitleaks-gate.sh <target-dir> [run-id]}"
RUN_ID="${2:-$(date -u +%Y%m%dT%H%M%SZ)}"
STATE_DIR="${SANITIZER_STATE_DIR:-$HOME/.local/state/claude-transcript-sanitizer}"
REPORT="$STATE_DIR/runs/${RUN_ID}.gitleaks.json"

mkdir -p "$(dirname "$REPORT")"

set +e
mise exec -- gitleaks dir "$TARGET" --redact --no-banner \
  --report-format json --report-path "$REPORT" --exit-code 1
STATUS=$?
set -e

echo "report: $REPORT"
echo "exit: $STATUS"
if [ "$STATUS" -ne 0 ]; then
  echo "FAIL: findings present. Breakdown:"
  uv run python3 -c "
import json
from collections import Counter
try:
    findings = json.load(open('$REPORT'))
except Exception:
    findings = []
by_rule = Counter(f['RuleID'] for f in findings)
for rule, n in sorted(by_rule.items(), key=lambda x: -x[1]):
    print(f'  {rule}: {n}')
print(f'  TOTAL: {len(findings)}')
"
fi

exit "$STATUS"

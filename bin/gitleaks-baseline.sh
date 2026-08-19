#!/usr/bin/env bash
# Plan §2 step 0 / §Verification: gitleaks over the RAW corpus, measurement
# only (--exit-code 0). Report finding count/rule breakdown to confirm or
# update the plan's 2026-08-18 baseline numbers -- the corpus drifts, so this
# is re-measured every run, never assumed.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$(pwd)"
TARGET="${1:-$HOME/.claude/projects}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$REPO_ROOT/.scratch/gitleaks-baseline-raw-${TIMESTAMP}.json"
LATEST_LINK="$REPO_ROOT/.scratch/gitleaks-baseline-raw-latest.json"

mkdir -p "$(dirname "$REPORT")"

mise exec -- gitleaks dir "$TARGET" --redact --no-banner \
  --config .gitleaks.toml \
  --report-format json --report-path "$REPORT" --exit-code 0

ln -sf "$(basename "$REPORT")" "$LATEST_LINK"

echo "report: $REPORT"
echo "latest symlink: $LATEST_LINK"
echo "total findings: $(uv run python3 -c "import json; print(len(json.load(open('$REPORT'))))")"
echo "by rule:"
uv run python3 -c "
import json
from collections import Counter
findings = json.load(open('$REPORT'))
by_rule = Counter(f['RuleID'] for f in findings)
for rule, n in sorted(by_rule.items(), key=lambda x: -x[1]):
    print(f'  {rule}: {n}')
"
echo "by extension:"
uv run python3 -c "
import json
from collections import Counter
findings = json.load(open('$REPORT'))
by_ext = Counter(f['File'].rsplit('.', 1)[-1] if '.' in f['File'] else '(none)' for f in findings)
for ext, n in sorted(by_ext.items(), key=lambda x: -x[1]):
    print(f'  .{ext}: {n}')
"
echo "jsonl files with findings:"
uv run python3 -c "
import json
findings = json.load(open('$REPORT'))
files = sorted({f['File'] for f in findings if f['File'].endswith('.jsonl')})
print(f'  {len(files)} files, {sum(1 for f in findings if f[\"File\"].endswith(\".jsonl\"))} findings')
"

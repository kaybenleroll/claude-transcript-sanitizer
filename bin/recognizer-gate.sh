#!/usr/bin/env bash
# Plan §P0.4 primary compensating control: run OUR OWN fixed credential
# recognizer patterns (sanitize/recognizers.py CREDENTIAL_PREFIX_PATTERNS --
# the same source classify.py's find_credential_relpaths uses, per P0.2's
# de-duplication) detect-only over a target directory, asserting zero
# findings. Not a modification of the recognizers, not a redaction pass.
#
# This is NOT independent verification of the regex fix itself -- gitleaks
# + .gitleaks.toml (gitleaks-gate.sh) is the independent check. This gate
# catches the likelier failure mode: a mirror built with a stale/pre-fix
# recognizer set, or a file silently skipped during redaction.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:?usage: recognizer-gate.sh <target-dir>}"

set +e
HITS="$(mise exec -- uv run python3 -c "
from pathlib import Path
import re
from sanitize.recognizers import CREDENTIAL_PREFIX_PATTERNS

CREDENTIAL_PREFIX_RE = re.compile('|'.join(f'(?:{p})' for p in CREDENTIAL_PREFIX_PATTERNS))

target = Path('$TARGET')
hits = []
for pattern in ('*.jsonl', '*.txt'):
    for p in sorted(target.rglob(pattern)):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if CREDENTIAL_PREFIX_RE.search(text):
            hits.append(str(p.relative_to(target)))

print(chr(10).join(hits))
")"
PY_STATUS=$?
set -e

if [ "$PY_STATUS" -ne 0 ]; then
  echo "ERROR: recognizer scan failed to run" >&2
  exit 2
fi

if [ -n "$HITS" ]; then
  echo "FAIL: recognizer-gate found credential-shaped matches in $TARGET:"
  echo "$HITS"
  COUNT="$(echo "$HITS" | grep -c '.')"
  echo "TOTAL: $COUNT"
  exit 1
fi

echo "PASS: 0 recognizer findings in $TARGET"
exit 0

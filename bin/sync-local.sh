#!/usr/bin/env bash
# Plan §8: local-only claude-code-sync dry run against the sanitized mirror.
# Never touches ~/.claude/ (source) or ~/.claude-code-sync-repo (the real
# sync repo/remote). Commits into a throwaway repo under .scratch/ only.
#
# Sequencing (see plan's Implementation Notes, gotcha #3): `claude-code-sync
# push` runs auto-onboarding (init-from-config) and the push itself in one
# process, with no chance to patch config.toml in between -- so init and
# push must be two separate invocations:
#   1. `claude-code-sync init --config <init.toml>` -- non-interactive,
#      writes state.json + config.toml (default max_file_size_bytes).
#   2. Patch max_file_size_bytes into the just-written config.toml.
#   3. `claude-code-sync push` -- already initialized, skips onboarding,
#      uses the patched config.toml as-is.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$(cd ../.. && pwd)"
MIRROR="${MIRROR_DEST:-$REPO_ROOT/.scratch/sanitized-mirror/projects}"
# claude-code-sync's CLAUDE_CODE_SYNC_CLAUDE_DIR is the ~/.claude equivalent
# (it appends "projects" itself, see discovery.rs claude_projects_dir()) --
# so the override must be MIRROR's *parent*, not MIRROR itself.
CLAUDE_DIR_OVERRIDE="$(dirname "$MIRROR")"
THROWAWAY_REPO="${SYNC_THROWAWAY_REPO:-$REPO_ROOT/.scratch/ccs-throwaway-repo}"
CCS_CONFIG_DIR="${SYNC_CCS_CONFIG_DIR:-$REPO_ROOT/.scratch/ccs-config}"
INIT_TOML="$CCS_CONFIG_DIR/init.toml"
CONFIG_TOML="$CCS_CONFIG_DIR/claude-code-sync/config.toml"
# Default 10MB (tool default) would exclude nothing today (corpus max
# observed 9.36MB) but the corpus drifts -- bump generously so the guard's
# size-exclusion term stays 0 in the common case, and is still measured
# dynamically (never assumed) below.
MAX_FILE_SIZE_BYTES="${SYNC_MAX_FILE_SIZE_BYTES:-104857600}"
STATE_DIR="${SANITIZER_STATE_DIR:-$HOME/.local/state/claude-transcript-sanitizer}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
GITLEAKS_REPORT="$STATE_DIR/runs/${RUN_ID}.gitleaks-committed.json"
PUSH_LOG="$REPO_ROOT/.scratch/sync-local-push-${RUN_ID}.log"

# --- Safety: never touch the real sync repo/config, everything stays under .scratch/. ---
case "$THROWAWAY_REPO" in
  "$REPO_ROOT"/.scratch/*) ;;
  *) echo "ERROR: THROWAWAY_REPO ($THROWAWAY_REPO) must live under $REPO_ROOT/.scratch/" >&2; exit 1 ;;
esac
if [ "$THROWAWAY_REPO" = "$HOME/.claude-code-sync-repo" ] || [ "$CCS_CONFIG_DIR" = "$HOME/.claude-code-sync-repo" ]; then
  echo "ERROR: refusing to touch the real ~/.claude-code-sync-repo" >&2
  exit 1
fi

if [ ! -d "$MIRROR" ]; then
  echo "ERROR: mirror not found at $MIRROR -- run 'just build-mirror' first." >&2
  exit 1
fi

MIRROR_JSONL_COUNT="$(find "$MIRROR" -name '*.jsonl' -type f | wc -l | tr -d ' ')"
if [ "$MIRROR_JSONL_COUNT" -eq 0 ]; then
  echo "ERROR: mirror at $MIRROR has 0 .jsonl files." >&2
  exit 1
fi
echo "mirror: $MIRROR_JSONL_COUNT .jsonl files"

MIRROR_OVERSIZE_COUNT="$(find "$MIRROR" -name '*.jsonl' -type f -size +"${MAX_FILE_SIZE_BYTES}"c | wc -l | tr -d ' ')"
EXPECTED_SESSIONS=$((MIRROR_JSONL_COUNT - MIRROR_OVERSIZE_COUNT))
echo "mirror files >= ${MAX_FILE_SIZE_BYTES} bytes: $MIRROR_OVERSIZE_COUNT"
echo "expected discovered sessions (pre-push estimate, before warn-drops known): $EXPECTED_SESSIONS"

# --- Pre-flight: re-run the mirror hygiene gate (suffix whitelist + .tmp
# sweep -- same logic as sanitize/mirror.py's build-side gate) against
# $MIRROR, regardless of whether `just build-mirror` ran cleanly in this
# invocation. Prune (mechanism 2, keyed on a run's processed-set) is
# build-side only -- sync-local.sh has no processed-set of its own, so this
# duplicate only covers mechanisms 1 and 3. (plan §9, commit step 7) ---
echo "pre-flight: mirror hygiene gate (suffix whitelist + .tmp sweep) against $MIRROR..."
find "$MIRROR" -type f -name '*.tmp' -print -delete
HYGIENE_FOREIGN="$(find "$MIRROR" -type f ! -name '*.jsonl' ! -name '*.txt')"
if [ -n "$HYGIENE_FOREIGN" ]; then
  echo "ERROR: foreign file(s) found in mirror (not .jsonl/.txt) after .tmp sweep:" >&2
  echo "$HYGIENE_FOREIGN" >&2
  exit 1
fi
echo "pre-flight: hygiene OK (no foreign-suffix files, no stray .tmp residue)"

# --- Fresh throwaway state each run (dry run semantics: clean slate). ---
rm -rf "$THROWAWAY_REPO" "$CCS_CONFIG_DIR"
mkdir -p "$CCS_CONFIG_DIR"

cat > "$INIT_TOML" <<EOF
repo_path = "$THROWAWAY_REPO"
exclude_attachments = false
use_project_name_only = false
sync_subdirectory = "projects"
EOF

echo "validating init.toml parses..."
uv run python3 -c "
import tomllib
with open('$INIT_TOML', 'rb') as f:
    cfg = tomllib.load(f)
assert cfg.get('repo_path'), 'repo_path missing'
assert 'remote_url' not in cfg, 'remote_url must not be set (local-only dry run)'
print('  OK:', cfg)
"

echo "step 1/3: claude-code-sync init (non-interactive, --config)..."
timeout 60 env \
  CLAUDE_CODE_SYNC_CONFIG_DIR="$CCS_CONFIG_DIR" \
  CLAUDE_CODE_SYNC_INIT_CONFIG="$INIT_TOML" \
  claude-code-sync init --config "$INIT_TOML"

if [ ! -f "$CONFIG_TOML" ]; then
  echo "ERROR: expected config.toml at $CONFIG_TOML after init, not found." >&2
  exit 1
fi

# --- .gitignore defense-in-depth (plan §9, commit step 7).
#
# DEVIATION FROM THE PLAN'S STATED MECHANISM, discovered empirically against
# the real claude-code-sync 0.3.3 source (src/artifacts/engine.rs,
# src/sync/push.rs): the plan assumed `.gitignore` exists after `init`, to be
# edited "after init, before push". In fact `claude-code-sync init` never
# touches `.gitignore` at all -- it's `push` that writes it, via
# ensure_ignore_files(), called *and* followed by `repo.commit(...)` inside
# one atomic `push` invocation (push.rs:261 write, :361 commit; no CLI hook
# point exists between them, and init+push were already split into two
# invocations per this script's header comment, so there is no third
# invocation to insert here). Editing the file "after init, before push" as
# a literal third step is therefore impossible with this tool version.
#
# ensure_ignore_files() *is* explicitly marker-aware and content-preserving
# (engine.rs: "Idempotent; preserves user content outside the block"): if
# the file already has non-empty content without the marker pair, it appends
# its own managed block *after* that content, unchanged. So instead of
# editing the file after push writes it (too late -- already committed by
# then), pre-create it right after init (once $THROWAWAY_REPO/.git exists)
# with our line as the file's entire pre-existing content; push's own
# ensure_ignore_files() call then appends its managed block below it,
# leaving our line outside (above) the block, exactly satisfying "outside
# the tool's managed block" -- verified against the real markers below
# (real generated block: "# >>> claude-code-sync managed block — do not
# edit inside" / "# <<< claude-code-sync managed block", confirmed from a
# prior real run's committed .gitignore). ---
if [ ! -d "$THROWAWAY_REPO/.git" ]; then
  echo "ERROR: expected $THROWAWAY_REPO/.git to exist after init, not found." >&2
  exit 1
fi
echo '*.tmp' > "$THROWAWAY_REPO/.gitignore"
echo "pre-seeded $THROWAWAY_REPO/.gitignore with '*.tmp' before push (push's ensure_ignore_files() appends its managed block after this line, preserving it outside the block)"

echo "step 2/3: patching max_file_size_bytes=$MAX_FILE_SIZE_BYTES into $CONFIG_TOML..."
uv run python3 -c "
import re
path = '$CONFIG_TOML'
with open(path) as f:
    content = f.read()
pattern = re.compile(r'^max_file_size_bytes\s*=\s*\d+\$', re.MULTILINE)
replacement = 'max_file_size_bytes = $MAX_FILE_SIZE_BYTES'
if pattern.search(content):
    content = pattern.sub(replacement, content)
else:
    content = content.rstrip('\n') + '\n' + replacement + '\n'
with open(path, 'w') as f:
    f.write(content)
"
grep -n "^max_file_size_bytes" "$CONFIG_TOML"

echo "step 3/3: claude-code-sync push (local only)..."
# NOTE: v0.3.3's `--push-remote` is a plain SetTrue flag (default true,
# takes no value) despite `push --help` implying it's a value-taking bool
# -- `--push-remote=false` errors ("unexpected value 'false'"). There is no
# CLI way to force it off. Local-only safety instead comes from
# `push_remote && state.has_remote` in src/sync/push.rs -- `has_remote` is
# only ever set from a `remote_url` (see src/sync/init.rs), which our
# init.toml never sets. So omitting `--push-remote` (and never setting
# remote_url) is the correct, and only, local-only invocation.
set +e
timeout 900 env \
  CLAUDE_CODE_SYNC_CLAUDE_DIR="$CLAUDE_DIR_OVERRIDE" \
  CLAUDE_CODE_SYNC_CONFIG_DIR="$CCS_CONFIG_DIR" \
  CLAUDE_CODE_SYNC_INIT_CONFIG="$INIT_TOML" \
  claude-code-sync push --message "transcript-sanitizer §8 local dry run ${RUN_ID}" \
  2>&1 | tee "$PUSH_LOG"
PUSH_STATUS="${PIPESTATUS[0]}"
set -e

echo "push log: $PUSH_LOG"
echo "push exit: $PUSH_STATUS"
if [ "$PUSH_STATUS" -eq 124 ]; then
  echo "FAIL: push timed out (900s) -- likely hung on an interactive onboarding prompt." >&2
  echo "  Check CLAUDE_CODE_SYNC_CONFIG_DIR/init.toml sequencing above." >&2
  exit 1
fi
if [ "$PUSH_STATUS" -ne 0 ]; then
  echo "FAIL: claude-code-sync push exited $PUSH_STATUS" >&2
  exit 1
fi

DISCOVERED_SESSIONS="$(grep -oE 'Found [0-9]+ sessions' "$PUSH_LOG" | grep -oE '[0-9]+' | head -1 || true)"
if [ -z "$DISCOVERED_SESSIONS" ]; then
  echo "FAIL: could not parse discovered session count from push output." >&2
  exit 1
fi
echo "discovered sessions (tool-reported): $DISCOVERED_SESSIONS"

# discover_sessions (discovery.rs) also silently drops any file whose
# ConversationSession::from_file errors, logging only a log::warn (plan
# gotcha #6). That drop is a legitimate, dynamically-measured third term in
# the guard -- never assume it's 0, but never hardcode its count either.
WARN_PARSE_DROP_COUNT="$(grep -c 'Failed to parse' "$PUSH_LOG" || true)"
WARN_COUNT="$(grep -ci 'WARN' "$PUSH_LOG" || true)"
if [ "$WARN_COUNT" -gt 0 ]; then
  echo "NOTE: $WARN_COUNT WARN line(s) in push log ($WARN_PARSE_DROP_COUNT parse-drop(s)) -- inspecting before trusting the session count:"
  grep -i 'WARN' "$PUSH_LOG" || true
fi

EXPECTED_SESSIONS=$((EXPECTED_SESSIONS - WARN_PARSE_DROP_COUNT))
echo "expected discovered sessions (mirror - oversize - warn-parse-drops): $EXPECTED_SESSIONS"

# --- Acceptance check 1: session-count guard (dynamic, plan gotcha #5/#6). ---
if [ "$DISCOVERED_SESSIONS" -eq "$EXPECTED_SESSIONS" ]; then
  echo "PASS: session-count guard ($DISCOVERED_SESSIONS == $MIRROR_JSONL_COUNT mirror - $MIRROR_OVERSIZE_COUNT oversize - $WARN_PARSE_DROP_COUNT warn-parse-drops)"
  GUARD_STATUS=0
else
  echo "FAIL: session-count guard -- discovered $DISCOVERED_SESSIONS, expected $EXPECTED_SESSIONS (mirror $MIRROR_JSONL_COUNT - oversize $MIRROR_OVERSIZE_COUNT - warn-drops $WARN_PARSE_DROP_COUNT)" >&2
  GUARD_STATUS=1
fi

# --- Acceptance check 2: committed file count vs actually-staged files (plan gotcha #8). ---
if [ ! -d "$THROWAWAY_REPO/.git" ]; then
  echo "FAIL: no git repo at $THROWAWAY_REPO after push." >&2
  exit 1
fi
COMMITTED_FILE_COUNT="$(git -C "$THROWAWAY_REPO" ls-tree -r --name-only HEAD | wc -l | tr -d ' ')"
COMMITTED_JSONL_COUNT="$(git -C "$THROWAWAY_REPO" ls-tree -r --name-only HEAD | grep -cE '\.jsonl$' || true)"
echo "committed file count (git ls-tree -r --name-only, HEAD, all files incl. tool-written .gitignore): $COMMITTED_FILE_COUNT"
echo "committed .jsonl file count (git ls-tree -r --name-only, HEAD): $COMMITTED_JSONL_COUNT"
if [ "$COMMITTED_JSONL_COUNT" -eq "$DISCOVERED_SESSIONS" ]; then
  echo "PASS: committed .jsonl count matches tool-discovered session count (staging did not silently diverge)."
  STAGE_STATUS=0
else
  echo "FAIL: committed .jsonl count ($COMMITTED_JSONL_COUNT) != discovered sessions ($DISCOVERED_SESSIONS) -- staging (git add -A) diverged from the tool's reported intent (check for a .gitignore match)." >&2
  STAGE_STATUS=1
fi

# --- Gate B2 (plan §9, commit step 7): every mirror .txt committed at
# "projects/" + mirror_relpath, plus count parity. Open question (a) --
# auto-mode-classifier-error.txt, the one sidecar shallower than
# tool-results/ -- is exercised here for the first time by the real corpus
# (no special-casing needed if the "projects/" + relpath identity holds
# generally, which it does per-file below). Open question (b) -- no
# drop-count term: the real corpus has exactly one project with zero valid
# sessions (~/.claude/projects/.scratch/, dropped by Gate A's WARN path),
# and it has zero .txt attachments, so there is no real case to adjust for;
# left as simple count-equality. ---
echo "Gate B2: mirror .txt <-> committed path + count parity..."
COMMITTED_LIST_FILE="$REPO_ROOT/.scratch/sync-local-committed-tree-${RUN_ID}.txt"
git -C "$THROWAWAY_REPO" ls-tree -r --name-only HEAD > "$COMMITTED_LIST_FILE"
COMMITTED_TXT_COUNT="$(grep -cE '\.txt$' "$COMMITTED_LIST_FILE" || true)"
MIRROR_TXT_COUNT="$(find "$MIRROR" -name '*.txt' -type f | wc -l | tr -d ' ')"
echo "mirror .txt files: $MIRROR_TXT_COUNT"
echo "committed .txt files: $COMMITTED_TXT_COUNT"

GATE_B2_STATUS=0
if [ "$MIRROR_TXT_COUNT" -ne "$COMMITTED_TXT_COUNT" ]; then
  echo "FAIL: Gate B2 count mismatch -- mirror .txt ($MIRROR_TXT_COUNT) != committed .txt ($COMMITTED_TXT_COUNT)" >&2
  GATE_B2_STATUS=1
fi

MISSING_TXT_FILE="$REPO_ROOT/.scratch/sync-local-gate-b2-missing-${RUN_ID}.txt"
: > "$MISSING_TXT_FILE"
while IFS= read -r f; do
  rel="${f#"$MIRROR"/}"
  expected="projects/$rel"
  if ! grep -qxF "$expected" "$COMMITTED_LIST_FILE"; then
    echo "$expected" >> "$MISSING_TXT_FILE"
  fi
done < <(find "$MIRROR" -name '*.txt' -type f)
if [ -s "$MISSING_TXT_FILE" ]; then
  echo "FAIL: Gate B2 -- mirror .txt file(s) missing from committed tree at their expected path:" >&2
  cat "$MISSING_TXT_FILE" >&2
  GATE_B2_STATUS=1
fi
if [ "$GATE_B2_STATUS" -eq 0 ]; then
  echo "PASS: Gate B2 (mirror .txt <-> committed path + count parity)"
fi

# --- Gate B3 (plan §9, commit step 7): sha256 each mirror .txt against its
# committed counterpart on disk (the throwaway repo is a normal, non-bare
# working tree -- committed files remain present at "projects/" + relpath
# after `claude-code-sync push` commits them). ---
echo "Gate B3: sha256 mirror .txt vs committed counterpart..."
GATE_B3_STATUS=0
MISMATCH_TXT_FILE="$REPO_ROOT/.scratch/sync-local-gate-b3-mismatch-${RUN_ID}.txt"
: > "$MISMATCH_TXT_FILE"
while IFS= read -r f; do
  rel="${f#"$MIRROR"/}"
  committed_path="$THROWAWAY_REPO/projects/$rel"
  if [ ! -f "$committed_path" ]; then
    echo "$rel (committed file missing on disk at $committed_path)" >> "$MISMATCH_TXT_FILE"
    continue
  fi
  mirror_hash="$(sha256sum "$f" | cut -d' ' -f1)"
  committed_hash="$(sha256sum "$committed_path" | cut -d' ' -f1)"
  if [ "$mirror_hash" != "$committed_hash" ]; then
    echo "$rel (mirror=$mirror_hash committed=$committed_hash)" >> "$MISMATCH_TXT_FILE"
  fi
done < <(find "$MIRROR" -name '*.txt' -type f)
if [ -s "$MISMATCH_TXT_FILE" ]; then
  echo "FAIL: Gate B3 -- sha256 mismatch(es) between mirror and committed .txt:" >&2
  cat "$MISMATCH_TXT_FILE" >&2
  GATE_B3_STATUS=1
else
  echo "PASS: Gate B3 (sha256 identity, mirror vs committed, all .txt)"
fi

# --- Gate B4 (plan §9, commit step 7): read skip_ceiling_exceeded from the
# fixed-path summary.json ($MIRROR/../summary.json, written by
# sanitize/mirror.py's run_build()/_main()) -- never invoke build-mirror or
# read its exit code from here. Fails closed if the file is missing. ---
echo "Gate B4: skip_ceiling_exceeded check (fixed-path summary.json)..."
FIXED_SUMMARY="$(dirname "$MIRROR")/summary.json"
GATE_B4_STATUS=0
if [ ! -f "$FIXED_SUMMARY" ]; then
  echo "FAIL: Gate B4 -- fixed-path summary.json not found at $FIXED_SUMMARY (run 'just build-mirror' first)." >&2
  GATE_B4_STATUS=1
else
  SKIP_CEILING_EXCEEDED="$(uv run python3 -c "
import json
with open('$FIXED_SUMMARY') as f:
    d = json.load(f)
print(d.get('skip_ceiling_exceeded'))
")"
  echo "skip_ceiling_exceeded: $SKIP_CEILING_EXCEEDED"
  if [ "$SKIP_CEILING_EXCEEDED" != "False" ]; then
    echo "FAIL: Gate B4 -- skip_ceiling_exceeded is not False ($SKIP_CEILING_EXCEEDED, or field missing)." >&2
    GATE_B4_STATUS=1
  fi
fi
if [ "$GATE_B4_STATUS" -eq 0 ]; then
  echo "PASS: Gate B4 (skip_ceiling_exceeded == False)"
fi

# --- Acceptance check 3 (gate 7): gitleaks over the committed, re-serialized tree. ---
mkdir -p "$(dirname "$GITLEAKS_REPORT")"
echo "running gitleaks over committed tree ($THROWAWAY_REPO)..."
set +e
mise exec -- gitleaks dir "$THROWAWAY_REPO" --redact --no-banner \
  --report-format json --report-path "$GITLEAKS_REPORT" --exit-code 1
GITLEAKS_STATUS=$?
set -e
echo "gitleaks report: $GITLEAKS_REPORT"
echo "gitleaks exit: $GITLEAKS_STATUS"
if [ "$GITLEAKS_STATUS" -ne 0 ]; then
  echo "FAIL: gitleaks findings on committed tree. Breakdown:"
  uv run python3 -c "
import json
from collections import Counter
try:
    findings = json.load(open('$GITLEAKS_REPORT'))
except Exception:
    findings = []
by_rule = Counter(f['RuleID'] for f in findings)
for rule, n in sorted(by_rule.items(), key=lambda x: -x[1]):
    print(f'  {rule}: {n}')
print(f'  TOTAL: {len(findings)}')
"
fi

echo
echo "=== §9 sync-local summary ==="
echo "mirror .jsonl files:          $MIRROR_JSONL_COUNT"
echo "mirror .txt files:            $MIRROR_TXT_COUNT"
echo "oversize (>= ${MAX_FILE_SIZE_BYTES}B): $MIRROR_OVERSIZE_COUNT"
echo "discovered sessions:          $DISCOVERED_SESSIONS (expected $EXPECTED_SESSIONS)"
echo "committed files (total):      $COMMITTED_FILE_COUNT"
echo "committed .jsonl files:       $COMMITTED_JSONL_COUNT"
echo "committed .txt files:         $COMMITTED_TXT_COUNT"
echo "hygiene pre-flight:           PASS (script would already have exited 1 above otherwise)"
echo "Gate A (session-count guard): $([ "$GUARD_STATUS" -eq 0 ] && echo PASS || echo FAIL)"
echo "Gate B (staged-vs-reported):  $([ "$STAGE_STATUS" -eq 0 ] && echo PASS || echo FAIL)"
echo "Gate B2 (txt path+count):     $([ "$GATE_B2_STATUS" -eq 0 ] && echo PASS || echo FAIL)"
echo "Gate B3 (txt sha256 parity):  $([ "$GATE_B3_STATUS" -eq 0 ] && echo PASS || echo FAIL)"
echo "Gate B4 (skip_ceiling_exceeded): $([ "$GATE_B4_STATUS" -eq 0 ] && echo PASS || echo FAIL)"
echo "Gate C (gitleaks committed):  $([ "$GITLEAKS_STATUS" -eq 0 ] && echo PASS || echo FAIL)"

if [ "$GUARD_STATUS" -ne 0 ] || [ "$STAGE_STATUS" -ne 0 ] || [ "$GATE_B2_STATUS" -ne 0 ] \
   || [ "$GATE_B3_STATUS" -ne 0 ] || [ "$GATE_B4_STATUS" -ne 0 ] || [ "$GITLEAKS_STATUS" -ne 0 ]; then
  exit 1
fi
exit 0

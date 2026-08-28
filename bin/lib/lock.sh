# bin/lib/lock.sh — sourced bash library (NOT a subprocess).
#
# Implements the pre-commit hook lock/reentrancy contract from
# ~/.claude/plans/joyful-noodling-heron.md (issue #48, Phase A). The lock
# must be held inline in whichever process needs it, in that process's own
# shell — a bash script that shells out to hold a lock loses the fd the
# instant the subprocess exits. Hence: bash library, not Python.
#
# Fd-collision rule: every acquiring process opens the lock file FRESH in
# its own scope (`exec {FD}>"$STATE/lock"`). No caller may operate on a
# bare inherited fd number, hardcoded or auto-allocated — that is the only
# path this library exposes.
#
# State written on disk:
#   $STATE/lock            — the flock target (empty file, content unused)
#   $STATE/lock.owner       — {"v":1,"run_id","pid","role","at"}, written
#                              only by the actual acquirer, only while it
#                              holds the lock
#   $STATE/runs/<run_id>.<pid>.hook-outcome.json
#                            — one per hook invocation (acquired, reentrant,
#                              or aborted), {"v":1,"run_id","pid","role",
#                              "lock","exit_code","at"}
#
# Public API (call from the sourcing script):
#   lock_state_dir                        -> prints resolved state dir
#   lock_acquire_or_reentrant <role>      -> sets LOCK_RESULT/LOCK_STATE/
#                                             LOCK_ROLE/LOCK_RUN_ID and
#                                             (on "acquired") LOCK_FD and an
#                                             EXIT trap; returns 0 for
#                                             acquired/reentrant, 1 for abort
#   lock_pid_is_ancestor <pid>            -> 0 if <pid> is $$ or an ancestor
#                                             of $$, 1 otherwise (never
#                                             crashes on a vanished /proc
#                                             entry)
#
# Only the wrapper role is ever permitted a "skip, lock already held by a
# peer" branch — and that branch does not exist anywhere in this file or in
# hooks/pre-commit. A hook that cannot acquire and is not a recognized
# reentrant call always aborts non-zero. Never exit 0 on that path.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "bin/lib/lock.sh must be sourced, not executed" >&2
  exit 1
fi

# lock_state_dir — resolves and prints the state dir, ALWAYS as an absolute
# path. This is load-bearing, not cosmetic: hooks/pre-commit runs with cwd
# at the *invoking* repo's toplevel, while a wrapper/backfill caller runs
# with whatever arbitrary cwd it started in. A relative SANITIZER_STATE_DIR
# resolves DIFFERENTLY in each -- silently producing two independent lock
# files and defeating mutual exclusion entirely, with no error anywhere
# (empirically found in Phase A: a relative override created a second,
# nested lock/lock.owner pair under the target repo's own worktree). Fail
# closed instead: refuse a relative override outright.
lock_state_dir() {
  local raw="${SANITIZER_STATE_DIR:-$HOME/.local/state/claude-transcript-sanitizer}"
  case "$raw" in
    /*)
      printf '%s\n' "$raw"
      ;;
    *)
      echo "lock.sh: SANITIZER_STATE_DIR must be an absolute path (got relative: '$raw')." >&2
      echo "A relative path resolves differently in hooks/pre-commit (cwd = the" >&2
      echo "invoking repo's toplevel) than in a wrapper/backfill caller (arbitrary" >&2
      echo "cwd), silently creating two independent lock files. Refusing to proceed." >&2
      return 1
      ;;
  esac
}

lock_owner_path() {
  printf '%s\n' "$(lock_state_dir)/lock.owner"
}

# lock_validate_run_id <id> — a run_id is attacker-influenceable
# (SANITIZER_RUN_ID is an env var any caller can set) and gets interpolated
# into filesystem paths (runs/<run_id>.<pid>.hook-outcome.json). Restrict to
# a safe charset up front so a run_id containing "../" can never escape
# SANITIZER_STATE_DIR, and a "/"-containing run_id can never silently fail
# an outcome-record write. No dots at all (not just no "..") -- simplest
# rule that is still trivially safe for a path component.
lock_validate_run_id() {
  local id="$1"
  [[ "$id" =~ ^[A-Za-z0-9_-]+$ ]]
}

# lock_close_all_lock_fds — closes EVERY fd in this process currently open
# on the lock file, whatever its number and however it got there: an fd
# this process opened itself, or one inherited across fork/exec from an
# ancestor (bash's `{name}>` fd allocation is not close-on-exec, so a
# wrapper's held LOCK_FD survives into `git commit`'s exec of this hook,
# and from there into the hook process's own children, on BOTH the
# acquired and reentrant branches). Callers use this from a subshell
# right before exec-ing an external tool (e.g. gitleaks) so the external
# tool can never hold the lock open past this hook's own exit. Safe to
# call with no lock fd open at all (no-op).
lock_close_all_lock_fds() {
  local raw_lock_path lock_path
  raw_lock_path="$(lock_state_dir)/lock" 2>/dev/null || return 0
  # Canonicalize before comparing against the /proc fd targets below, which
  # are themselves canonicalized via readlink -f (L110-ish). Without this, a
  # symlinked SANITIZER_STATE_DIR makes the two paths never match, so the
  # loop closes nothing and this fix silently no-ops (found via round-2
  # stress-test, round-3 fix pass on issue #3).
  lock_path="$(readlink -f "$raw_lock_path")" 2>/dev/null || return 0
  local fd_path fd target
  # $$ inside a `( ... )` subshell still reports the OUTER shell's pid, not
  # the subshell's own — a bash quirk, not a typo. $BASHPID always reports
  # the actual running process's pid, which is exactly what we need here:
  # every real caller invokes this from inside a subshell right before
  # exec-ing the external tool, and scanning /proc/$$/fd there would
  # inspect the wrong process's (the parent hook's) fd table entirely.
  for fd_path in /proc/$BASHPID/fd/*; do
    fd="${fd_path##*/}"
    [[ "$fd" =~ ^[0-9]+$ ]] || continue
    target="$(readlink -f "$fd_path" 2>/dev/null)" || continue
    if [[ "$target" == "$lock_path" ]]; then
      eval "exec ${fd}>&-" 2>/dev/null || true
    fi
  done
}

# lock_pid_is_ancestor <pid> — bounded-depth walk of /proc/<pid>/stat's PPID
# chain starting at $$, looking for <pid>. PPID is parsed as the field
# immediately after the LAST ')' in the stat line — the second field
# (`comm`) is parenthesized and can itself contain spaces or ')', so a
# fixed awk column is wrong. A /proc/<pid> that vanishes mid-walk (process
# exited between our flock failure and this check) is treated as "not an
# ancestor", never a crash.
lock_pid_is_ancestor() {
  local target_pid="$1"
  [[ "$target_pid" =~ ^[0-9]+$ ]] || return 1

  local pid="$$"
  local depth=0
  local max_depth="${LOCK_ANCESTRY_MAX_DEPTH:-64}"

  while (( depth < max_depth )); do
    if [[ "$pid" == "$target_pid" ]]; then
      return 0
    fi
    if [[ "$pid" == "1" || "$pid" == "0" ]]; then
      return 1
    fi

    local stat_line
    stat_line="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
    [[ -n "$stat_line" ]] || return 1

    # Strip everything up to and including the LAST ')' — what remains
    # starts with " <state> <ppid> ...".
    local after_comm="${stat_line##*)}"
    local state ppid _rest
    read -r state ppid _rest <<< "$after_comm"
    [[ "$ppid" =~ ^[0-9]+$ ]] || return 1

    pid="$ppid"
    depth=$(( depth + 1 ))
  done

  return 1
}

lock_owner_write() {
  local run_id="$1" pid="$2" role="$3"
  local path at
  path="$(lock_owner_path)"
  mkdir -p "$(dirname "$path")"
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # jq -n --arg builds the JSON with proper escaping -- a raw printf %s
  # substitution here would let a run_id containing a `"` inject a
  # duplicate/attacker-controlled key that jq's own last-wins parsing of
  # this file would then read back wrong.
  jq -n --arg run_id "$run_id" --argjson pid "$pid" --arg role "$role" --arg at "$at" \
    '{v: 1, run_id: $run_id, pid: $pid, role: $role, at: $at}' > "$path"
}

# lock_owner_read_field <jq-filter> — prints the field, or fails (return 1,
# no output) if lock.owner is missing, unreadable, or fails to parse. Used
# so a missing/corrupt lock.owner degrades to "no match" (abort), never a
# crash.
lock_owner_read_field() {
  local filter="$1"
  local path
  path="$(lock_owner_path)"
  [[ -r "$path" ]] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -e -r "$filter" "$path" 2>/dev/null
}

# lock_write_outcome <exit_code|""> <lock_state> <run_id> <role>
# One record per hook invocation. exit_code "" -> JSON null (used when the
# record is written before the hook's final exit code is known, i.e. the
# reentrant and abort branches, which do not install the EXIT trap).
lock_write_outcome() {
  local exit_code="$1" lock_state="$2" run_id="$3" role="$4"
  local state_dir path at
  state_dir="$(lock_state_dir)"
  mkdir -p "$state_dir/runs"
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  path="$state_dir/runs/${run_id}.$$.hook-outcome.json"
  # jq -n builds the JSON with proper escaping (same run_id-injection
  # hazard as lock_owner_write). exit_code is passed with --argjson when
  # present (a bare integer -> a JSON number) and omitted (-> JSON null)
  # when the caller does not yet know the hook's final exit code.
  if [[ -z "$exit_code" ]]; then
    jq -n --arg run_id "$run_id" --argjson pid "$$" --arg role "$role" --arg lock "$lock_state" --arg at "$at" \
      '{v: 1, run_id: $run_id, pid: $pid, role: $role, lock: $lock, exit_code: null, at: $at}' > "$path"
  else
    jq -n --arg run_id "$run_id" --argjson pid "$$" --arg role "$role" --arg lock "$lock_state" \
      --argjson exit_code "$exit_code" --arg at "$at" \
      '{v: 1, run_id: $run_id, pid: $pid, role: $role, lock: $lock, exit_code: $exit_code, at: $at}' > "$path"
  fi
}

# lock_patch_outcome_exit_code <exit_code> <lock_state> <run_id> <role> —
# for the reentrant/abort branches, which never install the acquirer's
# EXIT trap (they must not touch lock.owner or lock/flock semantics — only
# the acquirer owns those). Those branches' outcome records are written
# with exit_code:null at lock_acquire_or_reentrant time, before the hook's
# own stages (gitleaks etc.) have run. Called from the hook's own EXIT
# trap on those branches once the hook's exit code is actually known, so a
# reentrant commit that gets BLOCKED by Stage 1 is distinguishable from
# one that passed cleanly. A no-op if the record was never written (e.g.
# the run_id-validation abort path, which intentionally never used the
# unvalidated run_id in a path at all) or can't be read as JSON.
lock_patch_outcome_exit_code() {
  local exit_code="$1" lock_state="$2" run_id="$3" role="$4"
  local state_dir path tmp
  state_dir="$(lock_state_dir)" 2>/dev/null || return 0
  path="$state_dir/runs/${run_id}.$$.hook-outcome.json"
  [[ -f "$path" ]] || return 0
  tmp="$(mktemp "${path}.XXXXXX" 2>/dev/null)" || return 0
  if jq --argjson exit_code "$exit_code" '.exit_code = $exit_code' "$path" > "$tmp" 2>/dev/null; then
    mv "$tmp" "$path"
  else
    rm -f "$tmp"
  fi
}

# lock_on_exit <exit_code> — the ONE composed EXIT trap, installed only on
# the acquired branch. Order matters: (a) exit code is captured as the
# trap's first action (passed in from `trap '... "$?"' EXIT`, evaluated at
# fire time before this function runs anything else), (b) outcome record
# is written while the lock is still held, (c) lock is released last. No
# separate "release trap" / "outcome trap" — bash has exactly one EXIT
# trap slot and installing a second silently replaces the first.
lock_on_exit() {
  local exit_code="$1"
  # This call is a PLAIN command inside an EXIT trap running under the
  # sourcing script's set -e -- unlike lock_acquire_or_reentrant, `set -e` is
  # NOT suspended here. Without the `||` fallback, a jq/mkdir failure inside
  # lock_write_outcome would abort the trap right here and never reach the
  # cleanup below (rm lock.owner, flock -u, fd close) -- the observable
  # symptom is not a stale lock (flock is kernel-released on process exit
  # regardless), it's the trap dying under set -e with rc=127, which
  # terminates an otherwise-clean `exit 0` commit with that code instead
  # (found via round-2 stress-test, round-3 fix pass on issue #3).
  lock_write_outcome "$exit_code" "acquired" "$LOCK_RUN_ID" "$LOCK_ROLE" \
    || echo "lock.sh: warning — failed to write outcome record (jq missing or write failed)" >&2
  # lock.owner is documented (see header) as written only while the
  # acquirer holds the lock -- remove it here, after the outcome record is
  # safely written but before the flock itself is released, so a
  # concurrent contender that loses the flock race never sees a stale
  # lock.owner belonging to an acquirer that has already finished exiting.
  rm -f "$(lock_owner_path)" 2>/dev/null || true
  flock -u "$LOCK_FD" 2>/dev/null || true
  # NOTE: `exec {LOCK_FD}>&-` is a silent no-op here — the `{name}` form
  # only allocates a *fresh* fd on open; it does not resolve an existing
  # variable's fd number for a close. Verified empirically (Phase A).
  # Closing a stored fd number requires eval.
  eval "exec ${LOCK_FD}>&-" 2>/dev/null || true
}

# lock_acquire_or_reentrant <role> — the three-branch contract. Sets
# LOCK_RESULT/LOCK_STATE/LOCK_ROLE/LOCK_RUN_ID always; sets LOCK_FD and
# installs the EXIT trap only on the acquired branch. Returns 0 for
# acquired/reentrant, 1 for abort — the caller must treat non-zero as a
# hard stop (HOOK_ABORT_LOCK), never exit 0.
lock_acquire_or_reentrant() {
  local role="$1"
  local state_dir

  # NOTE: this function is always called as an `if lock_acquire_or_reentrant
  # ...; then` condition (by both hooks/pre-commit and the test-double
  # wrapper) -- bash suspends `set -e` for the ENTIRE body of a function
  # invoked that way, so a failed `state_dir="$(lock_state_dir)"` here does
  # NOT abort the script on its own (verified empirically in Phase A: it
  # silently fell through into `mkdir -p ""` / an unbound $LOCK_FD instead).
  # Every failure path in this function must therefore be checked
  # explicitly -- nothing here may rely on `set -e` to catch it.
  if ! state_dir="$(lock_state_dir)"; then
    LOCK_RUN_ID="${SANITIZER_RUN_ID:-unknown}"
    LOCK_ROLE="$role"
    LOCK_STATE="LOCK"
    LOCK_RESULT="abort"
    return 1
  fi

  # SANITIZER_RUN_ID is attacker-influenceable (any caller can set the env
  # var) and gets interpolated into filesystem paths downstream (the
  # outcome-record filename, and lock.owner's run_id field). Validate
  # before it is used ANYWHERE -- including before the abort-path
  # lock_write_outcome calls below, all of which take this same value --
  # so a "../"-laden or otherwise unsafe run_id can never reach a path or
  # a JSON field. Fail closed: abort, do not silently fall back to
  # "unknown" (that would swallow the attack instead of surfacing it).
  if [[ -n "${SANITIZER_RUN_ID:-}" ]] && ! lock_validate_run_id "${SANITIZER_RUN_ID}"; then
    echo "lock.sh: SANITIZER_RUN_ID contains invalid characters (only [A-Za-z0-9_-] allowed): '${SANITIZER_RUN_ID}'" >&2
    LOCK_RUN_ID="invalid"
    LOCK_ROLE="$role"
    LOCK_STATE="LOCK"
    LOCK_RESULT="abort"
    return 1
  fi

  if ! mkdir -p "$state_dir" 2>/dev/null; then
    echo "lock.sh: failed to create state dir '$state_dir'" >&2
    LOCK_RUN_ID="${SANITIZER_RUN_ID:-unknown}"
    LOCK_ROLE="$role"
    LOCK_STATE="LOCK"
    LOCK_RESULT="abort"
    return 1
  fi

  # Fresh open in this process's own scope — the only way this library
  # ever touches the lock file.
  #
  # NOTE: no `2>/dev/null` here, unlike the other checks in this function.
  # A bare `exec {FD}>file` has no command attached, so ANY redirection
  # written on that same line -- including a `2>...` meant only to
  # suppress bash's own error message -- is applied PERMANENTLY to the
  # current shell, not just to this one statement (verified empirically:
  # it silently redirects this process's stderr to /dev/null for the rest
  # of its life, including bash -x tracing and every later `echo ... >&2`).
  if ! exec {LOCK_FD}>"$state_dir/lock"; then
    echo "lock.sh: failed to open lock file '$state_dir/lock'" >&2
    LOCK_RUN_ID="${SANITIZER_RUN_ID:-unknown}"
    LOCK_ROLE="$role"
    LOCK_STATE="LOCK"
    LOCK_RESULT="abort"
    return 1
  fi

  if flock -n "$LOCK_FD"; then
    local run_id="${SANITIZER_RUN_ID:-}"
    if [[ -z "$run_id" ]]; then
      # Human ran `git commit` directly, no wrapper set SANITIZER_RUN_ID.
      run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    fi
    export SANITIZER_RUN_ID="$run_id"

    # lock_owner_write is jq-based and unguarded below. Because this
    # function's body runs with `set -e` suspended (see the NOTE above), a
    # missing jq there would NOT abort -- it would silently leave lock.owner
    # as an empty file while this branch still reports "acquired" and
    # returns 0. A legitimate reentrant descendant then reads that empty
    # file, gets no run_id match, and gets spuriously rejected with
    # HOOK_ABORT_LOCK -- with no diagnostic anywhere naming jq as the cause
    # (found via round-2 stress-test, round-3 fix pass on issue #3). Guard
    # explicitly here, before the write, and fail closed with a named
    # reason rather than let the corruption happen silently.
    if ! command -v jq >/dev/null 2>&1; then
      echo "lock.sh: jq is required but not found on PATH" >&2
      LOCK_RUN_ID="${SANITIZER_RUN_ID:-unknown}"
      LOCK_ROLE="$role"
      LOCK_STATE="LOCK"
      LOCK_RESULT="abort"
      eval "exec ${LOCK_FD}>&-" 2>/dev/null || true
      return 1
    fi

    LOCK_RUN_ID="$run_id"
    LOCK_ROLE="$role"
    LOCK_STATE="acquired"
    LOCK_RESULT="acquired"

    lock_owner_write "$run_id" "$$" "$role"
    trap 'lock_on_exit "$?"' EXIT
    return 0
  fi

  # Not acquired -- this fd is useless to us now, close it. (It never held
  # the flock, so there is nothing to release.) See lock_on_exit's note:
  # `{name}>&-` does not resolve a stored fd number, eval is required.
  eval "exec ${LOCK_FD}>&-" 2>/dev/null || true

  # Reentrancy check — all three required:
  #  (a) lock.owner exists and parses
  #  (b) its run_id == "${SANITIZER_RUN_ID:-}" (default-empty, so an unset
  #      var degrades to "no match" under set -u, not a crash)
  #  (c) its pid is alive AND an ancestor of this process
  local my_run_id="${SANITIZER_RUN_ID:-}"
  local owner_run_id owner_pid
  owner_run_id="$(lock_owner_read_field '.run_id')" || owner_run_id=""
  owner_pid="$(lock_owner_read_field '.pid')" || owner_pid=""

  if [[ -n "$my_run_id" ]] \
     && [[ -n "$owner_run_id" ]] \
     && [[ "$owner_run_id" == "$my_run_id" ]] \
     && [[ "$owner_pid" =~ ^[0-9]+$ ]] \
     && [[ -d "/proc/$owner_pid" ]] \
     && lock_pid_is_ancestor "$owner_pid"; then
    LOCK_RUN_ID="$my_run_id"
    LOCK_ROLE="$role"
    LOCK_STATE="reentrant"
    LOCK_RESULT="reentrant"
    lock_write_outcome "" "reentrant" "$my_run_id" "$role" || true
    return 0
  fi

  LOCK_RUN_ID="${my_run_id:-unknown}"
  LOCK_ROLE="$role"
  LOCK_STATE="LOCK"
  LOCK_RESULT="abort"
  lock_write_outcome "" "LOCK" "$LOCK_RUN_ID" "$role" || true
  return 1
}

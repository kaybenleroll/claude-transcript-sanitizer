"""tests/test_lock.py — Phase A validation harness for issue #48
(bin/lib/lock.sh + hooks/pre-commit Stage 0/1 only; Stage 2/classify.py
integration is deferred to Phase B, see ~/.claude/plans/joyful-noodling-heron.md).

Every test in this file runs against throwaway git repos under pytest's
tmp_path, with SANITIZER_STATE_DIR always pointed at a tmp directory (never
the real ~/.local/state/claude-transcript-sanitizer, never
~/.claude-code-sync-repo) -- enforced by the autouse `_isolated_state_dir`
fixture below, which asserts via conftest.assert_state_dir_isolated before
any test body runs.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from tests.conftest import assert_state_dir_isolated

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_SH = REPO_ROOT / "bin" / "lib" / "lock.sh"
HOOK_SRC = REPO_ROOT / "hooks" / "pre-commit"
WRAPPER_DOUBLE = REPO_ROOT / "tests" / "fixtures" / "test_double_wrapper.sh"
GATE_SH = REPO_ROOT / "bin" / "gitleaks-gate.sh"


# --------------------------------------------------------------------------
# Isolation + small helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state_dir = tmp_path / "sanitizer-state"
    monkeypatch.setenv("SANITIZER_STATE_DIR", str(state_dir))
    monkeypatch.delenv("SANITIZER_RUN_ID", raising=False)
    assert_state_dir_isolated(state_dir)
    return state_dir


def make_repo(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    return repo


def install_hook(repo: Path, hook_src: Path = HOOK_SRC) -> None:
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    if hook_path.exists() or hook_path.is_symlink():
        hook_path.unlink()
    hook_path.symlink_to(hook_src)


def stage_file(repo: Path, filename: str, content: str) -> None:
    (repo / filename).write_text(content)
    subprocess.run(["git", "add", filename], cwd=repo, check=True)


def commit(repo: Path, message: str, env: dict | None = None) -> subprocess.CompletedProcess:
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    return subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo,
        env=run_env,
        capture_output=True,
        text=True,
    )


def commit_count(repo: Path) -> int:
    result = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return 0
    return int(result.stdout.strip())


def outcome_records(state_dir: Path) -> list[dict]:
    runs_dir = state_dir / "runs"
    if not runs_dir.exists():
        return []
    return [json.loads(p.read_text()) for p in sorted(runs_dir.glob("*.json"))]


def start_wrapper_holder(
    state_dir: Path, tmp_path: Path, hold_cmd: list[str], lock_sh: Path = LOCK_SH
) -> tuple[subprocess.Popen, Path]:
    """Spawn the test-double wrapper in the background holding the lock
    while it runs hold_cmd (e.g. `sleep 5`). Returns (process, info_file)."""
    info_file = tmp_path / "holder.info"
    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = str(state_dir)
    env.pop("SANITIZER_RUN_ID", None)
    proc = subprocess.Popen(
        ["bash", str(WRAPPER_DOUBLE), str(lock_sh), str(info_file), *hold_cmd],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.time() + 5
    while not info_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    return proc, info_file


def read_holder_info(info_file: Path) -> tuple[str, str]:
    run_id, pid = info_file.read_text().split()
    return run_id, pid


def make_binshim(tmp_path: Path) -> Path:
    """A PATH directory with symlinks to every tool lock.sh/the hook need,
    EXCEPT jq -- for tests exercising a missing-jq failure mode without also
    breaking mkdir/git/date/flock/readlink (a naive PATH strip removes all
    of them, since jq lives alongside them under /usr/bin)."""
    shim = tmp_path / "binshim"
    shim.mkdir(exist_ok=True)
    for tool in ("mkdir", "rm", "date", "flock", "readlink", "git", "bash", "cat", "mv", "mktemp"):
        found = shutil.which(tool)
        assert found, f"required tool not found on PATH: {tool}"
        (shim / tool).symlink_to(found)
    return shim


# --------------------------------------------------------------------------
# Assertion 1 — foreign lock holder blocks the commit
# --------------------------------------------------------------------------


def test_foreign_lock_holder_blocks_commit(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        read_holder_info(info_file)  # holder acquired

        repo = make_repo(tmp_path, "repo")
        install_hook(repo)
        stage_file(repo, "f.txt", "hello\n")

        env = {"SANITIZER_STATE_DIR": str(state_dir)}
        env.pop("SANITIZER_RUN_ID", None)
        result = commit(repo, "foreign commit", env=env)

        assert result.returncode != 0, result.stdout + result.stderr
        assert commit_count(repo) == 0
        assert "HOOK_ABORT_LOCK" in (result.stdout + result.stderr)

        records = outcome_records(state_dir)
        foreign_records = [r for r in records if r["role"] == "recipe"]
        assert len(foreign_records) == 1
        assert foreign_records[0]["lock"] == "LOCK"
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


# --------------------------------------------------------------------------
# Assertion 2 — reentrancy: hook records "lock":"reentrant"
# --------------------------------------------------------------------------


def test_reentrant_commit_succeeds_and_records_reentrant(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    stage_file(repo, "f.txt", "hello\n")

    info_file = tmp_path / "holder.info"
    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = str(state_dir)
    env.pop("SANITIZER_RUN_ID", None)
    result = subprocess.run(
        [
            "bash", str(WRAPPER_DOUBLE), str(LOCK_SH), str(info_file),
            "git", "-C", str(repo), "commit", "-m", "reentrant commit",
        ],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert commit_count(repo) == 1
    # git relays hook stdout/stderr through to its own stderr, not stdout.
    assert "lock: reentrant" in result.stdout + result.stderr

    holder_run_id, holder_pid = read_holder_info(info_file)
    records = outcome_records(state_dir)
    reentrant_records = [r for r in records if r["role"] == "recipe" and r["lock"] == "reentrant"]
    assert len(reentrant_records) == 1
    assert reentrant_records[0]["run_id"] == holder_run_id

    acquired_records = [r for r in records if r["role"] == "wrapper" and r["lock"] == "acquired"]
    assert len(acquired_records) == 1
    assert acquired_records[0]["pid"] == int(holder_pid)


# --------------------------------------------------------------------------
# Assertion 3 — lock.owner unchanged across two sequential batches
# --------------------------------------------------------------------------


def test_lock_owner_unchanged_across_two_batches(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)

    driver = tmp_path / "two_batch_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
cd "{repo}"
echo "one" > file1.txt
git add file1.txt
git commit -q -m "batch 1"
cp "{state_dir}/lock.owner" "{tmp_path}/owner_after_batch1.json"
echo "two" > file2.txt
git add file2.txt
git commit -q -m "batch 2"
cp "{state_dir}/lock.owner" "{tmp_path}/owner_after_batch2.json"
"""
    )
    driver.chmod(0o755)

    info_file = tmp_path / "holder.info"
    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = str(state_dir)
    env.pop("SANITIZER_RUN_ID", None)
    result = subprocess.run(
        ["bash", str(WRAPPER_DOUBLE), str(LOCK_SH), str(info_file), "bash", str(driver)],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert commit_count(repo) == 2

    owner1 = (tmp_path / "owner_after_batch1.json").read_text()
    owner2 = (tmp_path / "owner_after_batch2.json").read_text()
    assert owner1 == owner2, "lock.owner must be byte-identical across both reentrant batches"


# --------------------------------------------------------------------------
# Regression (found empirically during Phase A, not in the original plan's
# 8 assertions): a RELATIVE SANITIZER_STATE_DIR resolves differently for
# the wrapper (arbitrary cwd) than for the hook (always the invoking
# repo's toplevel) -- silently producing two independent lock files and
# defeating mutual exclusion with no error. lock_state_dir() now rejects a
# relative override outright; this locks that in as a regression test.
# --------------------------------------------------------------------------


def test_relative_state_dir_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SANITIZER_STATE_DIR", "some/relative/path")
    result = subprocess.run(
        ["bash", "-c", f'source "{LOCK_SH}"; lock_state_dir'],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "must be an absolute path" in result.stderr


def test_relative_state_dir_makes_acquire_fail_closed_not_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The bug this guards: before the fix, a relative SANITIZER_STATE_DIR
    caused lock_acquire_or_reentrant to fall through into `mkdir -p ""`
    and an unbound $LOCK_FD (set -e does NOT catch this -- the function is
    always called as an `if funcname; then` condition, which suspends -e
    for its entire body). The fix must fail closed (return 1, clean
    LOCK_RESULT=abort) instead of crashing with unrelated shell errors."""
    monkeypatch.setenv("SANITIZER_STATE_DIR", "some/relative/path")
    monkeypatch.delenv("SANITIZER_RUN_ID", raising=False)
    result = subprocess.run(
        [
            "bash", "-c",
            f'source "{LOCK_SH}"; '
            'if lock_acquire_or_reentrant "recipe"; then echo "RESULT=$LOCK_RESULT"; exit 0; '
            'else echo "RESULT=$LOCK_RESULT"; exit 1; fi',
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "RESULT=abort" in result.stdout
    assert "unbound variable" not in result.stderr
    assert "Permission denied" not in result.stderr


def test_mutant_unresolved_relative_state_dir_breaks_reentrancy(tmp_path: Path):
    """Mutant: restore the original unguarded `lock_state_dir` (no
    absolute-path check). Reproduces the real bug directly at the lock.sh
    level (no git/hook machinery needed): a holder process and a genuine
    descendant of it run from two DIFFERENT cwds -- exactly what happens
    for a real wrapper (arbitrary cwd) and hooks/pre-commit (always the
    invoking repo's toplevel) -- both given the SAME relative
    SANITIZER_STATE_DIR. With the mutant, the descendant resolves a
    DIFFERENT, always-unlocked file and incorrectly reports "acquired"
    instead of "reentrant", silently defeating mutual exclusion."""
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "unguarded_state_dir.sh",
        [
            (
                'lock_state_dir() {\n'
                '  local raw="${SANITIZER_STATE_DIR:-$HOME/.local/state/claude-transcript-sanitizer}"\n'
                '  case "$raw" in\n'
                '    /*)\n'
                '      printf \'%s\\n\' "$raw"\n'
                '      ;;\n'
                '    *)\n'
                '      echo "lock.sh: SANITIZER_STATE_DIR must be an absolute path (got relative: \'$raw\')." >&2\n'
                '      echo "A relative path resolves differently in hooks/pre-commit (cwd = the" >&2\n'
                '      echo "invoking repo\'s toplevel) than in a wrapper/backfill caller (arbitrary" >&2\n'
                '      echo "cwd), silently creating two independent lock files. Refusing to proceed." >&2\n'
                '      return 1\n'
                '      ;;\n'
                '  esac\n'
                '}',
                'lock_state_dir() {\n'
                '  printf \'%s\\n\' "${SANITIZER_STATE_DIR:-$HOME/.local/state/claude-transcript-sanitizer}"\n'
                '}',
            )
        ],
    )

    holder_cwd = tmp_path / "holder_cwd"
    descendant_cwd = tmp_path / "descendant_cwd"
    holder_cwd.mkdir()
    descendant_cwd.mkdir()

    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = "relstate"  # relative -- resolved differently per-process below
    env.pop("SANITIZER_RUN_ID", None)

    driver = tmp_path / "cwd_mismatch_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -uo pipefail
cd "{holder_cwd}"
source "{mutant_lock_sh}"
lock_acquire_or_reentrant "wrapper"
export SANITIZER_RUN_ID="$LOCK_RUN_ID"

# Genuine descendant (child of this process), but from a DIFFERENT cwd --
# exactly the wrapper-vs-hook shape.
bash -c '
  cd "{descendant_cwd}"
  source "{mutant_lock_sh}"
  if lock_acquire_or_reentrant "recipe"; then
    echo "DESCENDANT_RESULT=$LOCK_RESULT"
  else
    echo "DESCENDANT_RESULT=$LOCK_RESULT"
  fi
'
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
    assert "DESCENDANT_RESULT=acquired" in result.stdout, (
        "mutant (no absolute-path guard) was expected to have the descendant "
        "incorrectly resolve a different file and report 'acquired' instead "
        "of 'reentrant'\n" + result.stdout + result.stderr
    )


# --------------------------------------------------------------------------
# Assertion 4 — fd-reuse hazard vs fresh-reopen, both auto and literal fd
# numbers, plus a static grep that no shipped script hardcodes an fd number.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("fd_style", ["auto", "literal"])
def test_fd_reuse_hazard_vs_fresh_reopen(tmp_path: Path, _isolated_state_dir: Path, fd_style: str):
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    lockfile = state_dir / "lock"

    # "auto" must export the allocated fd number so the BAD_CALLER child
    # (a separate bash -c process) can see it -- fd inheritance across
    # fork/exec is automatic, but the *variable name* holding the number
    # is not visible to a child unless exported.
    open_expr = 'exec {HOLDFD}>"$LOCKFILE"; export HOLDFD' if fd_style == "auto" else "exec 9>\"$LOCKFILE\""
    fd_ref = "$HOLDFD" if fd_style == "auto" else "9"

    script = f"""#!/usr/bin/env bash
set -euo pipefail
LOCKFILE="{lockfile}"
{open_expr}
flock -n {fd_ref}
echo "HELD_FD={fd_ref}"

# BAD caller: a child that inherits the fd number and reuses it bare,
# without reopening the file itself. This is the exact hazard the design
# forbids -- it must spuriously "succeed" (same open file description,
# so flock is a trivial no-op re-lock by the same underlying holder).
bash -c 'flock -n {fd_ref} && echo BAD_CALLER=acquired || echo BAD_CALLER=blocked'

# GOOD caller: a child that opens the SAME lock file fresh in its own
# scope. It must correctly fail to acquire, because the parent genuinely
# still holds the lock.
bash -c 'exec {{FRESHFD}}>"{lockfile}"; flock -n "$FRESHFD" && echo GOOD_CALLER=acquired || echo GOOD_CALLER=blocked'
"""
    script_path = tmp_path / f"fdtest_{fd_style}.sh"
    script_path.write_text(script)
    script_path.chmod(0o755)

    result = subprocess.run(["bash", str(script_path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BAD_CALLER=acquired" in result.stdout, (
        "bare inherited-fd reuse should spuriously succeed (demonstrates the "
        "hazard bin/lib/lock.sh's fresh-open rule exists to prevent)\n" + result.stdout
    )
    assert "GOOD_CALLER=blocked" in result.stdout, (
        "a fresh reopen of the same lock file must correctly contend and fail "
        "to acquire while the parent holds it\n" + result.stdout
    )


def test_no_hardcoded_fd_numbers_in_shipped_scripts():
    """Static assertion: no script in the repo operates on a bare, hardcoded
    fd number for the LOCK fd -- the only fd this repo's code touches is
    the named {LOCK_FD} allocated fresh by lock_acquire_or_reentrant.
    (Deliberately narrow to `exec N>`/`flock -n N` patterns, not any
    digit-prefixed redirection -- that would also flag ordinary
    `2>/dev/null` stderr redirects, which are unrelated to the lock fd and
    used throughout these scripts.)"""
    exec_pattern = re.compile(r"\bexec\s+[0-9]+[<>]")
    flock_pattern = re.compile(r"\bflock\s+-[a-zA-Z]*\s*[0-9]+\b")
    for path in [LOCK_SH, HOOK_SRC, WRAPPER_DOUBLE]:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = exec_pattern.search(line) or flock_pattern.search(line)
            assert m is None, f"{path}:{lineno}: hardcoded fd redirection: {line!r}"


# --------------------------------------------------------------------------
# Assertion 6 — spoofed run_id from a non-ancestor process, real holder alive
# --------------------------------------------------------------------------


def test_spoofed_run_id_from_non_ancestor_aborts(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        holder_run_id, _holder_pid = read_holder_info(info_file)

        repo = make_repo(tmp_path, "repo")
        install_hook(repo)
        stage_file(repo, "f.txt", "hello\n")

        # This test process's own commit is NOT a descendant of holder_proc
        # -- it is a sibling. Exporting the holder's real run_id here
        # simulates a spoofing/replay attempt.
        result = commit(repo, "spoofed commit", env={
            "SANITIZER_STATE_DIR": str(state_dir),
            "SANITIZER_RUN_ID": holder_run_id,
        })

        assert result.returncode != 0, result.stdout + result.stderr
        assert commit_count(repo) == 0
        records = outcome_records(state_dir)
        spoofed = [r for r in records if r["role"] == "recipe"]
        assert len(spoofed) == 1
        assert spoofed[0]["lock"] == "LOCK"
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


# --------------------------------------------------------------------------
# Assertion 7 — stale lock.owner (dead pid) is not reentrant, even if the
# run_id matches and the lock is genuinely held by someone else right now.
# --------------------------------------------------------------------------


def test_stale_owner_dead_pid_not_reentrant(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        holder_run_id, _real_pid = read_holder_info(info_file)

        # Corrupt lock.owner: same run_id, but a pid that is definitely
        # dead (spawn+wait a short-lived process to get a real, now-dead
        # pid rather than guessing a number).
        dead = subprocess.run(["bash", "-c", "echo $$"], capture_output=True, text=True)
        dead_pid = dead.stdout.strip()
        owner_path = state_dir / "lock.owner"
        owner_path.write_text(
            json.dumps({"v": 1, "run_id": holder_run_id, "pid": int(dead_pid), "role": "wrapper", "at": "corrupted"})
        )

        repo = make_repo(tmp_path, "repo")
        install_hook(repo)
        stage_file(repo, "f.txt", "hello\n")

        result = commit(repo, "against stale owner", env={
            "SANITIZER_STATE_DIR": str(state_dir),
            "SANITIZER_RUN_ID": holder_run_id,
        })

        assert result.returncode != 0, result.stdout + result.stderr
        assert commit_count(repo) == 0
        records = outcome_records(state_dir)
        stale = [r for r in records if r["role"] == "recipe"]
        assert len(stale) == 1
        assert stale[0]["lock"] == "LOCK"
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


# --------------------------------------------------------------------------
# Assertion 8 — SKIPPED_LOCKED is structurally absent from the hook
# --------------------------------------------------------------------------


def test_hook_has_no_skipped_locked_path():
    text = HOOK_SRC.read_text()
    assert "SKIPPED_LOCKED" not in text


def test_lock_sh_has_no_skipped_locked_path():
    text = LOCK_SH.read_text()
    assert "SKIPPED_LOCKED" not in text


# --------------------------------------------------------------------------
# Mutation coverage — each mutant reintroduces one specific bug and must
# make the relevant assertion above fail against the mutant.
# --------------------------------------------------------------------------


def write_mutant_lock_sh(tmp_path: Path, name: str, replacements: list[tuple[str, str]]) -> Path:
    text = LOCK_SH.read_text()
    for old, new in replacements:
        assert old in text, f"mutation anchor not found in lock.sh: {old!r}"
        text = text.replace(old, new, 1)
    mutant_dir = tmp_path / "mutant_lib"
    mutant_dir.mkdir(exist_ok=True)
    mutant_path = mutant_dir / name
    mutant_path.write_text(text)
    return mutant_path


def write_mutant_hook(tmp_path: Path, name: str, lock_sh_path: Path, replacements: list[tuple[str, str]]) -> Path:
    text = HOOK_SRC.read_text()
    for old, new in replacements:
        assert old in text, f"mutation anchor not found in hook: {old!r}"
        text = text.replace(old, new, 1)
    mutant_dir = tmp_path / "mutant_hook"
    mutant_dir.mkdir(exist_ok=True)
    mutant_path = mutant_dir / name
    mutant_path.write_text(text)
    mutant_path.chmod(0o755)
    return mutant_path


@pytest.mark.parametrize(
    "mutant_name,replacements",
    [
        (
            "strip_ancestry_check.sh",
            [
                (
                    '     && [[ -d "/proc/$owner_pid" ]] \\\n'
                    "     && lock_pid_is_ancestor \"$owner_pid\"; then",
                    '     && [[ -d "/proc/$owner_pid" ]]; then',
                )
            ],
        ),
    ],
)
def test_mutant_missing_ancestry_check_breaks_spoof_protection(
    tmp_path: Path, _isolated_state_dir: Path, mutant_name: str, replacements: list[tuple[str, str]]
):
    """Mutant: strip the `lock_pid_is_ancestor` call from the reentrancy
    condition. Assertion 6 (spoofed run_id from a non-ancestor) must now
    fail -- a spoofer with a merely-matching run_id gets treated as
    reentrant."""
    state_dir = _isolated_state_dir
    mutant_lock_sh = write_mutant_lock_sh(tmp_path, mutant_name, replacements)

    holder_proc, info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"], lock_sh=LOCK_SH)
    try:
        holder_run_id, _holder_pid = read_holder_info(info_file)

        repo = make_repo(tmp_path, "repo")
        install_hook(repo)
        stage_file(repo, "f.txt", "hello\n")

        # Drive the (mutant) library directly, bypassing the hook, since the
        # hook always sources the real lock.sh at its resolved repo path --
        # exercising the mutant requires calling lock_acquire_or_reentrant
        # from the mutant file directly, mirroring what the hook does.
        driver = tmp_path / "spoof_driver.sh"
        driver.write_text(
            f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
if lock_acquire_or_reentrant "recipe"; then
  echo "MUTANT_RESULT=$LOCK_RESULT"
  exit 0
else
  echo "MUTANT_RESULT=$LOCK_RESULT"
  exit 1
fi
"""
        )
        driver.chmod(0o755)
        result = subprocess.run(
            ["bash", str(driver)],
            env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir), "SANITIZER_RUN_ID": holder_run_id},
            capture_output=True,
            text=True,
        )
        # With the real (unmutated) library this spoof attempt aborts
        # (returncode != 0, MUTANT_RESULT=abort) -- see
        # test_spoofed_run_id_from_non_ancestor_aborts. The mutant must
        # break that: it incorrectly reports "reentrant".
        assert "MUTANT_RESULT=reentrant" in result.stdout, (
            "mutant (ancestry check stripped) was expected to incorrectly "
            "grant reentrant access to a non-ancestor spoofer, but it "
            "didn't -- mutant did not reproduce the intended bug\n" + result.stdout
        )
        assert result.returncode == 0
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


def test_mutant_second_exit_trap_breaks_lock_release(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: install a second EXIT trap after the acquirer's real one
    (bash has exactly one EXIT trap slot -- the second silently replaces
    the first, so lock release never runs). A subsequent, unrelated
    acquire attempt must then incorrectly find the lock still held even
    though the acquirer process has fully exited."""
    state_dir = _isolated_state_dir
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "second_exit_trap.sh",
        [
            (
                "    lock_owner_write \"$run_id\" \"$$\" \"$role\"\n"
                "    trap 'lock_on_exit \"$?\"' EXIT\n"
                "    return 0",
                "    lock_owner_write \"$run_id\" \"$$\" \"$role\"\n"
                "    trap 'lock_on_exit \"$?\"' EXIT\n"
                "    trap 'true' EXIT\n"  # <-- second trap silently replaces the first
                "    return 0",
            )
        ],
    )

    driver = tmp_path / "acquire_and_exit.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
lock_acquire_or_reentrant "wrapper"
echo "acquired, exiting now"
exit 0
"""
    )
    driver.chmod(0o755)
    env = {**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}
    result = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    # Acquirer process has fully exited. With the real lock_on_exit trap,
    # the flock would now be released and a fresh acquire would succeed.
    # With the mutant's second trap silently discarding lock_on_exit, the
    # fd (and its flock) leaked with the dead process and the file lock
    # itself is released by the kernel on process exit regardless -- so
    # what actually stays wrong is lock.owner: it is never cleared/updated
    # and the outcome record is never written, because lock_on_exit's body
    # (which does both) never ran.
    assert not (state_dir / "runs").exists() or not any((state_dir / "runs").glob("*.json")), (
        "mutant (second EXIT trap) was expected to suppress lock_on_exit "
        "entirely, so no outcome record should have been written"
    )


def test_mutant_child_inherits_open_fd_holds_lock_past_hook_exit(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: a child (e.g. gitleaks) inherits the lock fd WITHOUT it
    being explicitly closed.

    Note on what this actually has to prove: flock(2) locks are owned by
    the *open file description*, not by an individual fd. An explicit
    `flock -u` (the acquirer's normal EXIT trap) releases the lock for
    every duplicate fd that shares that description, regardless of
    whether a child closed its own copy -- so a graceful hook exit can
    never demonstrate this hazard either way. The real hazard is the
    acquirer dying *without* running its EXIT trap (a crash/SIGKILL,
    which bash cannot trap) while a child still holds an inherited
    duplicate of the fd: the kernel closes the acquirer's own copy on
    death, but the lock survives as long as ANY fd referencing that open
    file description remains open. Simulated here by SIGKILLing the
    acquirer out from under a still-running child."""
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)

    def make_acquirer_script(close_fd: bool, label: str) -> Path:
        close_stmt = 'eval "exec ${LOCK_FD}>&-"; ' if close_fd else ""
        script = tmp_path / f"acquirer_{label}.sh"
        script.write_text(
            f"""#!/usr/bin/env bash
set -uo pipefail
source "{LOCK_SH}"
lock_acquire_or_reentrant "wrapper"
( {close_stmt}exec sleep 30 ) &
echo $! > "{tmp_path}/{label}_child.pid"
echo $$ > "{tmp_path}/{label}_acquirer.pid"
# Block using a bash BUILTIN (no fork) -- `sleep 30` here would itself be
# a second, incidental fd-inheriting child (orphaned, not killed, by the
# SIGKILL below) that would leak the fd in both scenarios and mask the
# thing this test is actually isolating.
read -r -t 30 _unused || true
"""
        )
        script.chmod(0o755)
        return script

    def run_crash_scenario(close_fd: bool, label: str) -> bool:
        script = make_acquirer_script(close_fd, label)
        env = {**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}
        # stdin=PIPE (left open, never written/closed) so the script's
        # blocking `read` genuinely blocks on a live pipe instead of
        # hitting EOF on an already-closed/inherited stdin and exiting
        # (and running its own real EXIT trap) before we get to SIGKILL it.
        proc = subprocess.Popen(["bash", str(script)], env=env, stdin=subprocess.PIPE)
        acquirer_pidfile = tmp_path / f"{label}_acquirer.pid"
        child_pidfile = tmp_path / f"{label}_child.pid"
        deadline = time.time() + 5
        while (not acquirer_pidfile.exists() or not child_pidfile.exists()) and time.time() < deadline:
            time.sleep(0.05)
        assert acquirer_pidfile.exists() and child_pidfile.exists(), "acquirer/child failed to start in time"
        acquirer_pid = int(acquirer_pidfile.read_text().strip())
        child_pid = int(child_pidfile.read_text().strip())

        time.sleep(0.2)
        os.kill(acquirer_pid, signal.SIGKILL)  # simulate a crash, bypassing lock_on_exit entirely
        proc.wait(timeout=5)
        time.sleep(0.2)

        probe = subprocess.run(
            ["bash", "-c", f'exec {{FD}}>"{state_dir}/lock"; flock -n "$FD" && echo FREE || echo BLOCKED'],
            capture_output=True,
            text=True,
        )
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return "FREE" in probe.stdout

    good_is_free = run_crash_scenario(close_fd=True, label="good")
    (state_dir / "lock").unlink(missing_ok=True)
    bad_is_free = run_crash_scenario(close_fd=False, label="bad")

    assert good_is_free, (
        "when the child closes its inherited copy of the lock fd, an acquirer "
        "crash (SIGKILL, no EXIT trap) must still leave the lock free"
    )
    assert not bad_is_free, (
        "mutant (child keeps the inherited lock fd open) was expected to leave "
        "the lock held by the surviving child even after the acquirer was killed"
    )


def test_reentrant_branch_child_inherits_open_fd_holds_lock_past_acquirer_exit(
    tmp_path: Path, _isolated_state_dir: Path
):
    """Regression for issue #48 fix 1: the REENTRANT branch leaked the
    grandparent acquirer's lock fd into its own Stage-1 children too, not
    just the acquired branch. Shape: an acquirer (wrapper) holds the lock
    and blocks; a reentrant descendant (hook-shaped: same SANITIZER_RUN_ID,
    a genuine child-of-acquirer process) runs lock_acquire_or_reentrant
    "recipe", gets LOCK_STATE=reentrant, spawns its OWN child (a gitleaks
    stand-in) that inherits the fd, then the reentrant process itself exits
    normally -- exactly like a real hook finishing while gitleaks hangs.
    The acquirer is then SIGKILLed (crash, no EXIT trap) while the
    grandchild is still running. Without lock_close_all_lock_fds called on
    the reentrant branch before spawning that child, the grandchild's
    inherited copy of the fd keeps the flock held even though every
    process that ever ran lock_acquire_or_reentrant has exited."""
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)

    def make_scripts(close_fd: bool, label: str) -> tuple[Path, Path]:
        close_stmt = "lock_close_all_lock_fds; " if close_fd else ""
        reentrant_script = tmp_path / f"reentrant_{label}.sh"
        reentrant_script.write_text(
            f"""#!/usr/bin/env bash
set -uo pipefail
source "{LOCK_SH}"
if ! lock_acquire_or_reentrant "recipe"; then
  echo "reentrant script did not reach reentrant state: $LOCK_RESULT" >&2
  exit 1
fi
if [[ "$LOCK_STATE" != "reentrant" ]]; then
  echo "expected LOCK_STATE=reentrant, got $LOCK_STATE" >&2
  exit 1
fi
( {close_stmt}exec sleep 30 ) &
echo $! > "{tmp_path}/{label}_child.pid"
exit 0
"""
        )
        reentrant_script.chmod(0o755)

        acquirer_script = tmp_path / f"acquirer_{label}.sh"
        acquirer_script.write_text(
            f"""#!/usr/bin/env bash
set -uo pipefail
source "{LOCK_SH}"
lock_acquire_or_reentrant "wrapper"
export SANITIZER_RUN_ID="$LOCK_RUN_ID"
echo $$ > "{tmp_path}/{label}_acquirer.pid"
bash "{reentrant_script}"
read -r -t 30 _unused || true
"""
        )
        acquirer_script.chmod(0o755)
        return acquirer_script, reentrant_script

    def run_crash_scenario(close_fd: bool, label: str) -> bool:
        acquirer_script, _reentrant_script = make_scripts(close_fd, label)
        env = {**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}
        proc = subprocess.Popen(["bash", str(acquirer_script)], env=env, stdin=subprocess.PIPE)
        acquirer_pidfile = tmp_path / f"{label}_acquirer.pid"
        child_pidfile = tmp_path / f"{label}_child.pid"
        deadline = time.time() + 5
        while (not acquirer_pidfile.exists() or not child_pidfile.exists()) and time.time() < deadline:
            time.sleep(0.05)
        assert acquirer_pidfile.exists() and child_pidfile.exists(), "acquirer/reentrant child failed to start in time"
        acquirer_pid = int(acquirer_pidfile.read_text().strip())
        child_pid = int(child_pidfile.read_text().strip())

        time.sleep(0.2)
        os.kill(acquirer_pid, signal.SIGKILL)  # simulate a crash, bypassing lock_on_exit entirely
        proc.wait(timeout=5)
        time.sleep(0.2)

        probe = subprocess.run(
            ["bash", "-c", f'exec {{FD}}>"{state_dir}/lock"; flock -n "$FD" && echo FREE || echo BLOCKED'],
            capture_output=True,
            text=True,
        )
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return "FREE" in probe.stdout

    good_is_free = run_crash_scenario(close_fd=True, label="good_reentrant")
    (state_dir / "lock").unlink(missing_ok=True)
    bad_is_free = run_crash_scenario(close_fd=False, label="bad_reentrant")

    assert good_is_free, (
        "reentrant branch: when the Stage-1 child closes every inherited copy "
        "of the lock fd (lock_close_all_lock_fds), an acquirer crash must still "
        "leave the lock free even though the reentrant process spawned a child"
    )
    assert not bad_is_free, (
        "reentrant branch bug: without closing inherited lock fds before "
        "spawning a Stage-1 child, the child's inherited copy was expected to "
        "keep the lock held even after every process that ran "
        "lock_acquire_or_reentrant had exited"
    )


# --------------------------------------------------------------------------
# Fix 7 — end-to-end acquired-branch test: an actual `git commit` with the
# hook installed and the lock free. Before this, zero tests exercised the
# acquired branch at all (every prior test either used the wrapper
# test-double to force reentrancy, or a foreign holder to force abort).
# --------------------------------------------------------------------------


def test_acquired_branch_real_commit_succeeds_and_cleans_up(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    stage_file(repo, "f.txt", "hello\n")

    env = {"SANITIZER_STATE_DIR": str(state_dir)}
    result = commit(repo, "acquired commit", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert commit_count(repo) == 1
    assert "lock: acquired" in result.stdout + result.stderr
    assert "gitleaks: clean." in result.stdout + result.stderr

    records = outcome_records(state_dir)
    acquired_records = [r for r in records if r["role"] == "recipe" and r["lock"] == "acquired"]
    assert len(acquired_records) == 1
    assert acquired_records[0]["exit_code"] == 0

    # fix 6: lock.owner must be gone once the acquirer has exited.
    assert not (state_dir / "lock.owner").exists()

    # the lock itself must be free -- no leaked fd from the gitleaks
    # subshell (fix 1's close-on-both-branches form).
    probe = subprocess.run(
        ["bash", "-c", f'exec {{FD}}>"{state_dir}/lock"; flock -n "$FD" && echo FREE || echo BLOCKED'],
        capture_output=True,
        text=True,
    )
    assert "FREE" in probe.stdout


# --------------------------------------------------------------------------
# Round-3 fix pass (issue #3) -- regression tests for round-2 stress-test
# findings, and coverage for three round-1 fixes that shipped untested:
# the SANITIZER_RUN_ID path-traversal validator, the JSON-escaping fix, and
# lock_patch_outcome_exit_code. See ~/.claude/plans/deep-humming-goose.md.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile_run_id",
    [
        "../../../etc/passwd",
        'a"b',
        "$(whoami)",
        "a/b",
        "a;rm -rf /",
    ],
)
def test_hostile_run_id_rejected(tmp_path: Path, _isolated_state_dir: Path, hostile_run_id: str):
    """Round-1 fix, untested until now: lock_validate_run_id rejects any
    SANITIZER_RUN_ID outside [A-Za-z0-9_-]. Fails-against-unfixed via
    write_mutant_lock_sh stripping the validator's call site (see the
    dedicated mutant test below)."""
    state_dir = _isolated_state_dir
    result = subprocess.run(
        [
            "bash", "-c",
            f'source "{LOCK_SH}"; '
            'if lock_acquire_or_reentrant "wrapper"; then echo "RESULT=$LOCK_RESULT RUN_ID=$LOCK_RUN_ID"; exit 0; '
            'else echo "RESULT=$LOCK_RESULT RUN_ID=$LOCK_RUN_ID"; exit 1; fi',
        ],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir), "SANITIZER_RUN_ID": hostile_run_id},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "RESULT=abort" in result.stdout
    assert "RUN_ID=invalid" in result.stdout
    # Validation fails before any mkdir/write -- nothing should exist under
    # the state dir at all.
    assert not state_dir.exists() or not any(state_dir.iterdir())


def test_mutant_stripped_run_id_validator_accepts_hostile_id(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: remove the SANITIZER_RUN_ID validation call site entirely.
    Proves test_hostile_run_id_rejected actually bites -- with the
    validator gone, a hostile run_id is no longer rejected."""
    state_dir = _isolated_state_dir
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "no_run_id_validation.sh",
        [
            (
                '  if [[ -n "${SANITIZER_RUN_ID:-}" ]] && ! lock_validate_run_id "${SANITIZER_RUN_ID}"; then\n'
                '    echo "lock.sh: SANITIZER_RUN_ID contains invalid characters (only [A-Za-z0-9_-] allowed): \'${SANITIZER_RUN_ID}\'" >&2\n'
                '    LOCK_RUN_ID="invalid"\n'
                '    LOCK_ROLE="$role"\n'
                '    LOCK_STATE="LOCK"\n'
                '    LOCK_RESULT="abort"\n'
                '    return 1\n'
                '  fi\n',
                "",
            )
        ],
    )
    result = subprocess.run(
        [
            "bash", "-c",
            f'source "{mutant_lock_sh}"; '
            'if lock_acquire_or_reentrant "wrapper"; then echo "RESULT=$LOCK_RESULT"; exit 0; '
            'else echo "RESULT=$LOCK_RESULT"; exit 1; fi',
        ],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir), "SANITIZER_RUN_ID": "../hostile"},
        capture_output=True,
        text=True,
    )
    assert "RESULT=acquired" in result.stdout, (
        "mutant (validator stripped) was expected to accept a hostile "
        "run_id and proceed to acquire\n" + result.stdout + result.stderr
    )


def test_json_escaping_holds_on_shipped_code_path(tmp_path: Path, _isolated_state_dir: Path):
    """Round-1 fix, untested until now: lock_write_outcome's jq -n --arg
    escaping. Calls the real, unmutated lock.sh directly -- reworked from
    an earlier draft of this plan that asserted on a validator-stripped
    mutant, which would have passed regardless of whether the escaping fix
    existed in any form. Fails-against-unfixed via the dedicated mutant
    test below (swap jq -n --arg for naive printf interpolation)."""
    state_dir = _isolated_state_dir
    run_id = 'a"b'
    driver = tmp_path / "escape_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{LOCK_SH}"
lock_write_outcome "" "reentrant" "$RUN_ID" "wrapper"
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir), "RUN_ID": run_id},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = outcome_records(state_dir)
    assert len(records) == 1
    assert records[0]["run_id"] == run_id


def test_mutant_naive_printf_breaks_json_escaping(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: replace jq -n --arg's safe escaping with a naive printf %s
    interpolation. Proves test_json_escaping_holds_on_shipped_code_path
    actually bites -- a run_id containing `"` now produces invalid JSON."""
    state_dir = _isolated_state_dir
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "naive_printf_escaping.sh",
        [
            (
                '  if [[ -z "$exit_code" ]]; then\n'
                '    jq -n --arg run_id "$run_id" --argjson pid "$$" --arg role "$role" --arg lock "$lock_state" --arg at "$at" \\\n'
                "      '{v: 1, run_id: $run_id, pid: $pid, role: $role, lock: $lock, exit_code: null, at: $at}' > \"$path\"\n",
                '  if [[ -z "$exit_code" ]]; then\n'
                '    printf \'{"v":1,"run_id":"%s","pid":%s,"role":"%s","lock":"%s","exit_code":null,"at":"%s"}\' '
                '"$run_id" "$$" "$role" "$lock_state" "$at" > "$path"\n',
            )
        ],
    )
    driver = tmp_path / "naive_escape_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
lock_write_outcome "" "reentrant" "$RUN_ID" "wrapper"
"""
    )
    driver.chmod(0o755)
    run_id = 'a"b'
    result = subprocess.run(
        ["bash", str(driver)],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir), "RUN_ID": run_id},
        capture_output=True,
        text=True,
    )
    records_dir = state_dir / "runs"
    files = list(records_dir.glob("*.json")) if records_dir.exists() else []
    assert files, "mutant driver did not write an outcome file at all\n" + result.stdout + result.stderr
    invalid_json = False
    for f in files:
        try:
            json.loads(f.read_text())
        except json.JSONDecodeError:
            invalid_json = True
    assert invalid_json, (
        "mutant (naive printf interpolation) was expected to produce invalid "
        "JSON for a run_id containing '\"', but the output still parsed"
    )


def test_exit_code_patched_on_reentrant_and_lock_records(tmp_path: Path, _isolated_state_dir: Path):
    """Round-1 fix, untested until now: lock_patch_outcome_exit_code. Calls
    it directly -- no hook or mutant hook needed, it's a plain lock.sh
    function. Fails-against-unfixed via the dedicated mutant test below."""
    state_dir = _isolated_state_dir
    run_id = "testrun123"
    driver = tmp_path / "patch_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{LOCK_SH}"
lock_write_outcome "" "reentrant" "{run_id}" "wrapper"
lock_patch_outcome_exit_code 3 reentrant "{run_id}" wrapper
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)], env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = outcome_records(state_dir)
    assert len(records) == 1
    assert records[0]["exit_code"] == 3


def test_mutant_broken_patch_exit_code_leaves_null(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: lock_patch_outcome_exit_code becomes a no-op. Proves
    test_exit_code_patched_on_reentrant_and_lock_records actually bites."""
    state_dir = _isolated_state_dir
    run_id = "testrun456"
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "broken_patch.sh",
        [
            (
                'lock_patch_outcome_exit_code() {\n'
                '  local exit_code="$1" lock_state="$2" run_id="$3" role="$4"\n'
                '  local state_dir path tmp\n'
                '  state_dir="$(lock_state_dir)" 2>/dev/null || return 0\n'
                '  path="$state_dir/runs/${run_id}.$$.hook-outcome.json"\n'
                '  [[ -f "$path" ]] || return 0\n'
                '  tmp="$(mktemp "${path}.XXXXXX" 2>/dev/null)" || return 0\n'
                '  if jq --argjson exit_code "$exit_code" \'.exit_code = $exit_code\' "$path" > "$tmp" 2>/dev/null; then\n'
                '    mv "$tmp" "$path"\n'
                '  else\n'
                '    rm -f "$tmp"\n'
                '  fi\n'
                '}',
                "lock_patch_outcome_exit_code() {\n  return 0\n}",
            )
        ],
    )
    driver = tmp_path / "broken_patch_driver.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
lock_write_outcome "" "reentrant" "{run_id}" "wrapper"
lock_patch_outcome_exit_code 3 reentrant "{run_id}" wrapper
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)], env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = outcome_records(state_dir)
    assert len(records) == 1
    assert records[0]["exit_code"] is None, "mutant (no-op patch) was expected to leave exit_code null"


def test_failed_outcome_write_cannot_corrupt_acquired_branch_exit_status(tmp_path: Path, _isolated_state_dir: Path):
    """Fix 2: lock_on_exit's outcome-write failure must not abort the EXIT
    trap under set -e before cleanup (rm lock.owner, flock -u, fd close)
    runs. Triggered here via a blocked runs/ path (a regular file
    pre-occupies it, so lock_write_outcome's mkdir -p fails) rather than
    missing jq -- Fix 3's acquire-time jq preflight would otherwise
    intercept a jq-absent scenario before lock_on_exit ever runs, making
    that trigger unreachable for this specific fix. Fails-against-unfixed
    via the dedicated mutant test below."""
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "runs").write_text("blocking file, not a directory\n")

    driver = tmp_path / "acquire_exit0.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{LOCK_SH}"
lock_acquire_or_reentrant "wrapper"
exit 0
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"expected rc=0 despite the outcome-write failure, got rc={result.returncode}\n"
        + result.stdout + result.stderr
    )
    assert not (state_dir / "lock.owner").exists()


def test_mutant_bare_outcome_write_call_corrupts_exit_status(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: lock_on_exit's outcome-write call reverted to bare (no ||
    fallback). Proves the previous test actually bites: with the runs/
    path blocked, the EXIT trap now dies under set -e before cleanup runs,
    leaving lock.owner behind."""
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "runs").write_text("blocking file, not a directory\n")

    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "bare_outcome_write.sh",
        [
            (
                '  lock_write_outcome "$exit_code" "acquired" "$LOCK_RUN_ID" "$LOCK_ROLE" \\\n'
                '    || echo "lock.sh: warning — failed to write outcome record (jq missing or write failed)" >&2\n',
                '  lock_write_outcome "$exit_code" "acquired" "$LOCK_RUN_ID" "$LOCK_ROLE"\n',
            )
        ],
    )
    driver = tmp_path / "acquire_exit0_mutant.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
lock_acquire_or_reentrant "wrapper"
exit 0
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "mutant (bare outcome-write call) was expected to corrupt a clean "
        f"exit 0 into a non-zero exit, got rc={result.returncode}\n"
        + result.stdout + result.stderr
    )
    assert (state_dir / "lock.owner").exists(), (
        "mutant (bare outcome-write call) was expected to abort before "
        "cleanup ran, leaving lock.owner behind"
    )


def test_missing_jq_on_acquire_path_fails_closed_with_diagnostic(tmp_path: Path, _isolated_state_dir: Path):
    """Fix 3: lock_acquire_or_reentrant's jq preflight, guarding
    lock_owner_write. Fails-against-unfixed via write_mutant_lock_sh
    stripping the guard (dedicated mutant test below)."""
    state_dir = _isolated_state_dir
    binshim = make_binshim(tmp_path)
    driver = tmp_path / "acquire_no_jq.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -uo pipefail
source "{LOCK_SH}"
if lock_acquire_or_reentrant "wrapper"; then
  echo "RESULT=$LOCK_RESULT"
  exit 0
else
  echo "RESULT=$LOCK_RESULT"
  exit 1
fi
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)],
        env={"PATH": str(binshim), "SANITIZER_STATE_DIR": str(state_dir), "HOME": os.environ.get("HOME", "")},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "RESULT=abort" in result.stdout
    assert "jq" in result.stderr
    assert not (state_dir / "lock.owner").exists()


def test_mutant_stripped_jq_guard_leaves_corrupt_lock_owner(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: remove the Fix 3 jq preflight. Proves the previous test
    actually bites: with jq absent and no guard, acquisition "succeeds"
    while lock_owner_write silently produces an empty lock.owner."""
    state_dir = _isolated_state_dir
    binshim = make_binshim(tmp_path)
    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "no_jq_guard.sh",
        [
            (
                '    # lock_owner_write is jq-based and unguarded below. Because this\n'
                "    # function's body runs with `set -e` suspended (see the NOTE above), a\n"
                '    # missing jq there would NOT abort -- it would silently leave lock.owner\n'
                '    # as an empty file while this branch still reports "acquired" and\n'
                "    # returns 0. A legitimate reentrant descendant then reads that empty\n"
                "    # file, gets no run_id match, and gets spuriously rejected with\n"
                "    # HOOK_ABORT_LOCK -- with no diagnostic anywhere naming jq as the cause\n"
                "    # (found via round-2 stress-test, round-3 fix pass on issue #3). Guard\n"
                "    # explicitly here, before the write, and fail closed with a named\n"
                "    # reason rather than let the corruption happen silently.\n"
                '    if ! command -v jq >/dev/null 2>&1; then\n'
                '      echo "lock.sh: jq is required but not found on PATH" >&2\n'
                '      LOCK_RUN_ID="${SANITIZER_RUN_ID:-unknown}"\n'
                '      LOCK_ROLE="$role"\n'
                '      LOCK_STATE="LOCK"\n'
                '      LOCK_RESULT="abort"\n'
                '      eval "exec ${LOCK_FD}>&-" 2>/dev/null || true\n'
                '      return 1\n'
                '    fi\n\n',
                "",
            )
        ],
    )
    driver = tmp_path / "acquire_no_jq_mutant.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -uo pipefail
source "{mutant_lock_sh}"
lock_acquire_or_reentrant "wrapper" || true
echo "RESULT=$LOCK_RESULT"
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)],
        env={"PATH": str(binshim), "SANITIZER_STATE_DIR": str(state_dir), "HOME": os.environ.get("HOME", "")},
        capture_output=True,
        text=True,
    )
    assert "RESULT=acquired" in result.stdout, (
        "mutant (jq guard stripped) was expected to report acquired despite "
        "missing jq\n" + result.stdout + result.stderr
    )
    owner_path = state_dir / "lock.owner"
    owner_ok = owner_path.exists() and owner_path.stat().st_size > 0
    if owner_ok:
        try:
            json.loads(owner_path.read_text())
        except json.JSONDecodeError:
            owner_ok = False
    assert not owner_ok, (
        "mutant (jq guard stripped) was expected to leave lock.owner "
        "missing, empty, or corrupt (jq write silently failed) -- got a "
        "valid, complete lock.owner instead"
    )


@pytest.mark.parametrize("dir_kind", ["real", "symlink"])
def test_lock_close_all_lock_fds_closes_under_symlinked_state_dir(
    tmp_path: Path, dir_kind: str, monkeypatch: pytest.MonkeyPatch
):
    """Fix 4: lock_close_all_lock_fds canonicalizes the lock path before
    comparing against /proc fd targets, so it closes the fd under a
    symlinked SANITIZER_STATE_DIR too. Observation must match
    lock_close_all_lock_fds's own mechanism -- it scans /proc/$BASHPID/fd
    from inside the subshell it runs in, so the subshell itself reports
    whether its own fd is still open, rather than the parent inspecting
    its own (unrelated) /proc/$$/fd afterward."""
    real_dir = tmp_path / "real-state"
    real_dir.mkdir(parents=True, exist_ok=True)
    if dir_kind == "symlink":
        state_dir = tmp_path / "symlinked-state"
        state_dir.symlink_to(real_dir)
    else:
        state_dir = real_dir
    monkeypatch.setenv("SANITIZER_STATE_DIR", str(state_dir))
    monkeypatch.delenv("SANITIZER_RUN_ID", raising=False)
    assert_state_dir_isolated(real_dir)

    result_file = tmp_path / f"fdresult_{dir_kind}.txt"
    driver = tmp_path / f"symlink_driver_{dir_kind}.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{LOCK_SH}"
lock_acquire_or_reentrant "wrapper"
(
  lock_close_all_lock_fds
  if [[ -e "/proc/$BASHPID/fd/$LOCK_FD" ]]; then
    echo "STILL_OPEN" > "{result_file}"
  else
    echo "CLOSED" > "{result_file}"
  fi
)
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)], env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result_file.read_text().strip() == "CLOSED", (
        f"lock_close_all_lock_fds failed to close the fd under a {dir_kind} state dir"
    )


def test_mutant_uncanonicalized_lock_path_leaves_fd_open_under_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Mutant: restore the pre-Fix-4 uncanonicalized lock path comparison.
    Proves the previous test actually bites -- under a symlinked state
    dir, the fd stays open because the comparison never matches."""
    real_dir = tmp_path / "real-state"
    real_dir.mkdir(parents=True, exist_ok=True)
    state_dir = tmp_path / "symlinked-state"
    state_dir.symlink_to(real_dir)
    monkeypatch.setenv("SANITIZER_STATE_DIR", str(state_dir))
    monkeypatch.delenv("SANITIZER_RUN_ID", raising=False)
    assert_state_dir_isolated(real_dir)

    mutant_lock_sh = write_mutant_lock_sh(
        tmp_path,
        "uncanonicalized_lock_path.sh",
        [
            (
                'lock_close_all_lock_fds() {\n'
                '  local raw_lock_path lock_path\n'
                '  raw_lock_path="$(lock_state_dir)/lock" 2>/dev/null || return 0\n'
                "  # Canonicalize before comparing against the /proc fd targets below, which\n"
                "  # are themselves canonicalized via readlink -f (L110-ish). Without this, a\n"
                "  # symlinked SANITIZER_STATE_DIR makes the two paths never match, so the\n"
                "  # loop closes nothing and this fix silently no-ops (found via round-2\n"
                "  # stress-test, round-3 fix pass on issue #3).\n"
                '  lock_path="$(readlink -f "$raw_lock_path")" 2>/dev/null || return 0\n'
                "  local fd_path fd target",
                'lock_close_all_lock_fds() {\n'
                '  local lock_path\n'
                '  lock_path="$(lock_state_dir)/lock" 2>/dev/null || return 0\n'
                "  local fd_path fd target",
            )
        ],
    )
    result_file = tmp_path / "fdresult_mutant.txt"
    driver = tmp_path / "symlink_driver_mutant.sh"
    driver.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
source "{mutant_lock_sh}"
lock_acquire_or_reentrant "wrapper"
(
  lock_close_all_lock_fds
  if [[ -e "/proc/$BASHPID/fd/$LOCK_FD" ]]; then
    echo "STILL_OPEN" > "{result_file}"
  else
    echo "CLOSED" > "{result_file}"
  fi
)
"""
    )
    driver.chmod(0o755)
    result = subprocess.run(
        ["bash", str(driver)], env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result_file.read_text().strip() == "STILL_OPEN", (
        "mutant (uncanonicalized lock path) was expected to leave the fd "
        "open under a symlinked state dir"
    )


SECRET_CONTENT = "AKIAIOSFODNN7EXAMPLE\n"


def test_target_repo_gitleaks_toml_cannot_weaken_gate(tmp_path: Path, _isolated_state_dir: Path):
    """Fix 1, vector 1: a permissive .gitleaks.toml planted in the target
    repo must not suppress detection -- --config pins resolution to this
    sanitizer repo's own file. Fails-against-unfixed via reverting the
    --config flag."""
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    (repo / ".gitleaks.toml").write_text(
        '[extend]\nuseDefault = false\n[[rules]]\nid = "never-matches"\nregex = "zzz-does-not-exist-zzz"\n'
    )
    subprocess.run(["git", "add", ".gitleaks.toml"], cwd=repo, check=True)
    stage_file(repo, "secret.txt", SECRET_CONTENT)

    result = commit(repo, "planted secret + permissive config", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 0
    assert "BLOCKED: gitleaks found a likely secret" in (result.stdout + result.stderr)


@pytest.mark.parametrize("tracking", ["untracked", "staged"])
def test_target_repo_gitleaksignore_cannot_weaken_gate(tmp_path: Path, _isolated_state_dir: Path, tracking: str):
    """Round-3 CODE review (reviewers 1+3, independently): Stage 0.5's
    original form checked only `git diff --cached --name-only`, so an
    UNTRACKED (or previously-committed) .gitleaksignore was entirely
    invisible to it -- reproduced committing a real AWS-shaped key while
    that older Stage 0.5 was in place. Stage 0.5 now checks the filesystem
    directly, covering both cases. Note this is policy enforcement, not
    the security control: under the current dir-mode scan (see Stage 1),
    a target-repo .gitleaksignore cannot actually suppress a finding
    regardless of Stage 0.5 (its fingerprint is tied to the ephemeral
    per-run mktemp scan path, unguessable in advance, and the file is
    never materialized into the scan dir) -- see the dedicated mutant test
    below for what Stage 0.5's removal actually changes."""
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    stage_file(repo, "secret.txt", SECRET_CONTENT)
    (repo / ".gitleaksignore").write_text("secret.txt:aws-access-token-reanchored:1\n")
    if tracking == "staged":
        subprocess.run(["git", "add", ".gitleaksignore"], cwd=repo, check=True)

    result = commit(repo, f"planted secret + {tracking} gitleaksignore", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 0
    assert "BLOCKED: this repo has a .gitleaksignore file" in (result.stdout + result.stderr)


def test_mutant_no_gitleaksignore_check_lets_ignore_file_get_committed(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: remove Stage 0.5's .gitleaksignore check from the hook.

    Measured directly: Stage 1's dir-mode scan is NOT fooled by a
    target-repo .gitleaksignore even with Stage 0.5 removed -- gitleaks'
    dir-mode fingerprint includes the scanned path argument
    (`<mktemp-path>/secret.txt:rule:line`), which changes on every single
    invocation, so a .gitleaksignore entry can never be pre-computed to
    match it, and the target file is never materialized into the scan dir
    regardless. So Stage 0.5's real, narrower purpose is proven here
    instead: without it, a .gitleaksignore is free to land in the target
    repo's committed history -- which matters for OTHER tooling (e.g. a
    later bin/gitleaks-gate.sh pass over the synced mirror, which resolves
    ignore files from ITS OWN cwd/target, not an ephemeral per-commit
    path) even though this hook's own gate isn't fooled by it."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "no_gitleaksignore_check.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            (
                "# --- Stage 0.5: refuse a target-repo .gitleaksignore outright ---\n"
                "# Defense in depth, not the primary control (Stage 1's blob-materialization\n"
                "# below is what actually keeps gitleaks from ever seeing a target-repo\n"
                "# .gitleaksignore) -- but still worth refusing on principle, so one never\n"
                "# lands in a synced repo's history where a LATER, differently-invoked\n"
                "# gitleaks pass (e.g. bin/gitleaks-gate.sh scanning the built mirror) might\n"
                "# honor it. Checks the actual FILESYSTEM, not `git diff --cached` -- an\n"
                "# earlier version of this check inspected only staged filenames, which (a)\n"
                "# never sees an untracked or previously-committed .gitleaksignore, and (b)\n"
                "# piped `git diff --cached --name-only | grep -q`, which SIGPIPEs `git`\n"
                "# once the staged file list exceeds one pipe buffer, and under `set -o\n"
                "# pipefail` that silently skips the whole check (both measured empirically,\n"
                "# round-3 CODE review). A plain existence check has neither problem, and a\n"
                "# `git rm` that deletes the file (no longer present on disk by hook time)\n"
                "# is correctly allowed through.\n"
                'REPO_TOPLEVEL="$(git rev-parse --show-toplevel)"\n'
                'if [[ -e "$REPO_TOPLEVEL/.gitleaksignore" ]]; then\n'
                "  echo\n"
                '  echo "BLOCKED: this repo has a .gitleaksignore file (tracked, untracked, or"\n'
                '  echo "committed earlier -- doesn\'t matter which). This sanitizer repo never"\n'
                '  echo "honors one; remove it. (Stage 1 below doesn\'t even look at it, but a"\n'
                '  echo "later scan of the synced mirror by other tooling might.)"\n'
                "  exit 1\n"
                "fi\n\n",
                "",
            ),
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    stage_file(repo, "clean.txt", "hello\n")
    (repo / ".gitleaksignore").write_text("secret.txt:aws-access-token-reanchored:1\n")
    subprocess.run(["git", "add", ".gitleaksignore"], cwd=repo, check=True)

    result = commit(
        repo, "gitleaksignore committed, mutant hook", env={"SANITIZER_STATE_DIR": str(state_dir)}
    )

    assert result.returncode == 0, (
        "mutant (Stage 0.5 check removed) was expected to allow a "
        ".gitleaksignore to be committed\n" + result.stdout + result.stderr
    )
    show = subprocess.run(
        ["git", "show", "HEAD:.gitleaksignore"], cwd=repo, capture_output=True, text=True
    )
    assert show.returncode == 0, ".gitleaksignore was expected to be present in the resulting commit"


def test_target_repo_gitattributes_cannot_suppress_diff_scan(tmp_path: Path, _isolated_state_dir: Path):
    """Round-3 CODE review (reviewer 2, RESTRUCTURE): `gitleaks protect
    --staged` scans git's own textual diff, and a staged `.gitattributes`
    entry with `-diff` makes git treat a file as binary -- the diff for it
    is empty, so the old mechanism scanned nothing. Stage 1 now
    materializes actual staged blob content via `git show`, sidestepping
    git's diff/attribute machinery entirely. Fails-against-unfixed via the
    dedicated mutant test below (revert to the old protect --staged form)."""
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    stage_file(repo, "secret.txt", SECRET_CONTENT)
    (repo / ".gitattributes").write_text("secret.txt -diff\n")
    subprocess.run(["git", "add", ".gitattributes"], cwd=repo, check=True)

    result = commit(repo, "planted secret + gitattributes -diff", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 0
    assert "BLOCKED: gitleaks found a likely secret" in (result.stdout + result.stderr)


def test_mutant_diff_based_scan_misses_gitattributes_suppressed_secret(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: revert Stage 1 to the pre-restructure `gitleaks protect
    --staged` form (scans git's textual diff, not materialized blob
    content). Proves the previous test actually bites -- with the old
    mechanism, a `.gitattributes -diff` entry blanks the diff and the
    secret goes undetected."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "diff_based_scan.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            (
                'materialize_staged() {\n'
                '  local scan_dir="$1"\n'
                '  # This function\'s ONLY call site is `counts="$(materialize_staged\n'
                '  # "$scan_dir")"` below -- a command-substitution `$(...)`, which ALWAYS\n'
                '  # forks a fresh subshell to run it. So $BASHPID here is never the main\n'
                "  # hook process's own pid, and lock_close_all_lock_fds is safe to call\n"
                '  # directly (see bin/lib/lock.sh: it must NEVER be called directly in the\n'
                "  # main process's own shell -- this isn't that). Closing it FIRST, before\n"
                '  # the mkdir/git show loop below ever forks anything, closes this\n'
                "  # subshell's own inherited duplicate of the lock fd immediately -- so\n"
                '  # mkdir/git show (and everything else in this function) never inherit it\n'
                '  # either, without needing to wrap each one in its own subshell. Without\n'
                '  # this, the command-substitution subshell itself keeps an open duplicate\n'
                "  # of the lock fd for this function's entire runtime regardless of\n"
                "  # anything gitleaks's own subshell does later, and a hung `git show`\n"
                '  # (e.g. a corrupt/locked object store) orphaned by a hook crash would\n'
                "  # hold the flock past this hook's own exit (measured empirically: a\n"
                '  # per-iteration `( lock_close_all_lock_fds; mkdir && git show )` subshell\n'
                '  # closes ITS OWN copy correctly but leaves the enclosing\n'
                "  # command-substitution subshell's copy open the whole time -- that\n"
                '  # subshell surviving a hook crash was what actually kept the lock held).\n'
                '  # If this function is ever called any other way (not via `$(...)`), this\n'
                "  # call must move to wrap the loop body's fork instead.\n"
                '  lock_close_all_lock_fds\n'
                '  local f\n'
                '  local staged_count=0\n'
                '  local materialized_count=0\n'
                "  while IFS= read -r -d '' f; do\n"
                '    # Never materialize a target-repo .gitleaksignore into the scan dir --\n'
                '    # gitleaks would auto-discover and honor it sitting right there,\n'
                '    # reopening the exact vector this rewrite exists to close. Excluded\n'
                '    # from both counts -- it is deliberately never materialized.\n'
                '    case "$f" in\n'
                '      .gitleaksignore|*/.gitleaksignore) continue ;;\n'
                '    esac\n'
                '    staged_count=$((staged_count + 1))\n'
                '    if mkdir -p "$scan_dir/$(dirname "$f")" && git show ":$f" > "$scan_dir/$f" 2>/dev/null; then\n'
                '      materialized_count=$((materialized_count + 1))\n'
                '    else\n'
                '      rm -f "$scan_dir/$f"\n'
                '    fi\n'
                '  done < <(git diff --cached --name-only --diff-filter=ACMRT -z)\n'
                '  echo "$staged_count $materialized_count"\n'
                '}\n'
                '\n'
                'run_gitleaks() {\n'
                '  local scan_dir\n'
                '  scan_dir="$(mktemp -d)" || return 1\n'
                '\n'
                '  # Compose our scan_dir cleanup onto whatever EXIT trap is already\n'
                "  # installed (lock.sh's `lock_on_exit` on the acquired branch; this\n"
                "  # hook's own `lock_patch_outcome_exit_code` wrapper on the\n"
                '  # reentrant/abort branches) rather than replacing it outright -- bash\n'
                '  # has exactly one EXIT trap slot, and a bare `trap ... EXIT` here would\n'
                '  # silently clobber the lock-release trap instead of composing with it.\n'
                '  # `trap -p EXIT` captures whatever is currently installed there (empty\n'
                '  # if nothing is) so it can be chained. This closes the gap where a\n'
                '  # SIGINT/SIGTERM during a slow gitleaks run left the materialized\n'
                '  # staged-blob contents (i.e. exactly the secrets under scan) sitting\n'
                '  # under $TMPDIR indefinitely -- previously cleanup only ran on this\n'
                "  # function's own normal-return path below, never on a\n"
                '  # signal-interrupted exit of the whole hook process.\n'
                '  local prior_exit_trap\n'
                '  prior_exit_trap="$(trap -p EXIT)"\n'
                '  prior_exit_trap="${prior_exit_trap#trap -- \\\'}"\n'
                '  prior_exit_trap="${prior_exit_trap%\\\' EXIT}"\n'
                "  # $scan_dir is intentionally expanded NOW (this function's own `local`\n"
                '  # scope), not at trap-fire time -- by the time this trap could fire, the\n'
                '  # local variable may no longer be in scope at all.\n'
                '  trap "rm -rf \'$scan_dir\'; $prior_exit_trap" EXIT\n'
                '\n'
                '  local counts staged_count materialized_count\n'
                '  counts="$(materialize_staged "$scan_dir")"\n'
                '  staged_count="${counts% *}"\n'
                '  materialized_count="${counts#* }"\n'
                '  if [[ "$staged_count" -ne "$materialized_count" ]]; then\n'
                '    echo "materialize_staged: only $materialized_count/$staged_count staged files were" >&2\n'
                '    echo "materialized into the scan dir (a mkdir or git show failed on at least one" >&2\n'
                '    echo "staged path) -- refusing to scan an incomplete set." >&2\n'
                '    trap "$prior_exit_trap" EXIT\n'
                '    rm -rf "$scan_dir"\n'
                '    return 8\n'
                '  fi\n'
                '  ( lock_close_all_lock_fds\n'
                '    exec "$GITLEAKS_BIN" dir "$scan_dir" --redact --no-banner \\\n'
                '      --config "$SANITIZER_REPO_ROOT/.gitleaks.toml" \\\n'
                '      --ignore-gitleaks-allow \\\n'
                '      --exit-code 7 )\n'
                '  local rc=$?\n'
                '  trap "$prior_exit_trap" EXIT\n'
                '  rm -rf "$scan_dir"\n'
                '  return $rc\n'
                '}',
                "run_gitleaks() {\n"
                "  ( lock_close_all_lock_fds\n"
                '    exec "$GITLEAKS_BIN" protect --staged --redact --no-banner \\\n'
                '      --config "$SANITIZER_REPO_ROOT/.gitleaks.toml" \\\n'
                "      --ignore-gitleaks-allow \\\n"
                "      --exit-code 7 )\n"
                "}",
            ),
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    stage_file(repo, "secret.txt", SECRET_CONTENT)
    (repo / ".gitattributes").write_text("secret.txt -diff\n")
    subprocess.run(["git", "add", ".gitattributes"], cwd=repo, check=True)

    result = commit(
        repo, "planted secret + gitattributes -diff, mutant hook", env={"SANITIZER_STATE_DIR": str(state_dir)}
    )

    assert result.returncode == 0, (
        "mutant (diff-based scan) was expected to miss a .gitattributes "
        "-diff-suppressed secret\n" + result.stdout + result.stderr
    )


def test_target_repo_gitleaks_allow_comment_cannot_weaken_gate(tmp_path: Path, _isolated_state_dir: Path):
    """Fix 1, vector 3: an inline `# gitleaks:allow` comment must not
    suppress detection -- --ignore-gitleaks-allow disables it entirely.
    Fails-against-unfixed via reverting the --ignore-gitleaks-allow flag."""
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    stage_file(repo, "secret.txt", "AKIAIOSFODNN7EXAMPLE # gitleaks:allow\n")

    result = commit(repo, "planted secret with inline allow", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 0
    assert "BLOCKED: gitleaks found a likely secret" in (result.stdout + result.stderr)


def test_missing_config_reported_as_tool_failure_not_secret(tmp_path: Path, _isolated_state_dir: Path):
    """Fix 1: --exit-code 7 discrimination. A mutant hook keeps
    hooks/pre-commit:32's guard and the source line resolving to the REAL
    SANITIZER_REPO_ROOT (a literal path substitution, not left to
    self-resolve from the mutant's own tmp_path location -- otherwise the
    guard aborts before Stage 1 runs at all) and separately breaks only the
    --config argument value passed to run_gitleaks. Fails-against-unfixed
    via dropping --exit-code 7 and the two-branch discrimination."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "bad_config_path.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            (
                '--config "$SANITIZER_REPO_ROOT/.gitleaks.toml" \\',
                '--config "/nonexistent/gitleaks-mutant.toml" \\',
            ),
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    stage_file(repo, "f.txt", "hello\n")

    result = commit(repo, "should hit tool failure", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0
    assert commit_count(repo) == 0
    output = result.stdout + result.stderr
    assert "gitleaks failed to run" in output
    assert "found a likely secret" not in output


# --------------------------------------------------------------------------
# Round-3 fix pass P0/P1 (issue #3) -- typechange bypass + materialization
# completeness check.
# --------------------------------------------------------------------------


def stage_symlink_typechange_with_secret(repo: Path, filename: str, secret_content: str) -> None:
    """Commits `filename` as a symlink, then stages a typechange swap to a
    regular file carrying `secret_content` -- exactly the shape fix P0
    exists to catch (a staged symlink->regular-file swap, git status 'T',
    excluded by the pre-fix --diff-filter=ACMR)."""
    target = repo / f"{filename}.target"
    target.write_text("harmless\n")
    subprocess.run(["git", "add", target.name], cwd=repo, check=True)
    link = repo / filename
    link.symlink_to(target.name)
    subprocess.run(["git", "add", filename], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", f"add {filename} as symlink"], cwd=repo, check=True)

    link.unlink()
    link.write_text(secret_content)
    subprocess.run(["git", "add", filename], cwd=repo, check=True)

    status = subprocess.run(
        ["git", "diff", "--cached", "--name-status"], cwd=repo, capture_output=True, text=True
    )
    assert status.stdout.strip().startswith("T"), (
        f"test setup did not produce a staged typechange for {filename}: {status.stdout}"
    )


def test_staged_typechange_symlink_to_regular_with_secret_is_caught(tmp_path: Path, _isolated_state_dir: Path):
    """Fix P0: --diff-filter changed from ACMR to ACMRT. A staged
    symlink->regular-file typechange previously bypassed materialize_staged
    entirely (git's 'T' status is excluded by ACMR), so a secret introduced
    via such a swap was never even listed, let alone scanned. Reproduced
    here with a real AWS-access-key-shaped secret; committed WITHOUT the
    hook installed first to get past git's own commit-time symlink
    handling cleanly, then re-verified with the hook."""
    state_dir = _isolated_state_dir
    repo = make_repo(tmp_path, "repo")
    install_hook(repo)
    env = {"SANITIZER_STATE_DIR": str(state_dir)}

    stage_symlink_typechange_with_secret(repo, "f.txt", SECRET_CONTENT)
    assert commit_count(repo) == 1  # only the symlink-add commit so far

    result = commit(repo, "typechange with secret", env=env)

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 1  # the typechange commit must NOT have landed
    assert "BLOCKED: gitleaks found a likely secret" in (result.stdout + result.stderr)


def test_mutant_acmr_diff_filter_misses_typechange_secret(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: revert --diff-filter=ACMRT back to the pre-fix ACMR. Proves
    the previous test actually bites -- with ACMR, the typechange swap
    never appears in materialize_staged's file list at all, so the secret
    is never scanned and the commit is allowed through."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "acmr_diff_filter.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            (
                "--diff-filter=ACMRT -z)",
                "--diff-filter=ACMR -z)",
            ),
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    env = {"SANITIZER_STATE_DIR": str(state_dir)}

    stage_symlink_typechange_with_secret(repo, "f.txt", SECRET_CONTENT)
    assert commit_count(repo) == 1

    result = commit(repo, "typechange with secret, mutant filter", env=env)

    assert result.returncode == 0, (
        "mutant (ACMR diff-filter) was expected to let a typechange-carried "
        "secret bypass detection entirely\n" + result.stdout + result.stderr
    )
    assert commit_count(repo) == 2


# A real, uncontrived git-show failure (e.g. a racing external process
# corrupting the index, an OS-level read error, disk pressure during
# `mkdir -p`) can't be reliably forced from a test without mutating hook
# code -- git prepends its own git-core dir to PATH before invoking hooks
# (verified empirically: a `git`-shimming PATH override is invisible to
# every git call the hook itself makes, only the outer `git commit`
# invocation sees it), so a PATH-based `git show` shim cannot intercept
# materialize_staged's internal call. INJECT_GAP_REPLACEMENT instead forces
# a materialization failure for one specific staged filename ("gap.txt")
# directly in a copy of materialize_staged's own git-show line -- a
# targeted, realistic simulation of the exact failure fix P1 exists to
# catch, without touching the completeness-check logic under test.
INJECT_GAP_REPLACEMENT = (
    'if mkdir -p "$scan_dir/$(dirname "$f")" && git show ":$f" > "$scan_dir/$f" 2>/dev/null; then',
    'if [[ "$f" != "gap.txt" ]] && mkdir -p "$scan_dir/$(dirname "$f")" && git show ":$f" > "$scan_dir/$f" 2>/dev/null; then',
)


def test_materialization_gap_hard_fails_commit_not_silently_scans_partial_set(
    tmp_path: Path, _isolated_state_dir: Path
):
    """Fix P1: run_gitleaks hard-fails the whole commit on any
    staged/materialized count mismatch rather than silently scanning an
    incomplete set. gap.txt itself carries no secret -- if the gap were
    NOT caught, gitleaks would scan a dir missing gap.txt, report clean,
    and the commit would wrongly succeed despite materialize_staged having
    failed on a staged file (the P1 gap: `mkdir`/`git show` failures were
    previously `|| true`-swallowed with no completeness check at all)."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "inject_materialization_gap.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            INJECT_GAP_REPLACEMENT,
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    stage_file(repo, "gap.txt", "harmless content, no secret here\n")
    stage_file(repo, "other.txt", "also harmless\n")

    result = commit(repo, "should hard-fail on materialization gap", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode != 0, result.stdout + result.stderr
    assert commit_count(repo) == 0
    output = result.stdout + result.stderr
    assert "staged-file materialization was incomplete" in output
    assert "found a likely secret" not in output


def test_mutant_no_completeness_check_lets_materialization_gap_through(
    tmp_path: Path, _isolated_state_dir: Path
):
    """Mutant: on top of the same forced gap.txt materialization failure,
    also strip the staged/materialized count comparison from run_gitleaks
    (revert to unconditionally scanning whatever materialize_staged
    happened to produce). Proves the previous test's hard-fail actually
    bites, not just the injected gap -- with the check gone, the exact
    same gap now lets the commit through silently."""
    state_dir = _isolated_state_dir
    mutant_hook = write_mutant_hook(
        tmp_path,
        "no_completeness_check.sh",
        LOCK_SH,
        [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            INJECT_GAP_REPLACEMENT,
            (
                'run_gitleaks() {\n'
                '  local scan_dir\n'
                '  scan_dir="$(mktemp -d)" || return 1\n'
                '\n'
                '  # Compose our scan_dir cleanup onto whatever EXIT trap is already\n'
                "  # installed (lock.sh's `lock_on_exit` on the acquired branch; this\n"
                "  # hook's own `lock_patch_outcome_exit_code` wrapper on the\n"
                '  # reentrant/abort branches) rather than replacing it outright -- bash\n'
                '  # has exactly one EXIT trap slot, and a bare `trap ... EXIT` here would\n'
                '  # silently clobber the lock-release trap instead of composing with it.\n'
                '  # `trap -p EXIT` captures whatever is currently installed there (empty\n'
                '  # if nothing is) so it can be chained. This closes the gap where a\n'
                '  # SIGINT/SIGTERM during a slow gitleaks run left the materialized\n'
                '  # staged-blob contents (i.e. exactly the secrets under scan) sitting\n'
                '  # under $TMPDIR indefinitely -- previously cleanup only ran on this\n'
                "  # function's own normal-return path below, never on a\n"
                '  # signal-interrupted exit of the whole hook process.\n'
                '  local prior_exit_trap\n'
                '  prior_exit_trap="$(trap -p EXIT)"\n'
                '  prior_exit_trap="${prior_exit_trap#trap -- \\\'}"\n'
                '  prior_exit_trap="${prior_exit_trap%\\\' EXIT}"\n'
                "  # $scan_dir is intentionally expanded NOW (this function's own `local`\n"
                '  # scope), not at trap-fire time -- by the time this trap could fire, the\n'
                '  # local variable may no longer be in scope at all.\n'
                '  trap "rm -rf \'$scan_dir\'; $prior_exit_trap" EXIT\n'
                '\n'
                '  local counts staged_count materialized_count\n'
                '  counts="$(materialize_staged "$scan_dir")"\n'
                '  staged_count="${counts% *}"\n'
                '  materialized_count="${counts#* }"\n'
                '  if [[ "$staged_count" -ne "$materialized_count" ]]; then\n'
                '    echo "materialize_staged: only $materialized_count/$staged_count staged files were" >&2\n'
                '    echo "materialized into the scan dir (a mkdir or git show failed on at least one" >&2\n'
                '    echo "staged path) -- refusing to scan an incomplete set." >&2\n'
                '    trap "$prior_exit_trap" EXIT\n'
                '    rm -rf "$scan_dir"\n'
                '    return 8\n'
                '  fi\n'
                '  ( lock_close_all_lock_fds\n'
                '',
                "run_gitleaks() {\n"
                "  local scan_dir\n"
                '  scan_dir="$(mktemp -d)" || return 1\n'
                "  local prior_exit_trap=\"\"\n"
                '  materialize_staged "$scan_dir" >/dev/null\n'
                "  ( lock_close_all_lock_fds\n",
            ),
        ],
    )
    repo = make_repo(tmp_path, "repo")
    install_hook(repo, hook_src=mutant_hook)
    stage_file(repo, "gap.txt", "harmless content, no secret here\n")
    stage_file(repo, "other.txt", "also harmless\n")

    result = commit(repo, "materialization gap, mutant hook", env={"SANITIZER_STATE_DIR": str(state_dir)})

    assert result.returncode == 0, (
        "mutant (no completeness check) was expected to silently scan the "
        "incomplete set and let the commit through\n" + result.stdout + result.stderr
    )
    assert commit_count(repo) == 1


# --------------------------------------------------------------------------
# Issue #11 item 1 -- trap-protected scan_dir cleanup on SIGINT.
# --------------------------------------------------------------------------


def _write_slow_gitleaks_hook(
    tmp_path: Path, name: str, label: str, extra_replacements: list[tuple[str, str]] | None = None
) -> tuple[Path, Path]:
    """A mutant hook whose GITLEAKS_BIN points at a stand-in that blocks
    indefinitely instead of ever exiting (so a real gitleaks run can be
    reliably interrupted mid-scan), plus instrumentation that records
    scan_dir's path once mktemp'd. `extra_replacements` layers on top --
    e.g. reverting run_gitleaks's trap fix, to prove it's what matters."""
    standin = tmp_path / f"{label}_standin.sh"
    # `exec sleep 30`, not a blocking `read` -- git connects a pre-commit
    # hook's own stdin to something that always reads as EOF regardless of
    # the parent process's stdin (verified empirically: a PIPE stdin held
    # open on the `git commit` subprocess in this test does NOT reach the
    # hook), so a `read` here would return immediately instead of blocking.
    standin.write_text("#!/usr/bin/env bash\nexec sleep 30\n")
    standin.chmod(0o755)
    info_file = tmp_path / f"{label}_scan_dir.info"
    replacements = [
        (
            'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
            'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
            'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
            f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
        ),
        (
            'GITLEAKS_BIN="$HOME/.local/share/mise/installs/gitleaks/8.30.1/gitleaks"',
            f'GITLEAKS_BIN="{standin}"',
        ),
        (
            '  scan_dir="$(mktemp -d)" || return 1\n',
            '  scan_dir="$(mktemp -d)" || return 1\n' f'  echo "$scan_dir" > "{info_file}"\n',
        ),
    ]
    if extra_replacements:
        replacements.extend(extra_replacements)
    hook = write_mutant_hook(tmp_path, name, LOCK_SH, replacements)
    return hook, info_file


def _run_sigint_scan_dir_scenario(
    tmp_path: Path, state_dir: Path, hook_src: Path, info_file: Path, label: str
) -> bool:
    """Starts a real `git commit` (hook installed, real gitleaks stand-in
    blocking mid-scan), SIGINTs the whole process group like a terminal
    Ctrl-C once scan_dir exists on disk, then reports whether scan_dir
    survived the interrupted hook process."""
    repo = make_repo(tmp_path, f"repo_{label}")
    install_hook(repo, hook_src=hook_src)
    stage_file(repo, "f.txt", "hello\n")

    env = {**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}
    proc = subprocess.Popen(
        ["git", "commit", "-m", f"sigint scenario {label}"],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.time() + 10
    while not info_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert info_file.exists(), f"hook did not reach run_gitleaks in time ({label})"
    scan_dir = Path(info_file.read_text().strip())

    # Give the stand-in a moment to actually be exec'd and blocking.
    time.sleep(0.3)
    assert scan_dir.is_dir(), f"scan_dir {scan_dir} should exist while the gitleaks stand-in is running"

    os.killpg(proc.pid, signal.SIGINT)  # like a real terminal Ctrl-C on the whole foreground group
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
    time.sleep(0.3)

    return scan_dir.exists()


def test_scan_dir_removed_on_sigint_during_gitleaks(tmp_path: Path, _isolated_state_dir: Path):
    """Fix (issue #11 item 1): a SIGINT that kills the whole hook process
    group while gitleaks is still running must not leave the materialized
    staged-blob scan_dir (i.e. the secrets under scan) behind under
    $TMPDIR. Exercises the real, shipped run_gitleaks trap-composition
    logic unmodified -- only GITLEAKS_BIN is swapped for a stand-in that
    blocks instead of ever exiting."""
    state_dir = _isolated_state_dir
    hook, info_file = _write_slow_gitleaks_hook(tmp_path, "slow_gitleaks_good.sh", "good_sigint")

    survived = _run_sigint_scan_dir_scenario(tmp_path, state_dir, hook, info_file, "good_sigint")

    assert not survived, (
        "scan_dir should have been removed by the composed EXIT trap when "
        "the hook process was SIGINT'd mid-scan"
    )


def test_mutant_no_trap_leaves_scan_dir_after_sigint(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: revert run_gitleaks to the pre-fix shape (a plain `rm -rf
    "$scan_dir"` only at the very end of the function, no EXIT trap at
    all). Proves the previous test actually bites -- without the trap, a
    SIGINT mid-scan leaves scan_dir (containing the materialized staged
    secrets) behind under $TMPDIR indefinitely."""
    state_dir = _isolated_state_dir
    hook, info_file = _write_slow_gitleaks_hook(
        tmp_path,
        "slow_gitleaks_bad.sh",
        "bad_sigint",
        extra_replacements=[
            (
                "  local prior_exit_trap\n"
                '  prior_exit_trap="$(trap -p EXIT)"\n'
                "  prior_exit_trap=\"${prior_exit_trap#trap -- \\'}\"\n"
                "  prior_exit_trap=\"${prior_exit_trap%\\' EXIT}\"\n"
                "  # $scan_dir is intentionally expanded NOW (this function's own `local`\n"
                "  # scope), not at trap-fire time -- by the time this trap could fire, the\n"
                "  # local variable may no longer be in scope at all.\n"
                "  trap \"rm -rf '$scan_dir'; $prior_exit_trap\" EXIT\n",
                "",
            ),
            (
                '    trap "$prior_exit_trap" EXIT\n    rm -rf "$scan_dir"\n    return 8\n',
                '    rm -rf "$scan_dir"\n    return 8\n',
            ),
            (
                '  local rc=$?\n  trap "$prior_exit_trap" EXIT\n  rm -rf "$scan_dir"\n  return $rc\n',
                '  local rc=$?\n  rm -rf "$scan_dir"\n  return $rc\n',
            ),
        ],
    )

    survived = _run_sigint_scan_dir_scenario(tmp_path, state_dir, hook, info_file, "bad_sigint")

    assert survived, (
        "mutant (no EXIT trap, pre-fix shape) was expected to leave scan_dir "
        "behind after a SIGINT mid-scan, but it didn't -- mutant did not "
        "reproduce the intended bug"
    )


# --------------------------------------------------------------------------
# Issue #11 item 2 -- materialize_staged's own forked children (mkdir, git
# show) must not inherit an open lock fd either.
# --------------------------------------------------------------------------


def test_materialize_staged_children_do_not_inherit_lock_fd(tmp_path: Path, _isolated_state_dir: Path):
    """Fix (issue #11 item 2): materialize_staged's forked children (mkdir,
    git show) must not inherit an open lock fd either -- previously
    lock_close_all_lock_fds only ran in run_gitleaks's own subshell, AFTER
    materialize_staged's children had already forked. materialize_staged
    is only ever called via `$(materialize_staged ...)` command
    substitution (see run_gitleaks), which itself forks a subshell that
    inherits a duplicate of the lock fd -- the shipped fix closes that
    duplicate as materialize_staged's own first statement, before anything
    it forks can inherit it. Same shape as the existing fd-inheritance
    tests (a real hung `git show` can't be forced without mutating hook
    code -- see the comment above INJECT_GAP_REPLACEMENT): a long-running,
    uniquely-named stand-in replaces the mkdir+git-show step so it can be
    found and cleaned up afterward without touching unrelated processes;
    the hook process itself (the acquirer, in the acquired branch of a
    real `git commit`) is SIGKILLed out from under it to simulate a crash
    bypassing lock_on_exit entirely, then the lock file is probed for
    FREE/BLOCKED. (A `sleep N &` background form was tried first and
    rejected -- backgrounding inside the subshell forks an EXTRA hidden
    subshell of its own for the async job, which itself inherits an
    unclosed duplicate of the lock fd and produces a false BLOCKED
    regardless of the fix; a plain foreground `sleep N` matches the fork
    depth of the real mkdir/git-show call exactly.)"""
    state_dir = _isolated_state_dir
    state_dir.mkdir(parents=True, exist_ok=True)

    materialize_anchor_old = (
        'if mkdir -p "$scan_dir/$(dirname "$f")" && git show ":$f" > "$scan_dir/$f" 2>/dev/null; then'
    )
    close_call_old = "  lock_close_all_lock_fds\n  local f\n"
    close_call_removed = "  local f\n"

    def run_scenario(close_fd: bool, label: str) -> bool:
        pid_file = tmp_path / f"{label}_hook.pid"
        # A distinctive, unlikely-to-collide duration so the stand-in
        # process can be found and killed afterward via `pgrep -f` without
        # risking a match against an unrelated `sleep` elsewhere on the
        # machine.
        duration = f"29.{abs(hash(label)) % 900000 + 100000}"
        materialize_anchor_new = f"if sleep {duration}; then"

        replacements = [
            (
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                'SANITIZER_REPO_ROOT="$(dirname "$(dirname "$HOOK_SRC")")"',
                'HOOK_SRC="$(readlink -f "${BASH_SOURCE[0]}")"\n'
                f'SANITIZER_REPO_ROOT="{REPO_ROOT}"',
            ),
            (
                'source "$SANITIZER_REPO_ROOT/bin/lib/lock.sh"',
                'source "$SANITIZER_REPO_ROOT/bin/lib/lock.sh"\n' f'echo $$ > "{pid_file}"',
            ),
            (materialize_anchor_old, materialize_anchor_new),
        ]
        if not close_fd:
            # Pre-fix shape: strip the lock_close_all_lock_fds call this
            # fix adds at the top of materialize_staged, reproducing the
            # original bug.
            replacements.append((close_call_old, close_call_removed))

        hook = write_mutant_hook(tmp_path, f"materialize_fd_{label}.sh", LOCK_SH, replacements)

        repo = make_repo(tmp_path, f"repo_{label}")
        install_hook(repo, hook_src=hook)
        stage_file(repo, "f.txt", "hello\n")

        env = {**os.environ, "SANITIZER_STATE_DIR": str(state_dir)}
        proc = subprocess.Popen(
            ["git", "commit", "-m", f"fd inheritance scenario {label}"],
            cwd=repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        deadline = time.time() + 10
        while not pid_file.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert pid_file.exists(), f"hook failed to start in time ({label})"
        hook_pid = int(pid_file.read_text().strip())

        # Give materialize_staged a moment to actually reach and fork the
        # stand-in `sleep` before we crash the hook process out from
        # under it.
        time.sleep(0.3)

        os.kill(hook_pid, signal.SIGKILL)  # simulate a crash, bypassing lock_on_exit entirely
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(0.3)

        probe = subprocess.run(
            ["bash", "-c", f'exec {{FD}}>"{state_dir}/lock"; flock -n "$FD" && echo FREE || echo BLOCKED'],
            capture_output=True,
            text=True,
        )
        subprocess.run(["pkill", "-9", "-f", f"sleep {duration}"], capture_output=True)
        return "FREE" in probe.stdout

    good_is_free = run_scenario(close_fd=True, label="good_materialize")
    (state_dir / "lock").unlink(missing_ok=True)
    bad_is_free = run_scenario(close_fd=False, label="bad_materialize")

    assert good_is_free, (
        "materialize_staged: when it closes its own inherited duplicate of "
        "the lock fd before forking children (current shipped code), a "
        "hook-process crash must still leave the lock free"
    )
    assert not bad_is_free, (
        "regression check: without materialize_staged closing its "
        "inherited lock fd, the command-substitution subshell it runs in "
        "was expected to keep the lock held even after the hook process "
        "(the acquirer) was killed"
    )


# --------------------------------------------------------------------------
# Issue #11 item 4 -- bin/gitleaks-gate.sh --config/--ignore-gitleaks-allow
# parity with hooks/pre-commit's run_gitleaks.
# --------------------------------------------------------------------------


def write_mutant_gate_sh(tmp_path: Path, name: str, replacements: list[tuple[str, str]]) -> Path:
    text = GATE_SH.read_text()
    all_replacements = [
        ('cd "$(dirname "$0")/.."', f'cd "{REPO_ROOT}"'),
        *replacements,
    ]
    for old, new in all_replacements:
        assert old in text, f"mutation anchor not found in gitleaks-gate.sh: {old!r}"
        text = text.replace(old, new, 1)
    mutant_dir = tmp_path / "mutant_gate"
    mutant_dir.mkdir(exist_ok=True)
    mutant_path = mutant_dir / name
    mutant_path.write_text(text)
    mutant_path.chmod(0o755)
    return mutant_path


def run_gitleaks_gate(
    script: Path, target: Path, state_dir: Path, run_id: str
) -> tuple[int, list[dict], subprocess.CompletedProcess]:
    result = subprocess.run(
        ["bash", str(script), str(target), run_id],
        env={**os.environ, "SANITIZER_STATE_DIR": str(state_dir)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    report_path = state_dir / "runs" / f"{run_id}.gitleaks.json"
    findings = json.loads(report_path.read_text()) if report_path.exists() else []
    return result.returncode, findings, result


def test_gitleaks_gate_catches_secret_via_repo_own_config(tmp_path: Path, _isolated_state_dir: Path):
    """Fix (issue #11 item 4): bin/gitleaks-gate.sh now pins --config to
    this repo's own .gitleaks.toml, matching hooks/pre-commit's
    run_gitleaks. A bare AWS-access-key-shaped secret is only caught by
    this repo's re-anchored rule, not gitleaks's bundled default ruleset
    (verified empirically) -- so this also proves --config resolution
    actually changes behavior here, not just parity on paper."""
    state_dir = _isolated_state_dir
    target = tmp_path / "target_good_config"
    target.mkdir()
    (target / "secret.txt").write_text(SECRET_CONTENT)

    rc, findings, result = run_gitleaks_gate(GATE_SH, target, state_dir, "good-config-run")

    assert rc == 1, result.stdout + result.stderr
    assert findings, "expected at least one finding from the repo's re-anchored rule"


def test_mutant_gitleaks_gate_without_config_misses_secret(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: revert bin/gitleaks-gate.sh to the pre-fix invocation (no
    --config, no --ignore-gitleaks-allow). Proves the previous test
    actually bites: without --config, gitleaks falls back to its own
    (target-path-.gitleaks.toml-or-)bundled-default ruleset, which does not
    catch a bare AKIAIOSFODNN7EXAMPLE the way this repo's re-anchored rule
    does (verified empirically -- see hooks/pre-commit's Stage 1
    comments)."""
    state_dir = _isolated_state_dir
    mutant = write_mutant_gate_sh(
        tmp_path,
        "no_config.sh",
        [
            (
                '  --config "$REPO_ROOT/.gitleaks.toml" \\\n  --ignore-gitleaks-allow \\\n',
                "",
            ),
        ],
    )
    target = tmp_path / "target_mutant_config"
    target.mkdir()
    (target / "secret.txt").write_text(SECRET_CONTENT)

    rc, findings, result = run_gitleaks_gate(mutant, target, state_dir, "mutant-config-run")

    assert rc == 0, (
        "mutant (gitleaks-gate.sh without --config) was expected to miss "
        "a secret only this repo's re-anchored rule catches\n" + result.stdout + result.stderr
    )
    assert not findings


def test_gitleaks_gate_catches_gitleaks_allow_suppressed_secret(tmp_path: Path, _isolated_state_dir: Path):
    """Fix (issue #11 item 4): --ignore-gitleaks-allow means an inline
    `# gitleaks:allow` comment in the target dir cannot suppress a genuine
    finding, matching hooks/pre-commit's run_gitleaks."""
    state_dir = _isolated_state_dir
    target = tmp_path / "target_allow"
    target.mkdir()
    (target / "secret.txt").write_text("AKIAIOSFODNN7EXAMPLE # gitleaks:allow\n")

    rc, findings, result = run_gitleaks_gate(GATE_SH, target, state_dir, "allow-run")

    assert rc == 1, result.stdout + result.stderr
    assert findings


def test_mutant_gitleaks_gate_without_ignore_allow_suppressed(tmp_path: Path, _isolated_state_dir: Path):
    """Mutant: revert only --ignore-gitleaks-allow (keep --config). Proves
    the previous test actually bites -- without the flag, the inline
    `# gitleaks:allow` comment suppresses the same secret and the gate
    wrongly passes."""
    state_dir = _isolated_state_dir
    mutant = write_mutant_gate_sh(
        tmp_path,
        "no_ignore_allow.sh",
        [
            (
                '  --config "$REPO_ROOT/.gitleaks.toml" \\\n  --ignore-gitleaks-allow \\\n',
                '  --config "$REPO_ROOT/.gitleaks.toml" \\\n',
            ),
        ],
    )
    target = tmp_path / "target_mutant_allow"
    target.mkdir()
    (target / "secret.txt").write_text("AKIAIOSFODNN7EXAMPLE # gitleaks:allow\n")

    rc, findings, result = run_gitleaks_gate(mutant, target, state_dir, "mutant-allow-run")

    assert rc == 0, (
        "mutant (gitleaks-gate.sh without --ignore-gitleaks-allow) was "
        "expected to let the gitleaks:allow comment suppress the "
        "secret\n" + result.stdout + result.stderr
    )
    assert not findings

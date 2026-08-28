"""tests/test_flag_unflag_lock.py — issue #10 item 2: bin/flag.sh and
bin/unflag.sh must take the sanitizer lock (bin/lib/lock.sh) before
mutating the ledger, like every other script that touches shared state.

Concurrency proof strategy: hold the lock in a background process (via the
existing Phase A test-double wrapper, tests/fixtures/test_double_wrapper.sh
-- role="wrapper"), then invoke flag.sh/unflag.sh as a genuinely separate,
non-descendant process against the SAME SANITIZER_STATE_DIR. Since
lock_acquire_or_reentrant only grants reentrancy to a descendant of the
current holder with a matching SANITIZER_RUN_ID (see bin/lib/lock.sh), a
foreign flag.sh/unflag.sh call must be flock-blocked (non-blocking `flock
-n`, so it fails fast rather than hanging) and must NOT write to the
ledger. This is deterministic -- no timing race -- and directly exercises
the real lock acquisition path added to flag.sh/unflag.sh, not a mock.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from tests.conftest import assert_state_dir_isolated

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_SH = REPO_ROOT / "bin" / "lib" / "lock.sh"
FLAG_SH = REPO_ROOT / "bin" / "flag.sh"
UNFLAG_SH = REPO_ROOT / "bin" / "unflag.sh"
WRAPPER_DOUBLE = REPO_ROOT / "tests" / "fixtures" / "test_double_wrapper.sh"


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state_dir = tmp_path / "sanitizer-state"
    monkeypatch.setenv("SANITIZER_STATE_DIR", str(state_dir))
    monkeypatch.delenv("SANITIZER_RUN_ID", raising=False)
    assert_state_dir_isolated(state_dir)
    return state_dir


def start_wrapper_holder(state_dir: Path, tmp_path: Path, hold_cmd: list[str]) -> tuple[subprocess.Popen, Path]:
    info_file = tmp_path / "holder.info"
    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = str(state_dir)
    env.pop("SANITIZER_RUN_ID", None)
    proc = subprocess.Popen(
        ["bash", str(WRAPPER_DOUBLE), str(LOCK_SH), str(info_file), *hold_cmd],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.time() + 5
    while not info_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert info_file.exists(), "wrapper holder failed to acquire the lock in time"
    return proc, info_file


def run_script(script: Path, args: list[str], state_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["SANITIZER_STATE_DIR"] = str(state_dir)
    env.pop("SANITIZER_RUN_ID", None)
    return subprocess.run(
        ["bash", str(script), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def ledger_lines(state_dir: Path) -> list[dict]:
    ledger = state_dir / "overrides.jsonl"
    if not ledger.exists():
        return []
    return [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------
# flag.sh blocked by a foreign lock holder
# --------------------------------------------------------------------------


def test_flag_sh_blocked_by_foreign_lock_holder(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, _info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        result = run_script(FLAG_SH, ["abc123", "should not land"], state_dir)

        assert result.returncode != 0, result.stdout + result.stderr
        assert "could not acquire the sanitizer lock" in (result.stdout + result.stderr)
        assert ledger_lines(state_dir) == [], "flag.sh must not write to the ledger without the lock"
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


def test_unflag_sh_blocked_by_foreign_lock_holder(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, _info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        result = run_script(UNFLAG_SH, ["abc123"], state_dir)

        assert result.returncode != 0, result.stdout + result.stderr
        assert "could not acquire the sanitizer lock" in (result.stdout + result.stderr)
        assert ledger_lines(state_dir) == [], "unflag.sh must not write to the ledger without the lock"
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)


# --------------------------------------------------------------------------
# flag.sh succeeds once the foreign holder releases the lock -- proves the
# block above was a real, live lock contention, not a permanent failure.
# --------------------------------------------------------------------------


def test_flag_sh_succeeds_after_lock_released(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    holder_proc, _info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "1"])
    holder_proc.wait(timeout=5)  # let the holder finish and release the lock

    result = run_script(FLAG_SH, ["abc123", "now it lands"], state_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    lines = ledger_lines(state_dir)
    assert len(lines) == 1
    assert lines[0]["content_hash"] == "abc123"
    assert lines[0]["decision"] == "deny"


# --------------------------------------------------------------------------
# Static check -- flag.sh/unflag.sh must actually source bin/lib/lock.sh and
# call lock_acquire_or_reentrant, not just claim to via comments.
# --------------------------------------------------------------------------


def test_flag_and_unflag_source_lock_lib_and_check_result():
    for path in (FLAG_SH, UNFLAG_SH):
        text = path.read_text()
        assert "bin/lib/lock.sh" in text, f"{path} does not source bin/lib/lock.sh"
        assert "lock_acquire_or_reentrant" in text, f"{path} never calls lock_acquire_or_reentrant"
        assert "if ! lock_acquire_or_reentrant" in text, (
            f"{path} must check lock_acquire_or_reentrant's result and abort on failure"
        )


# --------------------------------------------------------------------------
# Mutation coverage — with the lock check stripped, a foreign holder must NO
# LONGER block flag.sh, proving the tests above actually exercise the fix
# rather than passing for an unrelated reason.
# --------------------------------------------------------------------------


def test_mutant_flag_sh_without_lock_check_ignores_foreign_holder(tmp_path: Path, _isolated_state_dir: Path):
    state_dir = _isolated_state_dir
    text = FLAG_SH.read_text()
    lock_block = (
        '# shellcheck source=lib/lock.sh\n'
        'source "$REPO_ROOT/bin/lib/lock.sh"\n'
        "\n"
        'if ! lock_acquire_or_reentrant "flag"; then\n'
        '  echo "flag.sh: could not acquire the sanitizer lock (result=$LOCK_RESULT) -- refusing to mutate the ledger" >&2\n'
        '  exit 1\n'
        "fi\n"
    )
    assert lock_block in text, "mutation anchor not found in flag.sh -- update this test if flag.sh's locking code changed"
    mutant_text = text.replace(lock_block, "")
    # The mutant is written outside bin/, so flag.sh's own
    # `cd "$(dirname "$0")/.."` would land one level above tmp_path instead
    # of at REPO_ROOT (where the uv project lives) -- pin it explicitly so
    # only the lock-check removal is under test here.
    mutant_text = mutant_text.replace('cd "$(dirname "$0")/.."', f'cd "{REPO_ROOT}"')
    mutant_path = tmp_path / "flag_no_lock.sh"
    mutant_path.write_text(mutant_text)
    mutant_path.chmod(0o755)

    holder_proc, _info_file = start_wrapper_holder(state_dir, tmp_path, ["sleep", "5"])
    try:
        result = run_script(mutant_path, ["abc123", "mutant landed"], state_dir)
        assert result.returncode == 0, (
            "mutant (lock check stripped) was expected to ignore the foreign "
            "holder and succeed anyway\n" + result.stdout + result.stderr
        )
        lines = ledger_lines(state_dir)
        assert len(lines) == 1, (
            "mutant (lock check stripped) was expected to write to the ledger "
            "despite a foreign process holding the lock"
        )
    finally:
        holder_proc.send_signal(signal.SIGTERM)
        holder_proc.wait(timeout=5)

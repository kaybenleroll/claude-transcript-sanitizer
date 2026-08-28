from pathlib import Path

import pytest

from sanitize.engine import RedactionEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# The real production state dir -- test_lock.py must never write here.
REAL_SANITIZER_STATE_DIR = Path.home() / ".local" / "state" / "claude-transcript-sanitizer"


@pytest.fixture(scope="session")
def engine() -> RedactionEngine:
    return RedactionEngine()


def assert_state_dir_isolated(state_dir: Path) -> None:
    """Hard assertion that a lock-test's SANITIZER_STATE_DIR is a tmp path,
    never the real state dir. Called by test_lock.py's autouse fixture
    before any test in that file runs (issue #48 Phase A)."""
    resolved = state_dir.resolve() if state_dir.exists() else state_dir
    assert resolved != REAL_SANITIZER_STATE_DIR, (
        f"SANITIZER_STATE_DIR resolved to the REAL state dir "
        f"({REAL_SANITIZER_STATE_DIR}) -- refusing to run lock tests"
    )
    assert REAL_SANITIZER_STATE_DIR not in resolved.parents, (
        f"SANITIZER_STATE_DIR ({resolved}) is nested inside the real "
        f"state dir ({REAL_SANITIZER_STATE_DIR}) -- refusing to run lock tests"
    )
    assert str(state_dir).startswith("/tmp") or "pytest" in str(state_dir) or "tmp" in str(state_dir).lower(), (
        f"SANITIZER_STATE_DIR ({state_dir}) does not look like a tmp path -- "
        f"refusing to run lock tests"
    )

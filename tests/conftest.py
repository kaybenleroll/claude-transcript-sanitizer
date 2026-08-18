from pathlib import Path

import pytest

from sanitize.engine import RedactionEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def engine() -> RedactionEngine:
    return RedactionEngine()

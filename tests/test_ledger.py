from pathlib import Path

import pytest

from sanitize.ledger import (
    InvalidDecisionError,
    append_entry,
    current_decision,
    flag,
    read_entries,
    unflag,
)


def test_append_and_read_roundtrip(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    append_entry(ledger, "abc123", "deny", "known secret", path_hint="proj/session.jsonl")
    entries = read_entries(ledger)
    assert len(entries) == 1
    assert entries[0].content_hash == "abc123"
    assert entries[0].decision == "deny"
    assert entries[0].reason == "known secret"


def test_append_only_never_rewrites(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    append_entry(ledger, "h1", "deny", "r1")
    append_entry(ledger, "h1", "allow", "r2")
    # Both lines present -- nothing pruned or rewritten.
    lines = ledger.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


def test_invalid_decision_rejected(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    with pytest.raises(InvalidDecisionError):
        append_entry(ledger, "h1", "maybe", "bad decision")


def test_no_entry_returns_none(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    assert current_decision(ledger, "nonexistent") is None


def test_flag_then_unflag_roundtrips_to_allow(tmp_path: Path):
    """The exact bug plan §6 fold #5 caught: under the superseded
    deny > allow (unconditional) precedence rule, an allow appended after a
    deny for the same hash could never win, so `just unflag` could never
    undo `just flag`. Last-entry-wins fixes this -- assert it actually does."""
    ledger = tmp_path / "overrides.jsonl"
    flag(ledger, "h1", "looks like a live credential")
    assert current_decision(ledger, "h1").decision == "deny"

    unflag(ledger, "h1")
    decision = current_decision(ledger, "h1")
    assert decision is not None
    assert decision.decision == "allow"


def test_flag_after_unflag_reverts_to_deny(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    unflag(ledger, "h1", reason="initially cleared")
    assert current_decision(ledger, "h1").decision == "allow"

    flag(ledger, "h1", "reclassified as sensitive")
    assert current_decision(ledger, "h1").decision == "deny"


def test_same_timestamp_tiebreak_deny_over_allow(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    same_at = "2026-08-18T00:00:00+00:00"
    append_entry(ledger, "h1", "allow", "a", at=same_at)
    append_entry(ledger, "h1", "deny", "b", at=same_at)
    assert current_decision(ledger, "h1").decision == "deny"


def test_independent_hashes_do_not_interfere(tmp_path: Path):
    ledger = tmp_path / "overrides.jsonl"
    flag(ledger, "h1", "r1")
    unflag(ledger, "h2")
    assert current_decision(ledger, "h1").decision == "deny"
    assert current_decision(ledger, "h2").decision == "allow"

"""Human override ledger. Plan §6:

~/.local/state/claude-transcript-sanitizer/overrides.jsonl -- append-only,
human-authored only, never written or pruned by automation. Fields: v, at,
content_hash, decision (allow|deny), reason, path_hint, operator. Keyed on
line content hash only -- not version-keyed, no whole-file hash, no
registry, no scope field.

Precedence: LAST ENTRY WINS per content_hash, with deny > allow as a
tie-break only within an identical timestamp. This is deliberately not the
deny > allow > classifier rule the parent (superseded) plan documents used:
under append-only storage plus an unconditional deny > allow, an allow
appended after a deny for the same hash could never win, so `just unflag`
could never undo `just flag`. See plan §6 and the Pass-2 stress-test fold #5.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

LEDGER_VERSION = 1

DEFAULT_LEDGER_PATH = Path.home() / ".local" / "state" / "claude-transcript-sanitizer" / "overrides.jsonl"


class InvalidDecisionError(ValueError):
    pass


@dataclass(frozen=True)
class LedgerEntry:
    v: int
    at: str
    content_hash: str
    decision: str  # "allow" | "deny"
    reason: str
    path_hint: str
    operator: str

    def to_json(self) -> dict:
        return {
            "v": self.v,
            "at": self.at,
            "content_hash": self.content_hash,
            "decision": self.decision,
            "reason": self.reason,
            "path_hint": self.path_hint,
            "operator": self.operator,
        }


def _now_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def append_entry(
    ledger_path: Path,
    content_hash: str,
    decision: str,
    reason: str,
    *,
    path_hint: str = "",
    operator: str | None = None,
    at: str | None = None,
) -> LedgerEntry:
    """Append one entry to the ledger. Never rewrites or prunes existing lines."""
    if decision not in ("allow", "deny"):
        raise InvalidDecisionError(f"decision must be 'allow' or 'deny', got {decision!r}")

    entry = LedgerEntry(
        v=LEDGER_VERSION,
        at=at or _now_iso(),
        content_hash=content_hash,
        decision=decision,
        reason=reason,
        path_hint=path_hint,
        operator=operator or os.environ.get("USER", "unknown"),
    )
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry.to_json(), ensure_ascii=False) + "\n")
    return entry


def read_entries(ledger_path: Path) -> list[LedgerEntry]:
    if not ledger_path.exists():
        return []
    out = []
    with ledger_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out.append(
                LedgerEntry(
                    v=d["v"],
                    at=d["at"],
                    content_hash=d["content_hash"],
                    decision=d["decision"],
                    reason=d["reason"],
                    path_hint=d.get("path_hint", ""),
                    operator=d.get("operator", "unknown"),
                )
            )
    return out


def _sort_key(entry: LedgerEntry) -> tuple:
    # Last-entry-wins by `at`, with deny > allow as a same-timestamp tie-break
    # only (decision compared so that "deny" sorts after "allow" -- alphabetic
    # 'd' > 'a' already gives this ordering).
    return (entry.at, entry.decision)


def current_decision(ledger_path: Path, content_hash: str) -> LedgerEntry | None:
    """The winning entry for content_hash, or None if no entry exists.

    Last-entry-wins per content_hash: among all entries for this hash, the
    one with the latest `at` wins; if two entries share the same `at`
    (same-timestamp tie), `deny` wins over `allow`. This is NOT insertion-
    order-wins -- it is `at`-wins, so a caller that back-dates an entry (not
    expected in normal use) would see it lose to a later-timestamped one
    regardless of append order. In normal use (real-time `at` on append)
    this is equivalent to last-appended-wins.
    """
    matches = [e for e in read_entries(ledger_path) if e.content_hash == content_hash]
    if not matches:
        return None
    return max(matches, key=_sort_key)


def flag(ledger_path: Path, content_hash: str, reason: str, *, operator: str | None = None) -> LedgerEntry:
    """`just flag <hash> "<reason>"` -- record a deny decision."""
    return append_entry(ledger_path, content_hash, "deny", reason, operator=operator)


def unflag(ledger_path: Path, content_hash: str, *, reason: str = "unflagged", operator: str | None = None) -> LedgerEntry:
    """`just unflag <hash>` -- record an allow decision, overriding a prior flag."""
    return append_entry(ledger_path, content_hash, "allow", reason, operator=operator)

"""Classification cache. Plan §6:

Single-file jsonl classification cache at
~/.local/state/claude-transcript-sanitizer/classification-cache.jsonl.
Line hash (post-redaction bytes) -> CLEARED | FLAGGED. Single file, not the
256-shard design -- the §7 sample is only ~50 files.

Not wired to anything yet in this phase (§7, deferred, will use it) -- this
module is just the read/write interface, unit-tested standalone.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

DEFAULT_CACHE_PATH = Path.home() / ".local" / "state" / "claude-transcript-sanitizer" / "classification-cache.jsonl"

VALID_VERDICTS = {"CLEARED", "FLAGGED"}


class InvalidVerdictError(ValueError):
    pass


def hash_content(post_redaction_bytes: bytes) -> str:
    """Hash key for the cache: sha256 over post-redaction bytes.

    Hash is over post-redaction bytes, not raw source bytes -- redaction
    precedes classification (plan §6).
    """
    return hashlib.sha256(post_redaction_bytes).hexdigest()


def load_cache(cache_path: Path) -> dict[str, str]:
    """line_hash -> verdict. Last write for a given hash wins (append-only
    file, later lines overwrite earlier ones for the same key when loaded)."""
    if not cache_path.exists():
        return {}
    out: dict[str, str] = {}
    with cache_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out[d["line_hash"]] = d["verdict"]
    return out


def get(cache_path: Path, line_hash: str) -> str | None:
    return load_cache(cache_path).get(line_hash)


def put(cache_path: Path, line_hash: str, verdict: str) -> None:
    """Append one hash->verdict entry. Appending a new verdict for an
    already-cached hash is allowed and the later entry wins on next load
    (mirrors the ledger's last-entry-wins discipline, but this is a cache,
    not an audit trail -- no `at`/`reason`/`operator` fields)."""
    if verdict not in VALID_VERDICTS:
        raise InvalidVerdictError(f"verdict must be one of {VALID_VERDICTS}, got {verdict!r}")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"line_hash": line_hash, "verdict": verdict}, ensure_ascii=False) + "\n")


def put_many(cache_path: Path, entries: dict[str, str]) -> None:
    for line_hash, verdict in entries.items():
        put(cache_path, line_hash, verdict)

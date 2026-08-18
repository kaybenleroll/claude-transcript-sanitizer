from pathlib import Path

import pytest

from sanitize.cache import (
    InvalidVerdictError,
    get,
    hash_content,
    load_cache,
    put,
    put_many,
)


def test_hash_content_deterministic():
    h1 = hash_content(b"redacted line bytes")
    h2 = hash_content(b"redacted line bytes")
    assert h1 == h2
    assert len(h1) == 64  # sha256 hexdigest


def test_hash_content_differs_by_input():
    assert hash_content(b"a") != hash_content(b"b")


def test_get_missing_returns_none(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    assert get(cache, "nonexistent") is None


def test_put_then_get_roundtrip(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    put(cache, "h1", "CLEARED")
    assert get(cache, "h1") == "CLEARED"


def test_invalid_verdict_rejected(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    with pytest.raises(InvalidVerdictError):
        put(cache, "h1", "MAYBE")


def test_later_write_wins_on_reload(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    put(cache, "h1", "CLEARED")
    put(cache, "h1", "FLAGGED")
    assert get(cache, "h1") == "FLAGGED"


def test_put_many(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    put_many(cache, {"h1": "CLEARED", "h2": "FLAGGED"})
    loaded = load_cache(cache)
    assert loaded == {"h1": "CLEARED", "h2": "FLAGGED"}


def test_load_cache_empty_file(tmp_path: Path):
    cache = tmp_path / "cache.jsonl"
    assert load_cache(cache) == {}

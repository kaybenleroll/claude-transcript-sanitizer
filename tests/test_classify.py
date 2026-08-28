import json
import subprocess
from pathlib import Path

import pytest

from sanitize.cache import get as cache_get, hash_content, load_cache, put as cache_put
from sanitize.classify import (
    MAX_CHUNK_BYTES,
    ClaudeCaller,
    DispatchOutcome,
    chunk_lines,
    classify_file,
    dispatch_chunk,
    filter_cache_misses,
    find_credential_relpaths,
    pick_contrast_relpaths,
    read_lines_bytes,
    select_sample,
)
import random


# ---------------------------------------------------------------------------
# Chunking: <=200KB, split on line boundaries, oversized single line
# ---------------------------------------------------------------------------

def test_chunk_lines_single_small_chunk():
    lines = [b"a" * 10, b"b" * 10, b"c" * 10]
    result = chunk_lines(lines, max_bytes=1000)
    assert result.chunks == [lines]
    assert result.oversized_lines == []


def test_chunk_lines_splits_on_line_boundary_not_midline():
    # Each line is 60 bytes; max_bytes=100 should force a new chunk every
    # 1-2 lines, but must never split a line's bytes across chunks.
    lines = [b"x" * 60 for _ in range(4)]
    result = chunk_lines(lines, max_bytes=100)
    # Every chunk must consist of whole lines from the original list.
    flat = [line for chunk in result.chunks for line in chunk]
    assert flat == lines
    # No chunk should exceed max_bytes when joined with '\n'.
    for chunk in result.chunks:
        size = sum(len(l) for l in chunk) + max(0, len(chunk) - 1)
        assert size <= 100 or len(chunk) == 1  # a single oversized-relative-but-under-max-bytes line is fine alone


def test_chunk_lines_respects_max_bytes_boundary():
    # Two 100-byte lines with max_bytes=150 must land in separate chunks.
    lines = [b"a" * 100, b"b" * 100]
    result = chunk_lines(lines, max_bytes=150)
    assert len(result.chunks) == 2
    assert result.chunks[0] == [lines[0]]
    assert result.chunks[1] == [lines[1]]


def test_chunk_lines_oversized_single_line_excluded():
    small = b"y" * 10
    huge = b"z" * 300
    result = chunk_lines([small, huge], max_bytes=200)
    assert result.oversized_lines == [huge]
    flat = [line for chunk in result.chunks for line in chunk]
    assert huge not in flat
    assert small in flat


def test_chunk_lines_empty_input():
    result = chunk_lines([], max_bytes=200_000)
    assert result.chunks == []
    assert result.oversized_lines == []


def test_chunk_lines_default_max_bytes_is_200kb():
    assert MAX_CHUNK_BYTES == 200_000


# ---------------------------------------------------------------------------
# Sample selection: credential-prefix files + random contrast
# ---------------------------------------------------------------------------

def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def test_find_credential_relpaths_matches_known_prefixes(tmp_path):
    source = tmp_path / "source"
    _write_jsonl(source / "a.jsonl", [{"message": {"content": "sk-ant-" + "x" * 30}}])
    _write_jsonl(source / "b.jsonl", [{"message": {"content": "nothing interesting here"}}])
    _write_jsonl(source / "c.jsonl", [{"message": {"content": "ghp_" + "y" * 30}}])

    found = find_credential_relpaths(source)
    assert found == {"a.jsonl", "c.jsonl"}


def test_find_credential_relpaths_no_false_positive_on_bare_substring(tmp_path):
    source = tmp_path / "source"
    # "AKIA" too short a suffix (needs 16 more [A-Z0-9] chars) -- not the real shape.
    _write_jsonl(source / "d.jsonl", [{"message": {"content": "AKIAshort not a real key"}}])
    found = find_credential_relpaths(source)
    assert found == set()


def test_find_credential_relpaths_matches_escape_residue_precedence(tmp_path):
    """Plan P0.2/P0.3: raw .jsonl bytes can carry literal `\\n`/`\\t` escape
    residue (e.g. from a captured `printf "a\\nTOKEN"` shell command) with a
    real word char immediately before the token shape. The old
    `\\b`-anchored CREDENTIAL_PREFIX_RE missed this, silently dropping the
    whole file from LLM classification. Written as raw bytes directly (not
    via json.dumps, which would add its own backslash-escaping layer on top)
    so the fixture's on-disk bytes match exactly what a raw-byte scan sees."""
    source = tmp_path / "source"
    source.mkdir(parents=True)
    (source / "escaped.jsonl").write_bytes(
        b'{"message": {"content": "echo hello\\nAKIAQ4ZKN7TG5XW2JLPD"}}\n'
    )
    found = find_credential_relpaths(source)
    assert found == {"escaped.jsonl"}


def test_select_sample_includes_credential_files_and_contrast(tmp_path):
    source = tmp_path / "source"
    mirror = tmp_path / "mirror"
    # 3 credential-bearing files in source, redacted (placeholder) in mirror.
    for i in range(3):
        _write_jsonl(source / f"cred{i}.jsonl", [{"message": {"content": "sk-ant-" + "x" * 30}}])
        _write_jsonl(mirror / f"cred{i}.jsonl", [{"message": {"content": "[ANTHROPIC_API_KEY]"}}])
    # 5 non-credential files only in the mirror (contrast candidates).
    for i in range(5):
        _write_jsonl(mirror / f"plain{i}.jsonl", [{"message": {"content": "hello world"}}])

    selection = select_sample(source, mirror, contrast_n=2, seed=42)
    assert set(selection.credential_relpaths) == {"cred0.jsonl", "cred1.jsonl", "cred2.jsonl"}
    assert len(selection.contrast_relpaths) == 2
    assert set(selection.contrast_relpaths).issubset({f"plain{i}.jsonl" for i in range(5)})
    # Contrast never re-picks a credential file.
    assert set(selection.contrast_relpaths).isdisjoint(selection.credential_relpaths)


def test_select_sample_credential_file_missing_from_mirror_excluded(tmp_path):
    source = tmp_path / "source"
    mirror = tmp_path / "mirror"
    _write_jsonl(source / "orphan.jsonl", [{"message": {"content": "sk-ant-" + "x" * 30}}])
    _write_jsonl(mirror / "plain0.jsonl", [{"message": {"content": "hi"}}])
    selection = select_sample(source, mirror, contrast_n=1, seed=1)
    assert "orphan.jsonl" not in selection.credential_relpaths


def test_pick_contrast_relpaths_excludes_given_set(tmp_path):
    mirror = tmp_path / "mirror"
    for i in range(4):
        _write_jsonl(mirror / f"f{i}.jsonl", [{"a": 1}])
    picked = pick_contrast_relpaths(mirror, exclude={"f0.jsonl"}, n=10, rng=random.Random(0))
    assert "f0.jsonl" not in picked
    assert set(picked) == {"f1.jsonl", "f2.jsonl", "f3.jsonl"}


# ---------------------------------------------------------------------------
# Cache-miss filtering
# ---------------------------------------------------------------------------

def test_filter_cache_misses_skips_already_cached_lines(tmp_path):
    cache_path = tmp_path / "cache.jsonl"
    line_cached = b'{"a": "already seen"}'
    line_new = b'{"a": "new line"}'
    cache_put(cache_path, hash_content(line_cached), "CLEARED")

    misses, hits, hit_count = filter_cache_misses([line_cached, line_new], cache_path)
    assert misses == [line_new]
    assert hits == [line_cached]
    assert hit_count == 1


def test_filter_cache_misses_empty_cache_all_miss(tmp_path):
    cache_path = tmp_path / "cache.jsonl"
    lines = [b'{"a": 1}', b'{"a": 2}']
    misses, hits, hit_count = filter_cache_misses(lines, cache_path)
    assert misses == lines
    assert hits == []
    assert hit_count == 0


def test_read_lines_bytes_drops_blank_lines(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_bytes(b'{"a": 1}\n\n{"a": 2}\n')
    lines = read_lines_bytes(p)
    assert lines == [b'{"a": 1}', b'{"a": 2}']


# ---------------------------------------------------------------------------
# Dispatch — mocked subprocess only, never a real `claude -p` call
# ---------------------------------------------------------------------------

class FakeCaller:
    """Stand-in for ClaudeCaller.run — never invokes a real subprocess."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def run(self, chunk_text, timeout=120):
        self.calls += 1
        resp = self._responses.pop(0)
        if resp == "TIMEOUT":
            raise subprocess.TimeoutExpired(cmd="claude", timeout=timeout)
        return resp


def _completed(stdout: bytes, returncode: int = 0):
    return subprocess.CompletedProcess(args=["claude"], returncode=returncode, stdout=stdout, stderr=b"")


def test_dispatch_chunk_ok_first_try():
    caller = FakeCaller([_completed(b'{"flagged": false, "reason": "clean"}')])
    outcome = dispatch_chunk(caller, [b"line1"], sleep_fn=lambda s: None)
    assert outcome.status == "ok"
    assert outcome.flagged is False
    assert outcome.attempts == 1


def test_dispatch_chunk_flagged():
    caller = FakeCaller([_completed(b'{"flagged": true, "reason": "sensitive"}')])
    outcome = dispatch_chunk(caller, [b"line1"], sleep_fn=lambda s: None)
    assert outcome.flagged is True


def test_dispatch_chunk_retries_on_malformed_then_succeeds():
    caller = FakeCaller([_completed(b"not json"), _completed(b'{"flagged": false, "reason": "ok"}')])
    outcome = dispatch_chunk(caller, [b"line1"], sleep_fn=lambda s: None)
    assert outcome.status == "ok"
    assert outcome.attempts == 2


def test_dispatch_chunk_deferred_after_max_attempts():
    caller = FakeCaller(["TIMEOUT", "TIMEOUT", "TIMEOUT"])
    outcome = dispatch_chunk(caller, [b"line1"], max_attempts=3, sleep_fn=lambda s: None)
    assert outcome.status == "deferred"
    assert outcome.attempts == 3
    # Timeout is recorded as a latency observation, not silently dropped.
    assert len(outcome.events) == 3
    assert all(e["outcome"] == "timeout" for e in outcome.events)


def test_dispatch_chunk_nonzero_exit_retried_and_deferred():
    caller = FakeCaller([_completed(b"", returncode=1), _completed(b"", returncode=1), _completed(b"", returncode=1)])
    outcome = dispatch_chunk(caller, [b"line1"], max_attempts=3, sleep_fn=lambda s: None)
    assert outcome.status == "deferred"
    assert caller.calls == 3


# ---------------------------------------------------------------------------
# classify_file: end-to-end with a fake caller, verifying cache writes
# ---------------------------------------------------------------------------

def test_classify_file_flagged_chunk_writes_nothing_to_cache(tmp_path, monkeypatch):
    """Issue #12: FLAGGED verdicts must never be cache-written -- the
    file-level report still reflects the flag, but no line-hash entry is
    written for any line in a FLAGGED chunk."""
    mirror = tmp_path / "mirror"
    _write_jsonl(mirror / "f.jsonl", [{"a": "one"}, {"a": "two"}])
    cache_path = tmp_path / "cache.jsonl"

    caller = FakeCaller([_completed(b'{"flagged": true, "reason": "sensitive stuff"}')])
    call_events: list[dict] = []
    result = classify_file("f.jsonl", mirror, cache_path, caller, call_events)

    assert result.file_flagged is True
    assert result.chunks == 1
    # Both lines were in the single flagged chunk -> neither is cached.
    lines = read_lines_bytes(mirror / "f.jsonl")
    for line in lines:
        assert cache_get(cache_path, hash_content(line)) is None
    assert load_cache(cache_path) == {}


def test_classify_file_cleared_chunk_still_writes_cache(tmp_path):
    mirror = tmp_path / "mirror"
    _write_jsonl(mirror / "clear.jsonl", [{"a": "one"}, {"a": "two"}])
    cache_path = tmp_path / "cache.jsonl"

    caller = FakeCaller([_completed(b'{"flagged": false, "reason": "fine"}')])
    result = classify_file("clear.jsonl", mirror, cache_path, caller, [])

    assert result.file_flagged is False
    lines = read_lines_bytes(mirror / "clear.jsonl")
    for line in lines:
        assert cache_get(cache_path, hash_content(line)) == "CLEARED"


def test_classify_file_flagged_line_redispatched_and_not_poisoned_by_shared_content(tmp_path):
    """Issue #12 core scenario: a FLAGGED chunk's content, if later seen as
    its own cache-miss line in an unrelated file's dispatch, must be
    re-dispatched (never short-circuited by a stale FLAGGED cache entry) and
    is free to clear independently on that redispatch."""
    mirror = tmp_path / "mirror"
    shared_content = {"a": "shared boilerplate line"}
    _write_jsonl(mirror / "bad.jsonl", [shared_content])
    cache_path = tmp_path / "cache.jsonl"

    # First dispatch: this file's chunk (containing the shared line) is
    # flagged. Per the fix, nothing gets cache-written.
    caller1 = FakeCaller([_completed(b'{"flagged": true, "reason": "sensitive"}')])
    result1 = classify_file("bad.jsonl", mirror, cache_path, caller1, [])
    assert result1.file_flagged is True
    assert load_cache(cache_path) == {}

    # Second dispatch: an unrelated file sharing the exact same line content
    # is classified. Because the first dispatch never cached the FLAGGED
    # verdict, this line is a cache miss and gets its own, independent
    # dispatch -- which clears it.
    _write_jsonl(mirror / "unrelated.jsonl", [shared_content])
    caller2 = FakeCaller([_completed(b'{"flagged": false, "reason": "fine after all"}')])
    result2 = classify_file("unrelated.jsonl", mirror, cache_path, caller2, [])

    assert caller2.calls == 1  # actually redispatched, not skipped as a cache hit
    assert result2.cache_hit_lines == 0
    assert result2.file_flagged is False
    shared_line = read_lines_bytes(mirror / "unrelated.jsonl")[0]
    assert cache_get(cache_path, hash_content(shared_line)) == "CLEARED"


def test_classify_file_deferred_chunk_writes_nothing_to_cache(tmp_path):
    mirror = tmp_path / "mirror"
    _write_jsonl(mirror / "g.jsonl", [{"a": "one"}])
    cache_path = tmp_path / "cache.jsonl"

    caller = FakeCaller(["TIMEOUT", "TIMEOUT", "TIMEOUT"])
    call_events: list[dict] = []
    result = classify_file("g.jsonl", mirror, cache_path, caller, call_events)

    assert result.deferred_chunks == 1
    assert result.file_flagged is False
    assert load_cache(cache_path) == {}


def test_classify_file_second_run_skips_cached_lines(tmp_path):
    mirror = tmp_path / "mirror"
    _write_jsonl(mirror / "h.jsonl", [{"a": "one"}])
    cache_path = tmp_path / "cache.jsonl"

    caller1 = FakeCaller([_completed(b'{"flagged": false, "reason": "fine"}')])
    classify_file("h.jsonl", mirror, cache_path, caller1, [])
    assert caller1.calls == 1

    # Second pass: the line is now cached, so no dispatch should occur.
    caller2 = FakeCaller([])
    result2 = classify_file("h.jsonl", mirror, cache_path, caller2, [])
    assert caller2.calls == 0
    assert result2.chunks == 0
    assert result2.cache_hit_lines == 1

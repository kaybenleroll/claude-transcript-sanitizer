"""Tests for sanitize/mirror.py.

Per plan §9 step 4: .jsonl and .txt now both go through build_mirror(),
dispatched on suffix, with a mirror hygiene gate (sweep .tmp -> prune ->
suffix whitelist) run at the end of every build. Baseline .jsonl-only tests
from step 3 are preserved; step-4 additions cover .txt dispatch, real
pruning, the exit-code policy, and the new summary.json fields.
"""

import json
from pathlib import Path
from unittest import mock

import pytest

from sanitize.mirror import (
    SKIP_CEILING,
    _line_count,
    build_mirror,
    run_build,
    snapshot_source,
)


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_dispatch_isolation_single_jsonl_processed(tmp_path):
    """Baseline the step-4 dispatch-by-suffix logic must preserve: a lone
    well-formed .jsonl file under source_root is picked up by the snapshot
    and successfully mirrored end to end."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess1.jsonl", [{"uuid": "u1", "content": "hello world"}])

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert result.processed == ["sess1.jsonl"]
    assert result.errors == {}
    assert (mirror_root / "sess1.jsonl").exists()
    mirrored = json.loads((mirror_root / "sess1.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert mirrored["content"] == "hello world"


def test_dispatch_isolation_foreign_suffix_files_ignored(tmp_path):
    """Files under source_root with a suffix outside {.jsonl, .txt} are
    outside the snapshot glob entirely -- they're neither processed nor
    errored, and never reach the mirror."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess1.jsonl", [{"uuid": "u1", "content": "hi"}])
    (source_root / "notes.md").parent.mkdir(parents=True, exist_ok=True)
    (source_root / "notes.md").write_text("not a session file", encoding="utf-8")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert result.processed == ["sess1.jsonl"]
    assert "notes.md" not in result.errors
    assert not (mirror_root / "notes.md").exists()


def test_dispatch_isolation_txt_processed_alongside_jsonl(tmp_path):
    """A .txt sidecar under source_root is now picked up by snapshot_source()
    and mirrored via the .txt branch (redact_text_file), distinct from the
    .jsonl branch."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess1.jsonl", [{"uuid": "u1", "content": "hi"}])
    _write_text(source_root / "notes.txt", "plain text notes, no PII\n")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert set(result.processed) == {"sess1.jsonl", "notes.txt"}
    assert result.errors == {}
    assert (mirror_root / "notes.txt").exists()
    assert (mirror_root / "notes.txt").read_text(encoding="utf-8") == "plain text notes, no PII\n"


def test_error_continue_malformed_line_does_not_abort_run(tmp_path):
    """A file with a malformed *non-final* line raises MalformedLineError
    internally, which build_mirror catches -- the run continues and other
    files still get processed.

    Must be non-final: build_mirror() passes tolerate_trailing_partial=True
    uniformly (see module docstring), so a malformed *final* line is
    silently omitted rather than raised -- it would not exercise the
    error-continue path at all."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    good = source_root / "good.jsonl"
    _write_jsonl(good, [{"uuid": "u1", "content": "clean line"}])

    bad = source_root / "bad.jsonl"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text('NOT JSON\n{"uuid": "u1", "content": "ok"}\n', encoding="utf-8")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert "bad.jsonl" in result.errors
    assert "MalformedLineError" in result.errors["bad.jsonl"]
    assert "good.jsonl" in result.processed
    assert (mirror_root / "good.jsonl").exists()
    assert not (mirror_root / "bad.jsonl").exists()


def test_error_continue_oserror_unreadable_file_does_not_abort_run(tmp_path):
    """A file that raises OSError on read (simulated: it's a directory, not
    a file -- read_text() raises IsADirectoryError, an OSError subclass) is
    caught per-file; other files still process."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    good = source_root / "good.jsonl"
    _write_jsonl(good, [{"uuid": "u1", "content": "clean line"}])

    # A directory named *.jsonl matches the glob (p.is_file() filters it out
    # of the snapshot -- so to hit the per-file except path we need a file
    # that snapshot picks up but errors on read). Simulate via a file with
    # invalid utf-8 bytes instead, which raises UnicodeDecodeError -- also
    # covered by the same except tuple.
    bad = source_root / "bad.jsonl"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_bytes(b"\xff\xfe\x00bad bytes not utf-8\n")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert "bad.jsonl" in result.errors
    assert "good.jsonl" in result.processed
    assert (mirror_root / "good.jsonl").exists()
    assert not (mirror_root / "bad.jsonl").exists()


def test_error_continue_summary_counts_reflect_partial_failure(tmp_path):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "good.jsonl", [{"uuid": "u1", "content": "clean"}])
    bad = source_root / "bad.jsonl"
    bad.parent.mkdir(parents=True, exist_ok=True)
    # Non-final malformed line -- see test_error_continue_malformed_line_
    # does_not_abort_run for why a malformed *final* line wouldn't raise.
    bad.write_text('NOT JSON AT ALL\n{"uuid": "u1", "content": "ok"}\n', encoding="utf-8")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert len(result.snapshot_pre) == 2
    assert len(result.processed) == 1
    assert len(result.errors) == 1

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["files_in_snapshot"] == 2
    assert summary["files_processed"] == 1
    assert summary["files_errored"] == 1
    assert "bad.jsonl" in summary["errors"]


def test_pruning_removes_mirror_file_for_deleted_source(tmp_path):
    """build_mirror() now DOES prune: a mirror file left over from a prior
    run, whose source .jsonl has since been deleted, is removed by the next
    build_mirror() call (mechanism 2 of the hygiene gate, keyed on this
    run's processed set)."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "keep.jsonl", [{"uuid": "u1", "content": "keep me"}])
    stale_src = source_root / "stale.jsonl"
    _write_jsonl(stale_src, [{"uuid": "u2", "content": "will vanish"}])

    build_mirror(source_root, mirror_root, run_dir / "run-1", "run-1")
    assert (mirror_root / "keep.jsonl").exists()
    assert (mirror_root / "stale.jsonl").exists()

    stale_src.unlink()

    build_mirror(source_root, mirror_root, run_dir / "run-2", "run-2")

    assert (mirror_root / "keep.jsonl").exists()
    assert not (mirror_root / "stale.jsonl").exists()


def test_pruning_removes_mirror_file_still_in_snapshot_but_skipped_this_run(tmp_path):
    """Negative test for the prune-keyed-on-snapshot bug: a file that's
    STILL present in the snapshot glob this run, but fails a check (here:
    becomes oversize) and is therefore never (re)written, must still be
    pruned -- pruning keyed on the raw snapshot set (rather than the
    processed set) would incorrectly leave its stale, previously-mirrored
    copy in place."""
    from sanitize.text import MAX_TEXT_BYTES

    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    flaky = source_root / "flaky.txt"
    _write_text(flaky, "small and clean, first run\n")

    build_mirror(source_root, mirror_root, run_dir / "run-1", "run-1")
    assert (mirror_root / "flaky.txt").exists()

    # File is still present in the source tree (and thus in this run's
    # snapshot), but now oversize -- it will be skipped, not rewritten.
    flaky.write_bytes(b"x" * (MAX_TEXT_BYTES + 1))

    result = build_mirror(source_root, mirror_root, run_dir / "run-2", "run-2")

    assert "flaky.txt" in result.errors
    assert "flaky.txt" not in result.processed
    assert "flaky.txt" in snapshot_source(source_root)  # still in the snapshot glob
    # Stale mirrored copy from run-1 must be gone, not left behind.
    assert not (mirror_root / "flaky.txt").exists()


def test_unchanged_relpaths_excludes_file_touched_during_run(tmp_path):
    """unchanged_relpaths() reports only files whose mtime+size at
    snapshot_post match snapshot_pre exactly. A file whose mtime is bumped
    between the pre- and post-snapshot (simulating a concurrent write during
    the run) is excluded even though build_mirror already processed the
    pre-run content."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    stable = source_root / "stable.jsonl"
    _write_jsonl(stable, [{"uuid": "u1", "content": "steady"}])
    touched = source_root / "touched.jsonl"
    _write_jsonl(touched, [{"uuid": "u2", "content": "will be bumped"}])

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    # Both were processed successfully this run.
    assert set(result.processed) == {"stable.jsonl", "touched.jsonl"}

    # Directly manipulate result.snapshot_post to simulate an mtime bump
    # for one file between pre- and post-snapshot, without re-running
    # build_mirror (keeps this test independent of filesystem mtime
    # resolution/granularity flakiness).
    bumped = result.snapshot_post["touched.jsonl"]
    result.snapshot_post["touched.jsonl"] = type(bumped)(
        relpath=bumped.relpath, mtime_ns=bumped.mtime_ns + 1, size=bumped.size
    )

    unchanged = result.unchanged_relpaths()
    assert "stable.jsonl" in unchanged
    assert "touched.jsonl" not in unchanged


def test_unchanged_relpaths_excludes_file_absent_from_post_snapshot(tmp_path):
    """A file present pre-run but deleted before the post-snapshot is taken
    is absent from snapshot_post -- unchanged_relpaths() must not raise and
    must exclude it (post.get returns None, guarded)."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    keep = source_root / "keep.jsonl"
    _write_jsonl(keep, [{"uuid": "u1", "content": "steady"}])
    ephemeral = source_root / "ephemeral.jsonl"
    _write_jsonl(ephemeral, [{"uuid": "u2", "content": "gone soon"}])

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")
    # Simulate deletion between the pre-snapshot (already taken, has both
    # relpaths) and inspection, by pruning it from the recorded post
    # snapshot directly.
    del result.snapshot_post["ephemeral.jsonl"]

    unchanged = result.unchanged_relpaths()
    assert "keep.jsonl" in unchanged
    assert "ephemeral.jsonl" not in unchanged


def test_snapshot_source_picks_up_jsonl_at_this_instant(tmp_path):
    source_root = tmp_path / "source"
    _write_jsonl(source_root / "a.jsonl", [{"uuid": "u1", "content": "x"}])
    _write_jsonl(source_root / "sub" / "b.jsonl", [{"uuid": "u2", "content": "y"}])

    snap = snapshot_source(source_root)

    assert set(snap.keys()) == {"a.jsonl", str(Path("sub") / "b.jsonl")}
    for rec in snap.values():
        assert rec.size > 0
        assert rec.mtime_ns > 0


def test_snapshot_source_is_sorted_union_of_jsonl_and_txt(tmp_path):
    source_root = tmp_path / "source"
    _write_jsonl(source_root / "a.jsonl", [{"uuid": "u1", "content": "x"}])
    _write_text(source_root / "b.txt", "hi\n")
    _write_jsonl(source_root / "sub" / "c.jsonl", [{"uuid": "u2", "content": "y"}])

    snap = snapshot_source(source_root)

    assert set(snap.keys()) == {"a.jsonl", "b.txt", str(Path("sub") / "c.jsonl")}


# ─── step-4 additions: .txt dispatch, hygiene gate, exit-code policy ────────


def test_line_count_never_called_for_txt_files(tmp_path):
    """Negative test for the line-count-convention leak: _line_count()
    (splitlines()-based) must never be invoked for a .txt path -- .txt line
    counts come exclusively from TextRedactResult (count("\\n"))."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess.jsonl", [{"uuid": "u1", "content": "hi"}])
    _write_text(source_root / "notes.txt", "line one\nline two\n")

    with mock.patch("sanitize.mirror._line_count", wraps=_line_count) as spy:
        result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert result.errors == {}
    called_paths = [str(call.args[0]) for call in spy.call_args_list]
    assert all(not p.endswith(".txt") for p in called_paths)
    # Sanity: it *was* called, just only for the .jsonl src/dst pair.
    assert len(called_paths) == 2


def test_jsonl_over_8mib_is_not_skipped_by_txt_cap(tmp_path):
    """Negative test for scope: the .txt MAX_TEXT_BYTES cap must never apply
    to .jsonl files. A > 8 MiB .jsonl is processed normally, not skipped as
    oversize (that check lives only in sanitize/text.py's .txt path)."""
    from sanitize.text import MAX_TEXT_BYTES

    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    big = source_root / "big.jsonl"
    big.parent.mkdir(parents=True, exist_ok=True)
    padding = "x" * (MAX_TEXT_BYTES + 1024)
    _write_jsonl(big, [{"uuid": "u1", "content": padding}])

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert "big.jsonl" in result.processed
    assert result.errors == {}
    assert (mirror_root / "big.jsonl").exists()


def test_malformed_jsonl_error_does_not_affect_txt_counters_but_trips_ceiling(tmp_path):
    """MalformedLineError on a .jsonl is still caught per-file and doesn't
    affect .txt skip counters -- but (new in step 4) run_build() now trips
    should_fail/non-zero exit on ANY .jsonl error, via the pruning-safety
    check, regardless of the .txt skip ceiling."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    good_txt = source_root / "good.txt"
    _write_text(good_txt, "clean text\n")

    bad = source_root / "bad.jsonl"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text('NOT JSON\n{"uuid": "u1", "content": "ok"}\n', encoding="utf-8")

    result, should_fail = run_build(source_root, mirror_root, run_dir)

    assert "bad.jsonl" in result.errors
    assert "MalformedLineError" in result.errors["bad.jsonl"]
    for key in (
        "files_skipped_oversize",
        "files_skipped_decode",
        "files_skipped_line_growth",
        "files_skipped_os_error_txt",
        "files_skipped_anomalous_span_txt",
    ):
        assert result.summary[key] == 0
    assert should_fail is True


def test_permission_error_on_txt_counted_by_elimination(tmp_path):
    """A PermissionError raised while processing a .txt file must be
    counted under files_skipped_os_error_txt by elimination (no literal
    "OSError:" prefix match is possible, since type(e).__name__ is always
    the concrete subclass name)."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_text(source_root / "locked.txt", "secret notes\n")

    def _boom(*args, **kwargs):
        raise PermissionError("denied")

    with mock.patch("sanitize.mirror.redact_text_file", side_effect=_boom):
        result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert "locked.txt" in result.errors
    assert result.errors["locked.txt"] == "PermissionError: denied"
    assert result.summary["files_skipped_os_error_txt"] == 1
    assert result.summary["skipped_txt_paths"]["files_skipped_os_error_txt"] == ["locked.txt"]
    for key in (
        "files_skipped_oversize",
        "files_skipped_decode",
        "files_skipped_line_growth",
        "files_skipped_anomalous_span_txt",
    ):
        assert result.summary[key] == 0


def test_anomalous_redaction_span_counted_distinctly(tmp_path):
    """AnomalousRedactionSpanError on a .txt file is counted under
    files_skipped_anomalous_span_txt, distinct from the os-error elimination
    bucket."""
    from sanitize.text import AnomalousRedactionSpanError

    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_text(source_root / "weird.txt", "content\n")

    def _boom(*args, **kwargs):
        raise AnomalousRedactionSpanError("span too big")

    with mock.patch("sanitize.mirror.redact_text_file", side_effect=_boom):
        result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert result.errors["weird.txt"] == "AnomalousRedactionSpanError: span too big"
    assert result.summary["files_skipped_anomalous_span_txt"] == 1
    assert result.summary["files_skipped_os_error_txt"] == 0


def test_unenumerated_exception_propagates_and_aborts(tmp_path):
    """An exception type outside the six caught types (e.g. the residue
    check's bare AssertionError from sanitize/text.py, or any other
    unexpected exception) must propagate out of build_mirror() and abort
    the run -- not be swallowed as a per-file error."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_text(source_root / "boom.txt", "content\n")

    def _boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    with mock.patch("sanitize.mirror.redact_text_file", side_effect=_boom):
        with pytest.raises(RuntimeError, match="unexpected"):
            build_mirror(source_root, mirror_root, run_dir, "run-1")


def test_unenumerated_exception_does_not_update_fixed_path_summary(tmp_path):
    """If build_mirror() aborts mid-run on an unenumerated exception,
    run_build()'s fixed-path summary.json write is never reached -- a
    pre-existing fixed-path file is left stale, not overwritten with a
    mid-crash snapshot."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess.jsonl", [{"uuid": "u1", "content": "hi"}])
    fixed_path = mirror_root.parent / "summary.json"
    fixed_path.parent.mkdir(parents=True, exist_ok=True)
    fixed_path.write_text('{"stale": true}', encoding="utf-8")

    def _boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    with mock.patch("sanitize.mirror.redact_jsonl_file", side_effect=_boom):
        with pytest.raises(RuntimeError):
            run_build(source_root, mirror_root, run_dir)

    assert json.loads(fixed_path.read_text(encoding="utf-8")) == {"stale": True}


def test_summary_counters_no_double_counting_and_new_fields_present(tmp_path):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "a.jsonl", [{"uuid": "u1", "content": "hi"}])
    _write_jsonl(source_root / "b.jsonl", [{"uuid": "u2", "content": "yo"}])
    _write_text(source_root / "notes.txt", "plain notes\n")

    result = build_mirror(source_root, mirror_root, run_dir, "run-1")

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))

    assert summary["files_in_snapshot_jsonl"] == 2
    assert summary["files_in_snapshot_txt"] == 1
    assert summary["files_processed_jsonl"] == 2
    assert summary["files_processed_txt"] == 1
    assert summary["files_in_snapshot"] == 3
    assert summary["files_processed"] == 3
    assert summary["line_count_convention"] == {"jsonl": "splitlines()", "txt": "count(\\n)"}
    assert "skip_ceiling_exceeded" not in summary  # only in the fixed-path copy
    assert result.errors == {}


def test_run_build_writes_fixed_path_summary_with_skip_ceiling(tmp_path):
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_text(source_root / "notes.txt", "clean\n")

    result, should_fail = run_build(source_root, mirror_root, run_dir)

    fixed_path = mirror_root.parent / "summary.json"
    assert fixed_path.exists()
    fixed_summary = json.loads(fixed_path.read_text(encoding="utf-8"))
    assert fixed_summary["skip_ceiling_exceeded"] is False
    assert fixed_summary["line_count_convention"] == {"jsonl": "splitlines()", "txt": "count(\\n)"}
    assert should_fail is False

    # Timestamped copy is still written too.
    assert (run_dir / result.run_id / "summary.json").exists()


def test_run_build_fails_when_txt_skip_ceiling_exceeded(tmp_path):
    """SKIP_CEILING + 1 oversize .txt skips this run trips should_fail and
    skip_ceiling_exceeded, independent of any .jsonl state."""
    from sanitize.text import MAX_TEXT_BYTES

    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    for i in range(SKIP_CEILING + 1):
        p = source_root / f"oversize{i}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * (MAX_TEXT_BYTES + 1))

    result, should_fail = run_build(source_root, mirror_root, run_dir)

    assert result.summary["files_skipped_oversize"] == SKIP_CEILING + 1
    fixed_summary = json.loads((mirror_root.parent / "summary.json").read_text(encoding="utf-8"))
    assert fixed_summary["skip_ceiling_exceeded"] is True
    assert should_fail is True


def test_mirror_hygiene_gate_sweeps_stale_tmp_and_enforces_whitelist(tmp_path):
    """The mirror hygiene gate fires at the end of build_mirror(): a stale
    *.jsonl.tmp left from a prior crashed run is swept, and (after sweep +
    prune) only .jsonl/.txt files remain under the mirror."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "sess.jsonl", [{"uuid": "u1", "content": "hi"}])

    stale_tmp = mirror_root / "sess.jsonl.tmp"
    stale_tmp.parent.mkdir(parents=True, exist_ok=True)
    stale_tmp.write_text("leftover from a crashed run", encoding="utf-8")

    build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert not stale_tmp.exists()
    assert (mirror_root / "sess.jsonl").exists()
    for p in mirror_root.rglob("*"):
        if p.is_file():
            assert p.suffix in (".jsonl", ".txt")


def test_assert_write_target_safe_still_called_for_both_suffixes(tmp_path):
    """assert_write_target_safe is still invoked from the loop for both
    .jsonl and .txt, and a violation aborts the whole run (it's called
    outside the per-file try/except, so PermissionError propagates rather
    than being swallowed as a per-file OSError)."""
    source_root = tmp_path / "source"
    mirror_root = tmp_path / "mirror"
    run_dir = tmp_path / "run"

    _write_jsonl(source_root / "a.jsonl", [{"uuid": "u1", "content": "hi"}])
    _write_text(source_root / "b.txt", "hi\n")

    with mock.patch(
        "sanitize.mirror.assert_write_target_safe",
        side_effect=PermissionError("refusing to write under source tree"),
    ) as spy:
        with pytest.raises(PermissionError):
            build_mirror(source_root, mirror_root, run_dir, "run-1")

    assert spy.call_count == 1  # aborted on the very first file, whichever suffix wins the sort

"""Mirror builder: ~/.claude/projects/**/*.jsonl + **/*.txt -> sanitized mirror.

Per plan §4 (~/.claude/plans/quirky-exploring-map.md), extended by plan §9
(step 4 of the .txt sidecar sync):
- The mirror contains .jsonl and .txt, and nothing else (enforced by the
  hygiene gate at the end of build_mirror() -- sweep .tmp residue, prune
  anything not in this run's successfully-processed set, then assert no
  foreign-suffix file remains).
- Snapshot file list + mtimes at run start, write the snapshot to a run
  directory. Files modified after that instant are excluded from the
  determinism/mtime assertions done by the caller (verification steps 3
  and 5) -- not treated as a bug here.
- .jsonl: line-count-preserving, line-by-line redaction (sanitize/jsonl.py).
  A trailing partial line in a live file is tolerated and omitted from the
  mirror. Judgment call (documented, not silently decided): rather than try
  to detect "which file is the live one" up front, tolerate_trailing_partial
  is passed True uniformly for every .jsonl file in the corpus. This is
  safe: it only ever changes behaviour for a *malformed final line* (any
  malformed *non-final* line still raises unconditionally, per
  sanitize/jsonl.py). A file that happens to have a genuinely corrupt final
  line for an unrelated reason would be silently trimmed by one line
  instead of aborting the whole-corpus run -- accepted as the right
  tradeoff for a full-corpus pass that must not be derailed by one
  in-progress append anywhere in ~8,700 files, several of which belong to
  concurrently-running sessions this process has no way to enumerate up
  front.
- .txt: whole-file redaction (sanitize/text.py), dispatched on suffix
  separately from .jsonl -- it never goes through _line_count() or
  redact_jsonl_file(); its line counts come exclusively from
  TextRedactResult (count("\\n")), never from _line_count()'s
  splitlines(). Mixing the two conventions would silently falsify
  summary.json's line_count_convention field.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from sanitize.engine import RedactionEngine
from sanitize.jsonl import (
    MalformedLineError,
    RedactionStats,
    assert_write_target_safe,
    redact_jsonl_file,
)
from sanitize.text import (
    MAX_TEXT_BYTES,
    AnomalousRedactionSpanError,
    LineGrowthError,
    OversizeTextError,
    redact_text_file,
)

DEFAULT_SOURCE_ROOT = Path.home() / ".claude" / "projects"

# Above this many total .txt skips (oversize + decode + line-growth +
# os-error + anomalous-span, this run), _main() treats the run as a
# failure. Named constant so it's easy to bump as the real corpus's known
# bad files are characterized further.
SKIP_CEILING = 3

# Only these suffixes may exist anywhere under the mirror root once
# build_mirror() completes.
MIRROR_SUFFIX_WHITELIST = {".jsonl", ".txt"}

_TXT_ERROR_PREFIX_TO_FIELD = {
    "OversizeTextError:": "files_skipped_oversize",
    "UnicodeDecodeError:": "files_skipped_decode",
    "LineGrowthError:": "files_skipped_line_growth",
    "AnomalousRedactionSpanError:": "files_skipped_anomalous_span_txt",
}


def _line_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    if text == "":
        return 0
    return len(text.splitlines())


@dataclass
class FileRecord:
    relpath: str
    mtime_ns: int
    size: int


def snapshot_source(source_root: Path) -> dict[str, FileRecord]:
    """relpath -> FileRecord for every *.jsonl and *.txt under source_root,
    at this instant. Sorted union of both globs."""
    out: dict[str, FileRecord] = {}
    paths = sorted(set(source_root.rglob("*.jsonl")) | set(source_root.rglob("*.txt")))
    for p in paths:
        if not p.is_file():
            continue
        st = p.stat()
        rel = str(p.relative_to(source_root))
        out[rel] = FileRecord(relpath=rel, mtime_ns=st.st_mtime_ns, size=st.st_size)
    return out


def snapshot_to_json(snapshot: dict[str, FileRecord]) -> dict:
    return {rel: {"mtime_ns": r.mtime_ns, "size": r.size} for rel, r in snapshot.items()}


@dataclass
class MirrorRunResult:
    run_id: str
    source_root: str
    mirror_root: str
    snapshot_pre: dict[str, FileRecord]
    snapshot_post: dict[str, FileRecord] = field(default_factory=dict)
    processed: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    src_line_counts: dict[str, int] = field(default_factory=dict)
    mirror_line_counts: dict[str, int] = field(default_factory=dict)
    collapsed_txt: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def unchanged_relpaths(self) -> set[str]:
        """Files whose mtime at run end matches their mtime at run start --
        i.e. nothing (this process or any concurrent session) touched them
        during the run. These are the only files eligible for the
        line-count/mtime-unchanged/determinism assertions (plan §4)."""
        out = set()
        for rel, pre in self.snapshot_pre.items():
            post = self.snapshot_post.get(rel)
            if post is not None and post.mtime_ns == pre.mtime_ns and post.size == pre.size:
                out.add(rel)
        return out


def _sweep_stale_tmp_files(mirror_root: Path) -> None:
    """Mechanism 1 of the hygiene gate: unconditionally delete any
    *.jsonl.tmp / *.txt.tmp left over from a prior crashed run."""
    if not mirror_root.exists():
        return
    for p in list(mirror_root.rglob("*.jsonl.tmp")) + list(mirror_root.rglob("*.txt.tmp")):
        if p.is_file():
            p.unlink(missing_ok=True)


def _prune_stale_mirror_files(mirror_root: Path, processed: set[str]) -> None:
    """Mechanism 2 of the hygiene gate: remove any .jsonl/.txt file under
    the mirror whose relpath is NOT in this run's successfully-processed
    set -- covers both a source file deleted upstream and a file that
    newly failed some check this run (oversize, undecodable, anomalous
    span, ...). Keyed on the processed set, not the raw snapshot, so a
    file that's still in the snapshot but was skipped this run is pruned
    too."""
    if not mirror_root.exists():
        return
    for p in list(mirror_root.rglob("*.jsonl")) + list(mirror_root.rglob("*.txt")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(mirror_root))
        if rel not in processed:
            p.unlink()


def _assert_mirror_suffix_whitelist(mirror_root: Path) -> None:
    """Mechanism 3 of the hygiene gate: by the time this runs, mechanism 2
    has already removed every non-processed .jsonl/.txt file, so only a
    genuinely foreign file (never matched by snapshot_source()'s glob)
    could still violate the whitelist. Raises loudly (uncaught) rather
    than silently deleting -- an unexpected file in the mirror is a bug
    worth stopping the run for."""
    if not mirror_root.exists():
        return
    for p in mirror_root.rglob("*"):
        if p.is_file() and p.suffix not in MIRROR_SUFFIX_WHITELIST:
            raise AssertionError(f"foreign file found in mirror (not in {MIRROR_SUFFIX_WHITELIST}): {p}")


def _txt_skip_buckets(errors: dict[str, str]) -> dict[str, list[str]]:
    """Bucket this run's .txt errors into the five named skip categories.

    The first four are matched by literal exception-type prefix (per
    result.errors' f"{type(e).__name__}: {e}" format); anything left over
    is, by elimination, an OS-level error -- a concrete OSError subclass
    (PermissionError, FileNotFoundError, ...), never the literal string
    "OSError:", since type(e).__name__ is always the concrete subclass
    name. MalformedLineError never occurs on a .txt path, so it can't
    land in either bucket.
    """
    buckets: dict[str, list[str]] = {
        "files_skipped_oversize": [],
        "files_skipped_decode": [],
        "files_skipped_line_growth": [],
        "files_skipped_anomalous_span_txt": [],
        "files_skipped_os_error_txt": [],
    }
    for rel, msg in sorted(errors.items()):
        if not rel.endswith(".txt"):
            continue
        for prefix, field_name in _TXT_ERROR_PREFIX_TO_FIELD.items():
            if msg.startswith(prefix):
                buckets[field_name].append(rel)
                break
        else:
            buckets["files_skipped_os_error_txt"].append(rel)
    return buckets


def build_mirror(source_root: Path, mirror_root: Path, run_dir: Path, run_id: str) -> MirrorRunResult:
    """Build the sanitized mirror. Never writes under source_root (enforced
    per-file via assert_write_target_safe, which is source-tree-relative and
    therefore correct regardless of which root is passed here)."""
    source_root = source_root.resolve()
    mirror_root = mirror_root.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    snapshot_pre = snapshot_source(source_root)
    (run_dir / "snapshot-pre.json").write_text(
        json.dumps(snapshot_to_json(snapshot_pre), indent=2), encoding="utf-8"
    )

    engine = RedactionEngine()
    result = MirrorRunResult(
        run_id=run_id,
        source_root=str(source_root),
        mirror_root=str(mirror_root),
        snapshot_pre=snapshot_pre,
    )

    for rel in snapshot_pre:
        src = source_root / rel
        dst = mirror_root / rel
        # Outside the try: a write-target-safety violation must abort the
        # whole run, never be swallowed as a per-file error.
        assert_write_target_safe(dst)
        try:
            if src.suffix == ".jsonl":
                result.src_line_counts[rel] = _line_count(src)
                stats = RedactionStats()
                redact_jsonl_file(src, dst, engine, stats, tolerate_trailing_partial=True)
                result.mirror_line_counts[rel] = _line_count(dst)
                result.processed.append(rel)
            elif src.suffix == ".txt":
                # .txt line counts come exclusively from TextRedactResult
                # (count("\n")) -- _line_count() (splitlines()) is never
                # called for a .txt path, here or anywhere else in this
                # branch.
                stats = RedactionStats()
                text_result = redact_text_file(src, dst, engine, stats)
                result.src_line_counts[rel] = text_result.src_line_count
                result.mirror_line_counts[rel] = text_result.mirror_line_count
                result.processed.append(rel)
                if text_result.collapsed:
                    result.collapsed_txt.append(rel)
            else:  # pragma: no cover - snapshot_source() only yields these two suffixes
                continue
        except (
            MalformedLineError,
            OSError,
            UnicodeDecodeError,
            OversizeTextError,
            LineGrowthError,
            AnomalousRedactionSpanError,
        ) as e:
            result.errors[rel] = f"{type(e).__name__}: {e}"

    # Mirror hygiene gate, in fixed order: sweep stale .tmp -> prune
    # anything not in this run's processed set -> assert only .jsonl/.txt
    # remain. Runs before snapshot_post/summary so the mirror tree is
    # finalized before we report on it.
    _sweep_stale_tmp_files(mirror_root)
    _prune_stale_mirror_files(mirror_root, set(result.processed))
    _assert_mirror_suffix_whitelist(mirror_root)

    snapshot_post = snapshot_source(source_root)
    result.snapshot_post = snapshot_post
    (run_dir / "snapshot-post.json").write_text(
        json.dumps(snapshot_to_json(snapshot_post), indent=2), encoding="utf-8"
    )

    skip_buckets = _txt_skip_buckets(result.errors)

    summary = {
        "run_id": run_id,
        "source_root": result.source_root,
        "mirror_root": result.mirror_root,
        "files_in_snapshot": len(snapshot_pre),
        "files_processed": len(result.processed),
        "files_errored": len(result.errors),
        "errors": result.errors,
        "unchanged_count": len(result.unchanged_relpaths()),
        "src_line_counts": result.src_line_counts,
        "mirror_line_counts": result.mirror_line_counts,
        "files_in_snapshot_jsonl": sum(1 for r in snapshot_pre if r.endswith(".jsonl")),
        "files_in_snapshot_txt": sum(1 for r in snapshot_pre if r.endswith(".txt")),
        "files_processed_jsonl": sum(1 for r in result.processed if r.endswith(".jsonl")),
        "files_processed_txt": sum(1 for r in result.processed if r.endswith(".txt")),
        "files_skipped_oversize": len(skip_buckets["files_skipped_oversize"]),
        "files_skipped_decode": len(skip_buckets["files_skipped_decode"]),
        "files_skipped_line_growth": len(skip_buckets["files_skipped_line_growth"]),
        "files_skipped_os_error_txt": len(skip_buckets["files_skipped_os_error_txt"]),
        "files_skipped_anomalous_span_txt": len(skip_buckets["files_skipped_anomalous_span_txt"]),
        "skipped_txt_paths": skip_buckets,
        "files_line_collapsed_txt": len(result.collapsed_txt),
        "line_count_convention": {"jsonl": "splitlines()", "txt": "count(\\n)"},
    }
    result.summary = summary
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return result


def redact_check(source_root: Path) -> dict[str, dict[str, int]]:
    """Dry-run: for every *.jsonl and *.txt under source_root, report
    entity-type counts a real redaction pass would find, without writing
    anything. Used by `just redact-check` (plan §Verification step 2) to
    sanity-check that the known-credential files still appear before
    running the full (writing) mirror build.

    .txt files decode with errors="replace" (not strict) -- this is a
    read-only report, not a write path, so the strict-decode leak-vector
    concern in sanitize/text.py doesn't apply here; inheriting it would
    abort the whole check on one known-bad-encoding file in the real
    corpus."""
    from sanitize.jsonl import redact_value, RedactionStats

    engine = RedactionEngine()
    out: dict[str, dict[str, int]] = {}
    paths = sorted(set(source_root.rglob("*.jsonl")) | set(source_root.rglob("*.txt")))
    for p in paths:
        if not p.is_file():
            continue
        stats = RedactionStats()
        if p.suffix == ".jsonl":
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for raw_line in text.splitlines():
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue  # dry-run: skip malformed lines silently, no write to protect
                redact_value(obj, (), engine, stats)
        elif p.suffix == ".txt":
            try:
                if p.stat().st_size > MAX_TEXT_BYTES:
                    continue
                text = p.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                continue
            _, entity_types, _ = engine.redact(text, "broad_pii")
            if entity_types:
                stats.add(entity_types)
        if stats.entity_counts:
            out[str(p.relative_to(source_root))] = dict(stats.entity_counts)
    return out


def hash_files(root: Path, relpaths: set[str]) -> dict[str, str]:
    """sha256 of each file in relpaths, resolved under root. Used by the
    verification step-5 determinism check to compare two mirror-build runs'
    output for the intersection of both runs' unchanged-file sets, since the
    mirror destination is overwritten in place on each run."""
    import hashlib

    out = {}
    for rel in sorted(relpaths):
        p = root / rel
        if not p.is_file():
            continue
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _txt_skip_total(summary: dict) -> int:
    return sum(
        summary[k]
        for k in (
            "files_skipped_oversize",
            "files_skipped_decode",
            "files_skipped_line_growth",
            "files_skipped_os_error_txt",
            "files_skipped_anomalous_span_txt",
        )
    )


def _write_fixed_summary(result: MirrorRunResult, skip_ceiling_exceeded: bool) -> Path:
    """Write the always-current, fixed-path copy of summary.json at
    $MIRROR/../summary.json (sibling of the mirror directory, NOT the
    timestamped mirror-runs/<run_id>/summary.json) -- this is what
    bin/sync-local.sh reads later. A straight copy of the timestamped
    summary plus the skip_ceiling_exceeded verdict."""
    fixed_path = Path(result.mirror_root).parent / "summary.json"
    fixed_summary = dict(result.summary)
    fixed_summary["skip_ceiling_exceeded"] = skip_ceiling_exceeded
    fixed_path.write_text(json.dumps(fixed_summary, indent=2), encoding="utf-8")
    return fixed_path


def run_build(source: Path, dest: Path, run_dir_base: Path, run_id: str | None = None) -> tuple[MirrorRunResult, bool]:
    """Build the mirror for one run and decide pass/fail per the exit-code
    policy: fail if EITHER this run's total .txt skips exceed SKIP_CEILING,
    OR result.errors contains any .jsonl entry (a newly-malformed .jsonl
    would otherwise be silently pruned from the mirror with exit 0).

    Also writes the fixed-path summary.json copy (see _write_fixed_summary)
    -- only reached if build_mirror() returns normally, so an unenumerated
    exception raised mid-build propagates out of this function too and the
    fixed-path file is left untouched (stale, not overwritten with a
    mid-crash snapshot).

    Factored out of _main() so the exit-code policy is testable without
    shelling out to the CLI.
    """
    if run_id is None:
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = run_dir_base / run_id
    result = build_mirror(source, dest, run_dir, run_id)

    jsonl_errors = {rel: msg for rel, msg in result.errors.items() if rel.endswith(".jsonl")}
    skip_ceiling_exceeded = _txt_skip_total(result.summary) > SKIP_CEILING
    should_fail = skip_ceiling_exceeded or bool(jsonl_errors)

    _write_fixed_summary(result, skip_ceiling_exceeded)

    return result, should_fail


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build or dry-run-check the sanitized jsonl/txt mirror.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    build_p = sub.add_parser("build", help="build the mirror (writes)")
    build_p.add_argument("--source", type=Path, default=DEFAULT_SOURCE_ROOT)
    build_p.add_argument("--dest", type=Path, required=True)
    build_p.add_argument("--run-dir", type=Path, required=True)

    check_p = sub.add_parser("check", help="dry-run: report what would be redacted, write nothing")
    check_p.add_argument("--source", type=Path, default=DEFAULT_SOURCE_ROOT)

    args = parser.parse_args()

    if args.cmd == "build":
        result, should_fail = run_build(args.source, args.dest, args.run_dir)
        print(f"run_id={result.run_id}")
        print(f"files_in_snapshot={len(result.snapshot_pre)}")
        print(f"files_processed={len(result.processed)}")
        print(f"files_errored={len(result.errors)}")
        print(f"unchanged_count={len(result.unchanged_relpaths())}")
        print(f"run_dir={args.run_dir / result.run_id}")
        if result.errors:
            print("ERRORS:")
            for rel, msg in result.errors.items():
                print(f"  {rel}: {msg}")
        if should_fail:
            print("FAILED: skip ceiling exceeded or .jsonl error present", file=sys.stderr)
            sys.exit(1)
    elif args.cmd == "check":
        findings = redact_check(args.source)
        print(f"files_with_findings={len(findings)}")
        total_entities: dict[str, int] = {}
        for counts in findings.values():
            for k, v in counts.items():
                total_entities[k] = total_entities.get(k, 0) + v
        print("entity totals:")
        for k, v in sorted(total_entities.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("files:")
        for rel, counts in sorted(findings.items()):
            print(f"  {rel}: {counts}")


if __name__ == "__main__":
    _main()

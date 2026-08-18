"""Mirror builder: ~/.claude/projects/**/*.jsonl -> sanitized mirror.

Per plan §4 (~/.claude/plans/quirky-exploring-map.md):
- The mirror contains .jsonl and nothing else.
- Snapshot file list + mtimes at run start, write the snapshot to a run
  directory. Files modified after that instant are excluded from the
  determinism/mtime assertions done by the caller (verification steps 3
  and 5) -- not treated as a bug here.
- A trailing partial line in a live file is tolerated and omitted from the
  mirror. Judgment call (documented, not silently decided): rather than try
  to detect "which file is the live one" up front, tolerate_trailing_partial
  is passed True uniformly for every file in the corpus. This is safe: it
  only ever changes behaviour for a *malformed final line* (any malformed
  *non-final* line still raises unconditionally, per sanitize/jsonl.py). A
  file that happens to have a genuinely corrupt final line for an unrelated
  reason would be silently trimmed by one line instead of aborting the
  whole-corpus run -- accepted as the right tradeoff for a full-corpus pass
  that must not be derailed by one in-progress append anywhere in ~8,700
  files, several of which belong to concurrently-running sessions this
  process has no way to enumerate up front.
"""

from __future__ import annotations

import json
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

DEFAULT_SOURCE_ROOT = Path.home() / ".claude" / "projects"


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
    """relpath -> FileRecord for every *.jsonl under source_root, at this instant."""
    out: dict[str, FileRecord] = {}
    for p in sorted(source_root.rglob("*.jsonl")):
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
        assert_write_target_safe(dst)
        try:
            result.src_line_counts[rel] = _line_count(src)
            stats = RedactionStats()
            redact_jsonl_file(src, dst, engine, stats, tolerate_trailing_partial=True)
            result.mirror_line_counts[rel] = _line_count(dst)
            result.processed.append(rel)
        except (MalformedLineError, OSError, UnicodeDecodeError) as e:
            result.errors[rel] = f"{type(e).__name__}: {e}"

    snapshot_post = snapshot_source(source_root)
    result.snapshot_post = snapshot_post
    (run_dir / "snapshot-post.json").write_text(
        json.dumps(snapshot_to_json(snapshot_post), indent=2), encoding="utf-8"
    )

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
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return result


def redact_check(source_root: Path) -> dict[str, dict[str, int]]:
    """Dry-run: for every *.jsonl under source_root, report entity-type
    counts a real redaction pass would find, without writing anything.
    Used by `just redact-check` (plan §Verification step 2) to sanity-check
    that the known-credential files still appear before running the full
    (writing) mirror build."""
    from sanitize.jsonl import redact_value, RedactionStats

    engine = RedactionEngine()
    out: dict[str, dict[str, int]] = {}
    for p in sorted(source_root.rglob("*.jsonl")):
        if not p.is_file():
            continue
        stats = RedactionStats()
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


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build or dry-run-check the sanitized jsonl mirror.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    build_p = sub.add_parser("build", help="build the mirror (writes)")
    build_p.add_argument("--source", type=Path, default=DEFAULT_SOURCE_ROOT)
    build_p.add_argument("--dest", type=Path, required=True)
    build_p.add_argument("--run-dir", type=Path, required=True)

    check_p = sub.add_parser("check", help="dry-run: report what would be redacted, write nothing")
    check_p.add_argument("--source", type=Path, default=DEFAULT_SOURCE_ROOT)

    args = parser.parse_args()

    if args.cmd == "build":
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        run_dir = args.run_dir / run_id
        result = build_mirror(args.source, args.dest, run_dir, run_id)
        print(f"run_id={run_id}")
        print(f"files_in_snapshot={len(result.snapshot_pre)}")
        print(f"files_processed={len(result.processed)}")
        print(f"files_errored={len(result.errors)}")
        print(f"unchanged_count={len(result.unchanged_relpaths())}")
        print(f"run_dir={run_dir}")
        if result.errors:
            print("ERRORS:")
            for rel, msg in result.errors.items():
                print(f"  {rel}: {msg}")
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

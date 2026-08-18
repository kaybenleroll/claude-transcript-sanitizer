"""Line-count-preserving jsonl sanitizer.

Per plan §3 (~/.claude/plans/quirky-exploring-map.md):
- json.loads -> recursive walk with a path tuple -> redact string leaves ->
  json.dumps -> write. Never regex over raw bytes.
- Two profiles by JSON path: narrow (message/content text, content, summary,
  title) gets credentials + EMAIL_ADDRESS/PHONE_NUMBER/IP_ADDRESS; broad
  (everything else, incl. tool_use/tool_result) gets credentials only.
- Structural keys are a keep-list, deny-by-default, so unknown future
  fields get scanned rather than skipped.
- Hard invariant: line-count preserving. Every replacement newline-free,
  asserted per line. Write to .tmp, re-parse every line, os.replace.
  Malformed non-final line -> raise, leave original untouched. A truncated
  final line in a known-live file is omitted from the mirror, not raised.
- Redaction log: entity-type counts only, never matched values.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from sanitize.engine import RedactionEngine

# Structural keys never scanned for PII/credentials — a KEEP-list, so any
# key not on this list defaults to being scanned (deny-by-default).
STRUCTURAL_KEEP_KEYS = {
    "uuid",
    "sessionId",
    "parentUuid",
    "timestamp",
    "cwd",
    "version",
    "gitBranch",
    "userType",
    "type",
    "isSidechain",
    "requestId",
    "id",
    "role",
    "model",
    "stop_reason",
    "stop_sequence",
    "usage",
}

# JSON path suffixes (tuples of str/int, where int means "any array index")
# that select the NARROW profile. All other string leaves get BROAD.
NARROW_PATH_SUFFIXES: list[tuple] = [
    ("message", "content", "*", "text"),
    ("content",),
    ("summary",),
    ("title",),
]


class MalformedLineError(ValueError):
    pass


def _path_matches_narrow(path: tuple) -> bool:
    """Exact match from the record root against NARROW_PATH_SUFFIXES.

    Deliberately exact-from-root, not a suffix/substring match: '.content'
    means the top-level 'content' key on the record, not any nested field
    happening to be named 'content' (e.g. a tool_result's own .content leaf,
    which must stay on the broad/credentials-only profile per plan §3).
    """
    if len(path) not in {1, 4}:
        return False
    for suffix in NARROW_PATH_SUFFIXES:
        if len(path) != len(suffix):
            continue
        ok = True
        for a, b in zip(path, suffix):
            if b == "*":
                if not isinstance(a, int):
                    ok = False
                    break
            elif a != b:
                ok = False
                break
        if ok:
            return True
    return False


@dataclass
class RedactionStats:
    entity_counts: dict[str, int] = field(default_factory=dict)

    def add(self, entity_types: list[str]) -> None:
        for t in entity_types:
            self.entity_counts[t] = self.entity_counts.get(t, 0) + 1


def redact_value(value, path: tuple, engine: RedactionEngine, stats: RedactionStats):
    """Recursively redact string leaves in `value`, keyed by JSON path."""
    if isinstance(value, dict):
        return {
            k: (value[k] if k in STRUCTURAL_KEEP_KEYS else redact_value(value[k], path + (k,), engine, stats))
            for k in value
        }
    if isinstance(value, list):
        return [redact_value(v, path + (i,), engine, stats) for i, v in enumerate(value)]
    if isinstance(value, str):
        profile = "narrow" if _path_matches_narrow(path) else "broad"
        redacted, entity_types = engine.redact(value, profile)
        if entity_types:
            stats.add(entity_types)
        return redacted
    return value


def redact_line(raw_line: str, engine: RedactionEngine, stats: RedactionStats) -> str:
    """Redact one jsonl line (no trailing newline). Raises MalformedLineError
    on invalid JSON. Raises ValueError if a replacement introduces a newline
    (the line-count-preserving invariant)."""
    try:
        obj = json.loads(raw_line)
    except json.JSONDecodeError as e:
        raise MalformedLineError(str(e)) from e

    stats_before_count = len(stats.entity_counts)
    redacted_obj = redact_value(obj, (), engine, stats)
    out = json.dumps(redacted_obj, ensure_ascii=False)

    if "\n" in out or "\r" in out:
        raise ValueError("redaction introduced a newline — line-count invariant violated")

    del stats_before_count  # reserved for future per-line stats if needed
    return out


def redact_jsonl_file(
    src_path: Path,
    dst_path: Path,
    engine: RedactionEngine,
    stats: RedactionStats,
    *,
    tolerate_trailing_partial: bool = False,
) -> None:
    """Redact `src_path` line-by-line into `dst_path`, preserving line count.

    Writes to `dst_path.with_suffix(dst_path.suffix + ".tmp")` first, re-parses
    every line of the tmp output, then os.replace()s into place. A malformed
    non-final line raises and leaves `dst_path` untouched (original, if any,
    is not overwritten). If `tolerate_trailing_partial` is True, a malformed
    *final* line is treated as an in-progress append and omitted from the
    output (not raised, not copied verbatim) — see plan §4 live-file handling.
    """
    raw_text = src_path.read_text(encoding="utf-8")
    had_trailing_newline = raw_text.endswith("\n")
    src_lines = raw_text.splitlines()

    out_lines: list[str] = []
    for i, raw_line in enumerate(src_lines):
        is_last = i == len(src_lines) - 1
        if raw_line == "":
            out_lines.append("")
            continue
        try:
            out_lines.append(redact_line(raw_line, engine, stats))
        except MalformedLineError:
            if is_last and tolerate_trailing_partial:
                # Omit the truncated trailing line entirely — do not append
                # it, redacted or verbatim. Line count drops by one; callers
                # that need count-parity for a known-live file account for
                # this via the run-start snapshot (plan §4), not here.
                continue
            raise

    tmp_path = dst_path.with_suffix(dst_path.suffix + ".tmp")
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
        if out_lines and had_trailing_newline:
            f.write("\n")

    # Re-parse every line of the tmp output before committing.
    with tmp_path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if line == "":
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                tmp_path.unlink(missing_ok=True)
                raise MalformedLineError(
                    f"re-parse failed at output line {lineno}: {e}"
                ) from e

    os.replace(tmp_path, dst_path)


PROJECTS_DIR_MARKER = os.path.join(".claude", "projects")


def assert_write_target_safe(path: Path) -> None:
    """Refuse to write under any path resolving to ~/.claude/projects/.

    Fail-closed per plan: 'Every write path asserts its target does not
    resolve under ~/.claude/projects/; violation aborts fail-closed.'
    """
    resolved = path.resolve()
    home_claude_projects = (Path.home() / ".claude" / "projects").resolve()
    try:
        resolved.relative_to(home_claude_projects)
    except ValueError:
        return
    raise PermissionError(
        f"refusing to write under source tree: {resolved} resolves under {home_claude_projects}"
    )


def write_redaction_log(stats: RedactionStats, log_path: Path) -> None:
    """Append entity-type counts only (never matched values) as one jsonl line."""
    import datetime

    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entity_counts": stats.entity_counts,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


DEFAULT_REDACTION_LOG_PATH = Path.home() / ".local" / "state" / "claude-transcript-sanitizer" / "redaction-log.jsonl"

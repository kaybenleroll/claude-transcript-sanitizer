"""Whole-file .txt sidecar sanitizer (see sanitize/jsonl.py for the line-by-
line jsonl equivalent).

Per plan §9: text files are redacted as a single whole-file `broad_pii`
pass through `RedactionEngine.redact()` -- no chunking, no line-by-line
JSON parsing (there is no JSON structure to walk). This is the single,
defined data path for summary.json's src_line_counts / mirror_line_counts /
files_line_collapsed_txt counters for .txt files (populated by mirror.py,
a later step, from this module's return value and raised exceptions).

Safety checks, in order:
  1. Oversize guard (stat() before any read) -- OversizeTextError.
  2. Strict UTF-8 decode -- lets UnicodeDecodeError propagate naturally.
  3. Match-span sanity check on SOURCE-text spans, before any write --
     AnomalousRedactionSpanError. Regression guard for a measured
     unbounded-span bug where a whole-file PRIVATE_KEY_BLOCK match can
     span two unrelated PEM marker mentions far apart in one file.
  4. Line-growth guard on \\n and \\r counts of the POST-restoration
     string, computed against the original decoded source -- LineGrowthError.
  5. Residue check (only when >=1 entity was found) -- a bare `assert`,
     deliberately NOT one of the three custom exception types above, so it
     is never caught by an except clause added later in mirror.py and
     aborts the whole run loudly.
  6. Write to a `.tmp` sibling (mirrors sanitize/jsonl.py's own
     write-tmp-then-os.replace convention), then os.replace() into place.
     Any exception raised anywhere in this function unlinks a
     already-created `.tmp` file before propagating -- no `.tmp` residue
     ever survives an error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sanitize.engine import RedactionEngine
from sanitize.jsonl import RedactionStats

MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_SINGLE_MATCH_SPAN = 64 * 1024  # generous vs. real PEM keys (~1-4 KB); see step 4a


class OversizeTextError(Exception):
    pass


class LineGrowthError(ValueError):
    pass


class AnomalousRedactionSpanError(Exception):
    """A single entity match spans an implausibly large range of source text."""


@dataclass
class TextRedactResult:
    src_line_count: int
    mirror_line_count: int
    collapsed: bool


def redact_text_file(
    src_path: Path,
    dst_path: Path,
    engine: RedactionEngine,
    stats: RedactionStats,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
) -> TextRedactResult:
    """Redact `src_path` as a single whole-file pass into `dst_path`.

    Writes `dst_path.with_suffix(dst_path.suffix + ".tmp")` first, then
    os.replace()s into place. Raises (and leaves `dst_path` untouched, with
    no `.tmp` residue) on: oversize source, invalid UTF-8, an anomalously
    large single match span, output line/CR growth, or a failed residue
    re-check.
    """
    # 1. Size guard, before any read.
    size = src_path.stat().st_size
    if size > max_bytes:
        raise OversizeTextError(
            f"{src_path}: {size} bytes exceeds max_bytes={max_bytes}"
        )

    # 2. Strict UTF-8 decode -- UnicodeDecodeError propagates as-is.
    raw_bytes = src_path.read_bytes()
    text = raw_bytes.decode("utf-8")

    # 3. Trailing-newline flag, recorded before redaction.
    had_trailing_newline = text.endswith("\n")

    # 4. Whole-file redaction, one call, no chunking.
    redacted, entity_types, spans = engine.redact(text, "broad_pii")

    # 4a. Match-span sanity check on SOURCE-text spans -- before any write.
    for start, end in spans:
        span_len = end - start
        if span_len > MAX_SINGLE_MATCH_SPAN:
            raise AnomalousRedactionSpanError(
                f"{src_path}: match span of {span_len} bytes exceeds "
                f"MAX_SINGLE_MATCH_SPAN={MAX_SINGLE_MATCH_SPAN} "
                f"(source offsets {start}-{end})"
            )

    # 5. Restore the trailing-newline flag; all line counts are computed
    # from this final, post-restoration string.
    if had_trailing_newline and not redacted.endswith("\n"):
        redacted = redacted + "\n"

    src_line_count = text.count("\n")
    src_cr_count = text.count("\r")
    mirror_line_count = redacted.count("\n")
    mirror_cr_count = redacted.count("\r")

    if mirror_line_count > src_line_count or mirror_cr_count > src_cr_count:
        raise LineGrowthError(
            f"{src_path}: mirror grew ({src_line_count}->{mirror_line_count} '\\n', "
            f"{src_cr_count}->{mirror_cr_count} '\\r')"
        )

    collapsed = mirror_line_count < src_line_count or mirror_cr_count < src_cr_count

    # 6. Residue check, only when step 4 found >= 1 entity. Deliberately a
    # bare assert (not one of the three custom exception types) so it is
    # never caught by an except clause added later in mirror.py -- it must
    # propagate and abort the whole run loudly. Runs before the write.
    if entity_types:
        _, residue_entities, _ = engine.redact(redacted, "broad_pii")
        assert not residue_entities, (
            f"{src_path}: residue check found leftover entities after "
            f"redaction: {residue_entities}"
        )
        stats.add(entity_types)

    # 7. Write .tmp, then os.replace(). Any exception from here on unlinks
    # a created .tmp file before propagating.
    tmp_path = dst_path.with_suffix(dst_path.suffix + ".tmp")
    try:
        tmp_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(redacted, encoding="utf-8")
        os.replace(tmp_path, dst_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return TextRedactResult(
        src_line_count=src_line_count,
        mirror_line_count=mirror_line_count,
        collapsed=collapsed,
    )

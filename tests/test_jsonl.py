import json
from pathlib import Path

import pytest

from sanitize.jsonl import (
    MalformedLineError,
    RedactionStats,
    assert_write_target_safe,
    redact_jsonl_file,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _line_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    if text == "":
        return 0
    return len(text.splitlines())


def test_line_count_preserved_clean(engine, tmp_path):
    src = FIXTURES_DIR / "clean.jsonl"
    dst = tmp_path / "clean.out.jsonl"
    stats = RedactionStats()
    redact_jsonl_file(src, dst, engine, stats)
    assert _line_count(dst) == _line_count(src)


def test_line_count_preserved_credentials(engine, tmp_path):
    src = FIXTURES_DIR / "credentials.jsonl"
    dst = tmp_path / "credentials.out.jsonl"
    stats = RedactionStats()
    redact_jsonl_file(src, dst, engine, stats)
    assert _line_count(dst) == _line_count(src)
    # Every original line still parses as JSON, unchanged count.
    for line in dst.read_text(encoding="utf-8").splitlines():
        json.loads(line)


def test_credentials_redacted_from_all_profiles(engine, tmp_path):
    src = FIXTURES_DIR / "credentials.jsonl"
    dst = tmp_path / "credentials.out.jsonl"
    stats = RedactionStats()
    redact_jsonl_file(src, dst, engine, stats)
    out_text = dst.read_text(encoding="utf-8")
    assert "sk-ant-api03-FAKE" not in out_text
    assert "sk-or-v1-FAKE" not in out_text
    assert "ghp_FAKE" not in out_text
    assert stats.entity_counts.get("ANTHROPIC_API_KEY", 0) >= 1
    assert stats.entity_counts.get("OPENROUTER_API_KEY", 0) >= 1


def test_profile_selection_narrow_vs_broad_email(engine, tmp_path):
    """Same email: redacted in .message.content[].text (narrow), left
    intact in a tool_result's .content leaf (broad, credentials-only)."""
    src = FIXTURES_DIR / "credentials.jsonl"
    dst = tmp_path / "credentials.out.jsonl"
    stats = RedactionStats()
    redact_jsonl_file(src, dst, engine, stats)
    lines = dst.read_text(encoding="utf-8").splitlines()

    narrow_line = json.loads(lines[2])  # u3: message.content[].text
    narrow_text = narrow_line["message"]["content"][0]["text"]
    assert "test.user@example-corp.com" not in narrow_text
    assert "[EMAIL_ADDRESS]" in narrow_text

    broad_line = json.loads(lines[3])  # u4: tool_result.content
    broad_text = broad_line["message"]["content"][0]["content"]
    assert "test.user@example-corp.com" in broad_text


def test_malformed_middle_line_raises_and_leaves_original_untouched(engine, tmp_path):
    src = FIXTURES_DIR / "malformed_middle.jsonl"
    dst = tmp_path / "malformed.out.jsonl"
    stats = RedactionStats()
    with pytest.raises(MalformedLineError):
        redact_jsonl_file(src, dst, engine, stats)
    assert not dst.exists()
    tmp_marker = dst.with_suffix(dst.suffix + ".tmp")
    assert not tmp_marker.exists()


def test_truncated_trailing_line_raises_without_tolerate_flag(engine, tmp_path):
    src = FIXTURES_DIR / "truncated_trailing.jsonl"
    dst = tmp_path / "truncated.out.jsonl"
    stats = RedactionStats()
    with pytest.raises(MalformedLineError):
        redact_jsonl_file(src, dst, engine, stats, tolerate_trailing_partial=False)
    assert not dst.exists()


def test_truncated_trailing_line_omitted_with_tolerate_flag(engine, tmp_path):
    src = FIXTURES_DIR / "truncated_trailing.jsonl"
    dst = tmp_path / "truncated.out.jsonl"
    stats = RedactionStats()
    redact_jsonl_file(src, dst, engine, stats, tolerate_trailing_partial=True)
    assert dst.exists()
    out_lines = dst.read_text(encoding="utf-8").splitlines()
    # Source has 2 lines (one truncated); output must have exactly 1 —
    # the truncated line is omitted, not raised, not copied verbatim.
    assert len(out_lines) == 1
    json.loads(out_lines[0])  # still valid JSON
    assert "mid-append trunc" not in dst.read_text(encoding="utf-8")


def test_write_target_refused_under_claude_projects(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    (fake_home / ".claude" / "projects" / "proj1").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    bad_target = fake_home / ".claude" / "projects" / "proj1" / "out.jsonl"
    with pytest.raises(PermissionError):
        assert_write_target_safe(bad_target)


def test_write_target_allowed_outside_claude_projects(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    good_target = tmp_path / "sanitized-mirror" / "projects" / "proj1" / "out.jsonl"
    assert_write_target_safe(good_target) is None

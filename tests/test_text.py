from pathlib import Path

import pytest

from sanitize.jsonl import RedactionStats
from sanitize.text import (
    AnomalousRedactionSpanError,
    LineGrowthError,
    MAX_SINGLE_MATCH_SPAN,
    OversizeTextError,
    TextRedactResult,
    redact_text_file,
)


def _tmp_marker(dst: Path) -> Path:
    return dst.with_suffix(dst.suffix + ".tmp")


def test_clean_roundtrip_byte_identical(engine, tmp_path):
    text = "just some ordinary log lines\nwith nothing sensitive in them\ngoodbye\n"
    src = tmp_path / "clean.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "clean.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    assert dst.read_bytes() == src.read_bytes()
    assert result == TextRedactResult(src_line_count=3, mirror_line_count=3, collapsed=False)
    assert not stats.entity_counts


def test_single_line_credential_with_trailing_newline(engine, tmp_path):
    text = "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD\n"
    src = tmp_path / "cred.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "cred.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "sk-ant-api03-FAKE" not in out
    assert out.endswith("\n")
    assert result.src_line_count == 1
    assert result.mirror_line_count == 1
    assert result.collapsed is False


def test_single_line_credential_without_trailing_newline(engine, tmp_path):
    text = "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD"
    src = tmp_path / "cred.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "cred.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "sk-ant-api03-FAKE" not in out
    assert not out.endswith("\n")
    assert result.src_line_count == 0
    assert result.mirror_line_count == 0
    assert result.collapsed is False


def test_last_line_credential_with_trailing_newline(engine, tmp_path):
    text = (
        "preamble line one\n"
        "preamble line two\n"
        "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD\n"
    )
    src = tmp_path / "last.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "last.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "sk-ant-api03-FAKE" not in out
    assert out.endswith("\n")
    assert result.src_line_count == 3
    assert result.mirror_line_count == 3
    assert result.collapsed is False


def test_last_line_credential_without_trailing_newline(engine, tmp_path):
    text = (
        "preamble line one\n"
        "preamble line two\n"
        "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD"
    )
    src = tmp_path / "last.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "last.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "sk-ant-api03-FAKE" not in out
    assert not out.endswith("\n")
    assert result.src_line_count == 2
    assert result.mirror_line_count == 2
    assert result.collapsed is False


def test_crlf_clean_roundtrip(engine, tmp_path):
    text = "line one\r\nline two\r\nline three\r\n"
    src = tmp_path / "crlf.txt"
    src.write_bytes(text.encode("utf-8"))
    dst = tmp_path / "crlf.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    assert dst.read_bytes() == src.read_bytes()
    assert result == TextRedactResult(src_line_count=3, mirror_line_count=3, collapsed=False)


def test_empty_file(engine, tmp_path):
    src = tmp_path / "empty.txt"
    src.write_text("", encoding="utf-8")
    dst = tmp_path / "empty.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    assert dst.exists()
    assert dst.read_bytes() == b""
    assert result == TextRedactResult(src_line_count=0, mirror_line_count=0, collapsed=False)


def test_invalid_utf8_raises_and_leaves_no_residue(engine, tmp_path):
    src = tmp_path / "bad.txt"
    src.write_bytes(b"hello \xff\xfe world")
    dst = tmp_path / "bad.out.txt"
    stats = RedactionStats()

    with pytest.raises(UnicodeDecodeError):
        redact_text_file(src, dst, engine, stats)

    assert not dst.exists()
    assert not _tmp_marker(dst).exists()


def test_oversize_raises_before_read(engine, tmp_path, monkeypatch):
    src = tmp_path / "big.txt"
    src.write_bytes(b"x" * 100)
    dst = tmp_path / "big.out.txt"
    stats = RedactionStats()

    def fail_read_bytes(self):
        raise AssertionError("read_bytes should not be called when oversize")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    with pytest.raises(OversizeTextError):
        redact_text_file(src, dst, engine, stats, max_bytes=10)

    assert not dst.exists()
    assert not _tmp_marker(dst).exists()


def test_idempotency_running_twice_produces_same_output(engine, tmp_path):
    text = (
        "hello there\n"
        "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD\n"
        "goodbye\n"
    )
    src = tmp_path / "idem.txt"
    src.write_text(text, encoding="utf-8")
    dst1 = tmp_path / "idem.out1.txt"
    dst2 = tmp_path / "idem.out2.txt"

    redact_text_file(src, dst1, engine, RedactionStats())
    redact_text_file(src, dst2, engine, RedactionStats())

    assert dst1.read_bytes() == dst2.read_bytes()


def test_full_pem_block_redacted_with_fewer_lines(engine, tmp_path):
    body_line = "MIIEowIBAAKCAQEA1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm\n"
    text = "-----BEGIN RSA PRIVATE KEY-----\n" + body_line * 4 + "-----END RSA PRIVATE KEY-----\n"
    src = tmp_path / "pem.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "pem.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "[PRIVATE_KEY]" in out
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert "MIIEowIBAAKCAQEA" not in out
    assert result.mirror_line_count < result.src_line_count
    assert result.collapsed is True


def test_env_assignment_secret_mid_line_glues_next_line_on(engine, tmp_path):
    """Regression test documenting expected behaviour, not a bug: the
    ENV_ASSIGNMENT_SECRET pattern's trailing terminator can consume the
    newline right after the matched value, collapsing the following line
    onto the same output line."""
    text = "line0\nAPI_KEY=abc123XYZsuperlonglooooooongsecretvalue1234567890\nafter\n"
    src = tmp_path / "glue.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "glue.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "[ENV_ASSIGNMENT_SECRET]after" in out
    assert result.collapsed is True
    assert result.mirror_line_count < result.src_line_count


def test_numeric_heavy_fixture_unmodified_under_broad_pii(engine, tmp_path):
    """broad_pii deliberately excludes PHONE_NUMBER -- a phone-number-shaped
    string, plus other numeric/date-like content, must survive untouched."""
    text = (
        "Call us at +1-202-555-0179 for support.\n"
        "Processed 128000 context tokens on 2026-08-19.\n"
        "Totals: 100, 200, 300.\n"
    )
    src = tmp_path / "numeric.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "numeric.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    assert dst.read_text(encoding="utf-8") == text
    assert result.collapsed is False
    assert not stats.entity_counts


def test_email_and_rfc1918_ip_both_redacted(engine, tmp_path):
    text = "Contact alice@example.com from 10.0.0.5 for access.\n"
    src = tmp_path / "pii.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "pii.out.txt"
    stats = RedactionStats()

    redact_text_file(src, dst, engine, stats)

    out = dst.read_text(encoding="utf-8")
    assert "alice@example.com" not in out
    assert "10.0.0.5" not in out
    assert "[EMAIL_ADDRESS]" in out
    assert "[IP_ADDRESS]" in out


def test_two_unrelated_pem_markers_far_apart_raises_anomalous_span(engine, tmp_path):
    """Regression test for the measured unbounded-span bug: a whole-file
    PRIVATE_KEY_BLOCK match spanning two unrelated PEM marker mentions far
    apart in one file must be rejected before any write."""
    filler = "x" * (MAX_SINGLE_MATCH_SPAN + 5000)
    text = f"-----BEGIN RSA PRIVATE KEY-----\n{filler}\n-----END RSA PRIVATE KEY-----\n"
    src = tmp_path / "anomalous.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "anomalous.out.txt"
    stats = RedactionStats()

    with pytest.raises(AnomalousRedactionSpanError):
        redact_text_file(src, dst, engine, stats)

    assert not dst.exists()
    assert not _tmp_marker(dst).exists()


def test_residue_check_failure_propagates_before_any_write(engine, tmp_path, monkeypatch):
    text = "ANTHROPIC_API_KEY=sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD\n"
    src = tmp_path / "residue.txt"
    src.write_text(text, encoding="utf-8")
    dst = tmp_path / "residue.out.txt"
    stats = RedactionStats()

    original_redact = engine.redact
    call_count = {"n": 0}

    def fake_redact(text_arg, profile):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return original_redact(text_arg, profile)
        # Second call is the residue re-check -- force a leftover finding.
        return text_arg, ["FAKE_LEFTOVER_ENTITY"], []

    monkeypatch.setattr(engine, "redact", fake_redact)

    with pytest.raises(AssertionError):
        redact_text_file(src, dst, engine, stats)

    assert call_count["n"] == 2
    assert not dst.exists()
    assert not _tmp_marker(dst).exists()


def test_crlf_with_trailing_credential_collapses_via_cr_count(engine, tmp_path):
    """Regression test for the CRLF-swallowed-quietly bug: a credential on
    the final line whose trailing \\r gets consumed by the match must be
    detected as collapsed via the \\r count, even though the \\n count is
    unchanged."""
    text = (
        "line1\r\n"
        "line2\r\n"
        "API_KEY=abc123XYZsuperlonglooooooongsecretvalue1234567890\r\n"
    )
    src = tmp_path / "crlf_cred.txt"
    src.write_bytes(text.encode("utf-8"))
    dst = tmp_path / "crlf_cred.out.txt"
    stats = RedactionStats()

    result = redact_text_file(src, dst, engine, stats)

    out = dst.read_bytes().decode("utf-8")
    assert "abc123XYZsuperlonglooooooongsecretvalue1234567890" not in out
    assert result.src_line_count == result.mirror_line_count  # \n count unchanged
    assert result.collapsed is True  # but \r count dropped

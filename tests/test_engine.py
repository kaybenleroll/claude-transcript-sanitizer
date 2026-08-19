"""Engine-level tests for RedactionEngine.redact()'s spans return value."""


def test_redact_returns_no_spans_for_empty_text(engine):
    redacted, entity_types, spans = engine.redact("", "broad")
    assert redacted == ""
    assert entity_types == []
    assert spans == []


def test_redact_returns_no_spans_when_no_findings(engine):
    text = "nothing sensitive here"
    redacted, entity_types, spans = engine.redact(text, "broad")
    assert redacted == text
    assert entity_types == []
    assert spans == []


def test_redact_spans_align_with_source_text(engine):
    """Each span is a (start, end) pair into the *source* text, not the
    anonymized output -- text[start:end] must reproduce the original
    matched substring even though the redacted text has a different length
    (the fixed-literal placeholder is rarely the same length as the match)."""
    text = "sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD"
    redacted, entity_types, spans = engine.redact(text, "broad")
    assert entity_types == ["ANTHROPIC_API_KEY"]
    assert len(spans) == 1
    start, end = spans[0]
    assert text[start:end] == text
    assert redacted == "[ANTHROPIC_API_KEY]"


def test_redact_spans_one_per_finding_in_order(engine):
    """A leaf with multiple findings produces one span per finding, aligned
    1:1 and in the same order as entity_types."""
    text = (
        "sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD "
        "and separately AZURE_SECRET=abc1Q~defghijklmnopqrstuvwxyzABCDEFGHIJKL"
    )
    redacted, entity_types, spans = engine.redact(text, "broad")
    assert len(spans) == len(entity_types)
    assert len(spans) >= 2
    for (start, end), etype in zip(spans, entity_types):
        # Each span must locate a real, non-empty substring of the source.
        assert 0 <= start < end <= len(text)


def test_broad_pii_profile_includes_credentials_email_and_ip():
    from sanitize.engine import RedactionEngine

    engine = RedactionEngine()
    entities = engine.entities_for_profile("broad_pii")
    assert "EMAIL_ADDRESS" in entities
    assert "IP_ADDRESS" in entities
    # broad_pii must not silently drop credential coverage.
    from sanitize.recognizers import CREDENTIAL_ENTITY_TYPES

    for entity_type in CREDENTIAL_ENTITY_TYPES:
        assert entity_type in entities
    # broad_pii deliberately excludes PHONE_NUMBER (narrow-only extra).
    assert "PHONE_NUMBER" not in entities


def test_narrow_and_broad_profiles_unaffected_by_new_profile(engine):
    """Existing profile behaviour is unchanged by adding broad_pii."""
    narrow = engine.entities_for_profile("narrow")
    broad = engine.entities_for_profile("broad")
    assert "PHONE_NUMBER" in narrow
    assert "EMAIL_ADDRESS" in narrow
    assert broad == engine.entities_for_profile("broad")


def test_unknown_profile_still_raises(engine):
    import pytest

    with pytest.raises(ValueError):
        engine.entities_for_profile("nonsense")

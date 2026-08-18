"""Recognizer-level tests, per plan verification step 1."""


def test_sk_ant_not_swallowed_by_sk_or(engine):
    """sk-ant- must not be caught by the sk-or- (or any generic sk-) pattern."""
    text = "sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD"
    redacted, entity_types = engine.redact(text, "broad")
    assert redacted == "[ANTHROPIC_API_KEY]"
    assert entity_types == ["ANTHROPIC_API_KEY"]


def test_sk_or_recognized_independently(engine):
    text = "sk-or-v1-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    redacted, entity_types = engine.redact(text, "broad")
    assert redacted == "[OPENROUTER_API_KEY]"
    assert entity_types == ["OPENROUTER_API_KEY"]


def test_redaction_is_idempotent(engine):
    text = "sk-ant-api03-FAKE0123456789abcdefghijklmnopqrstuvwxyzABCD"
    once, _ = engine.redact(text, "broad")
    twice, entity_types_second_pass = engine.redact(once, "broad")
    assert once == twice
    assert entity_types_second_pass == []


def test_env_assignment_recognized(engine):
    text = "API_KEY=abc123XYZsuperlonglooooooongsecretvalue1234567890"
    redacted, entity_types = engine.redact(text, "broad")
    assert redacted == "[ENV_ASSIGNMENT_SECRET]"
    assert entity_types == ["ENV_ASSIGNMENT_SECRET"]


def test_env_assignment_placeholder_not_redacted(engine):
    text = "API_KEY=changeme_placeholder_xxxx"
    redacted, entity_types = engine.redact(text, "broad")
    assert redacted == text
    assert entity_types == []


def test_github_oauth_token_recognized(engine):
    text = "export GITHUB_TOKEN=ghp_FAKE0123456789abcdefghijklmnopqrstuv"
    redacted, entity_types = engine.redact(text, "broad")
    assert "[GITHUB_OAUTH_TOKEN]" in redacted or "[ENV_ASSIGNMENT_SECRET]" in redacted
    assert "ghp_FAKE0123456789abcdefghijklmnopqrstuv" not in redacted


def test_env_assignment_recognized_with_trailing_context(engine):
    """Regression test for a real full-corpus gate-4 miss (2026-08-18): the
    trailing terminator char class was transcribed from the plan as
    `[`'";]`, silently dropping `\\s` from the plan's exact spec `[`'"\\s;]`.
    Any KEY=value assignment followed by whitespace instead of a
    quote/backtick/semicolon (the overwhelmingly common real-world case --
    `-e KEY=value -e KEY2=value2`-style CLI flags, `KEY=value` lines in a
    pasted .env/log dump) silently failed to match; only a value at the
    exact end of the string was caught. This is exactly the shape that
    produced 16 `generic-api-key` gate-4 findings over the real corpus."""
    text = "podman run --name=x -e API_KEY=abc123XYZsuperlonglooooooongsecretvalue1234567890 -e OTHER=y"
    redacted, entity_types = engine.redact(text, "broad")
    assert "abc123XYZsuperlonglooooooongsecretvalue1234567890" not in redacted
    assert "ENV_ASSIGNMENT_SECRET" in entity_types


def test_stripe_test_token_also_redacted(engine):
    """Regression test: plan §2 originally scoped the Stripe recognizer to
    sk_live_/rk_live_ only ('pk_test_/sk_test_ are safe by design'). gitleaks'
    real stripe-access-token rule matches (?:sk|rk)_(?:test|live|prod)_...
    with no test/live distinction, and 3 real full-corpus gate-4 findings
    were genuine sk_test_/rk_test_ tokens. Widened per the plan's own
    'closable only by widening redaction' policy -- documented as a
    deviation from the original table note, not silently decided."""
    text = "STRIPE_KEY=sk_test_FAKE0123456789abcdefghijklmnopqrstuv"
    redacted, entity_types = engine.redact(text, "broad")
    assert "sk_test_FAKE0123456789abcdefghijklmnopqrstuv" not in redacted
    assert "STRIPE_ACCESS_TOKEN" in entity_types


def test_azure_ad_client_secret_shape(engine):
    """Regression test: the original recognizer assumed a 3-dot-separated-
    segment shape that never matched gitleaks' real azure-ad-client-secret
    rule (3 chars + digit + literal 'Q~' marker + 31-34 more chars, no dots)
    -- a plain implementation error (never verified against source), not
    corpus drift. Both real full-corpus gate-4 findings of this rule were
    misses caused by this."""
    text = "AZURE_SECRET=abc1Q~defghijklmnopqrstuvwxyzABCDEFGHIJKL"
    redacted, entity_types = engine.redact(text, "broad")
    assert "AZURE_AD_CLIENT_SECRET" in entity_types


def test_adjacent_placeholder_tags_do_not_form_a_credential_shape(engine):
    """Regression test for a real full-corpus gate-4 finding (2026-08-18):
    when Presidio finds two credential matches immediately adjacent in one
    string leaf, the anonymizer emits two placeholder tags back-to-back with
    no separator. With the old '<ENTITY_TYPE>' format this produced
    '<A><B>' -- every entity-type name contains a gitleaks trigger keyword
    (KEY/TOKEN/SECRET/...) and '>' is itself one of gitleaks' recognized
    delimiter characters, so 'SECRET>' read as keyword+delimiter and
    whatever followed read as its value, letting a live value slip through
    gate 4 riding on our own placeholder text. Square brackets don't
    collide this way since ']' isn't a gitleaks delimiter."""
    text = "TOKEN_A=abc123XYZsuperlonglooooooongsecretvalue1234567890KEY_B=xyz987ABCsuperlonglooooooongsecretvalue0987654321"
    redacted, entity_types = engine.redact(text, "broad")
    assert "><" not in redacted
    import re

    from sanitize.recognizers import ENV_ASSIGNMENT_PATTERN

    assert re.search(ENV_ASSIGNMENT_PATTERN, redacted) is None


def test_pem_marker_literal_redacted_standalone(engine):
    """A lone PEM BEGIN marker mention with no matching END/body in the same
    leaf (e.g. prose discussing the marker string) must still be redacted --
    this is exactly the shape PRIVATE_KEY_BLOCK's block regex cannot catch
    on its own, since there is no closing '...KEY-----' 64+ chars later
    within this single leaf."""
    text = "grepping for a marker like `-----BEGIN RSA PRIVATE KEY-----` in the corpus"
    redacted, entity_types = engine.redact(text, "broad")
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
    assert "PEM_MARKER_LITERAL" in entity_types


def test_pem_marker_literal_redacted_across_split_leaves(engine):
    """Regression test for the real full-corpus gate-4 finding (2026-08-18):
    two mentions of the same PEM marker text land in adjacent JSON string
    leaves (this project's own transcript, a diff-hunk array where each
    line is its own leaf). gitleaks scans raw bytes and sees the two
    marker occurrences close enough together in the file to trip its
    private-key rule, even though per-leaf JSON-aware redaction (plan §3)
    cannot see across the leaf boundary that produces that adjacency.
    Simulate the two-leaf split directly: redact each leaf independently,
    then concatenate as gitleaks' raw-byte scanner would, and confirm no
    unredacted marker text survives in either leaf's output."""
    leaf_one = "note: grepping for `-----BEGIN RSA PRIVATE KEY-----` in the corpus"
    leaf_two = "as of today, every `-----BEGIN RSA PRIVATE KEY-----` marker found is a false positive"

    redacted_one, entity_types_one = engine.redact(leaf_one, "broad")
    redacted_two, entity_types_two = engine.redact(leaf_two, "broad")

    assert "PEM_MARKER_LITERAL" in entity_types_one
    assert "PEM_MARKER_LITERAL" in entity_types_two
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted_one
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted_two

    # Raw-byte concatenation of the two independently-redacted leaves (what
    # a gitleaks-style scanner sees) must not reconstruct the marker text.
    concatenated = redacted_one + redacted_two
    assert "-----BEGIN RSA PRIVATE KEY-----" not in concatenated

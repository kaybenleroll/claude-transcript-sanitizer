"""Credential recognizers for the Presidio AnalyzerEngine.

Derived from the gitleaks 8.30.1 baseline over the real corpus (see plan
§2 at ~/.claude/plans/quirky-exploring-map.md), not from a prefix grep.
Rule IDs observed in the baseline: generic-api-key, github-oauth,
private-key, stripe-access-token, gcp-api-key, anthropic-api-key,
aws-access-token, azure-ad-client-secret. sk-or- (OpenRouter) has no
gitleaks rule at all and is covered here only.
"""

from __future__ import annotations

import math
import re

from presidio_analyzer import Pattern, PatternRecognizer

# ---------------------------------------------------------------------------
# Placeholder allow-list (reduces over-redaction; never used to suppress a
# genuine finding — see plan §2 "Policy on gate-4 findings").
# Pattern lifted verbatim from .scratch/secret-scan/classify.sh.
# ---------------------------------------------------------------------------
PLACEHOLDER_RE = re.compile(
    r"change_?me|your[-_]|xxxx|placeholder|example|<[a-z]|replace|dummy|fake|localhost|test123",
    re.IGNORECASE,
)

# Entropy floor for the env-assignment recognizer (bits per char, Shannon).
# Low-entropy captured values (e.g. "aaaaaaaaaa", "1234567890") are not
# credentials; skip them to cut false positives on the highest-FP recognizer.
ENTROPY_FLOOR = 3.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_placeholder_or_low_entropy(matched_text: str) -> bool:
    """True if the matched text looks like a placeholder or is low-entropy.

    Used as the PatternRecognizer's custom validation hook to suppress
    over-redaction — never to close a gitleaks gate-4 finding (plan §2).
    """
    if PLACEHOLDER_RE.search(matched_text):
        return True
    if shannon_entropy(matched_text) < ENTROPY_FLOOR:
        return True
    return False


# ---------------------------------------------------------------------------
# Fixed-prefix recognizers
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = PatternRecognizer(
    supported_entity="ANTHROPIC_API_KEY",
    name="AnthropicApiKeyRecognizer",
    supported_language="en",
    patterns=[
        Pattern("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 0.9),
    ],
)

# Must be checked/registered such that sk-ant- is never swallowed by this
# pattern — Presidio resolves overlapping matches by taking the highest
# score, so sk-ant- is scored higher (0.9) than sk-or- (0.85) and the
# sk-ant- pattern's prefix is more specific, avoiding the collision.
# See tests/test_recognizers.py::test_sk_ant_not_swallowed_by_sk_or.
OPENROUTER_API_KEY = PatternRecognizer(
    supported_entity="OPENROUTER_API_KEY",
    name="OpenRouterApiKeyRecognizer",
    supported_language="en",
    patterns=[
        Pattern("openrouter-api-key", r"\bsk-or-[A-Za-z0-9_-]{20,}\b", 0.85),
    ],
)

GITHUB_OAUTH_TOKEN = PatternRecognizer(
    supported_entity="GITHUB_OAUTH_TOKEN",
    name="GithubOauthTokenRecognizer",
    supported_language="en",
    patterns=[
        Pattern("github-oauth", r"\b(?:gho|ghp|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b", 0.9),
    ],
)

GCP_API_KEY = PatternRecognizer(
    supported_entity="GCP_API_KEY",
    name="GcpApiKeyRecognizer",
    supported_language="en",
    patterns=[
        Pattern("gcp-api-key-aiza", r"\bAIza[A-Za-z0-9_-]{35}\b", 0.9),
        Pattern("gcp-api-key-aq", r"\bAQ\.[A-Za-z0-9_-]{30,}\b", 0.8),
    ],
)

GROQ_API_KEY = PatternRecognizer(
    supported_entity="GROQ_API_KEY",
    name="GroqApiKeyRecognizer",
    supported_language="en",
    patterns=[
        Pattern("groq-api-key", r"\bgsk_[A-Za-z0-9]{20,}\b", 0.9),
    ],
)

PRIVATE_KEY_BLOCK = PatternRecognizer(
    supported_entity="PRIVATE_KEY",
    name="PrivateKeyBlockRecognizer",
    supported_language="en",
    patterns=[
        # Ported verbatim from gitleaks' own private-key rule (cmd/generate/
        # config/rules/privatekey.go, verified 2026-08-18) rather than a
        # hand-written approximation. The earlier hand-written form required
        # "PRIVATE KEY" literally on the END line and >=1 char of body; the
        # real rule only requires "KEY(?: BLOCK)?-----" on the END line and
        # >=64 chars of body, is case-insensitive, and allows any of
        # [ A-Z0-9_-]{0,100} between BEGIN and "PRIVATE KEY". That gap let
        # a real corpus finding through gate 4: two backtick-quoted marker
        # mentions in unrelated prose (this project's own prior-session
        # analysis text discussing gitleaks' private-key rule) sit >=64
        # chars apart and satisfy gitleaks' rule without containing an
        # actual key -- widening to match gitleaks exactly closes this.
        Pattern(
            "private-key-block",
            r"(?i)-----BEGIN[ A-Za-z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----",
            0.95,
        ),
    ],
)

PEM_MARKER_LITERAL = PatternRecognizer(
    supported_entity="PEM_MARKER_LITERAL",
    name="PemMarkerLiteralRecognizer",
    supported_language="en",
    patterns=[
        # Added 2026-08-18: the last remaining full-corpus gate-4 finding.
        # A single leaf-level occurrence of just the PEM marker line (no
        # matching BEGIN/END pair, no >=64-char body within the SAME leaf)
        # doesn't trip PRIVATE_KEY_BLOCK above, and gitleaks' own
        # private-key rule (verified 8.30.1) does not require an actual key
        # body either -- two marker mentions landing in adjacent JSON string
        # leaves (a diff-hunk array, each line its own leaf) are close
        # enough in the RAW BYTES that gitleaks' rule matches across the
        # leaf boundary, even though per-leaf JSON-aware redaction (plan §3:
        # never regex over raw bytes) cannot see across that boundary by
        # construction. Fix: redact the marker text itself, standalone, in
        # every leaf it appears in -- so no leaf ever contains an
        # unredacted marker for gitleaks to concatenate with its neighbour.
        # A real leaked key's BEGIN/END marker lines get caught by this too
        # (they contain the identical literal text), so this does not
        # weaken detection of an actual credential.
        Pattern(
            "pem-marker-literal",
            r"(?i)-----(?:BEGIN|END)[ A-Za-z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----",
            0.9,
        ),
    ],
)

AWS_ACCESS_TOKEN = PatternRecognizer(
    supported_entity="AWS_ACCESS_TOKEN",
    name="AwsAccessTokenRecognizer",
    supported_language="en",
    patterns=[
        Pattern("aws-access-token", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0.9),
    ],
)

STRIPE_ACCESS_TOKEN = PatternRecognizer(
    supported_entity="STRIPE_ACCESS_TOKEN",
    name="StripeAccessTokenRecognizer",
    supported_language="en",
    patterns=[
        # WIDENED 2026-08-18 from plan §2's original "sk_live_/rk_live_ only
        # — pk_test_/sk_test_ are safe by design". Verified against gitleaks'
        # own stripe-access-token rule (cmd/generate/config/rules/stripe.go,
        # 8.30.1): the real pattern is (?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]
        # {10,99} — it does NOT distinguish test from live, and 3 gate-4
        # findings over the real corpus were genuine sk_test_/rk_test_ tokens.
        # Plan §"Policy on gate-4 findings" is explicit that a finding is
        # closable only by widening, never by an allow-list/ignore-file
        # workaround — so this recognizer now matches what gitleaks matches,
        # superseding the "safe by design" note as a documented deviation
        # (flagged in this phase's report, not silently decided).
        Pattern("stripe-access-token", r"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b", 0.9),
    ],
)

AZURE_AD_CLIENT_SECRET = PatternRecognizer(
    supported_entity="AZURE_AD_CLIENT_SECRET",
    name="AzureAdClientSecretRecognizer",
    supported_language="en",
    patterns=[
        # CORRECTED 2026-08-18 — the original "3 dot-separated segments"
        # shape was simply wrong (never verified against source; a genuine
        # implementation error, not corpus drift) and matched nothing in
        # the real corpus, letting 2 findings through gate 4. Verified
        # against gitleaks' actual azure-ad-client-secret rule (cmd/
        # generate/config/rules/azure.go, 8.30.1): 3 chars, a digit, the
        # literal "Q~" marker, then 31-34 more chars — no dots involved.
        Pattern(
            "azure-ad-client-secret",
            r"[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}",
            0.7,
        ),
    ],
)

# ---------------------------------------------------------------------------
# Env-assignment recognizer — the hard one.
#
# Regex is quoted verbatim from plan §2, derived from gitleaks' own
# generic-api-key rule (cmd/generate/config/rules/generic.go), fact-checked
# against the local gitleaks 8.30.1 binary. Do NOT hand-roll a narrower
# form — see plan §2 for the specific false-negative shapes the naive
# `(?i)(key|token|secret...)\s*[=:]\s*\S{8,}` form misses.
# ---------------------------------------------------------------------------

ENV_ASSIGNMENT_PATTERN = (
    r"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)"
    r"(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'\"\s=]{0,5}"
    r"([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[`'\"\s;]|\\[nr]|$)"
)

class EnvAssignmentRecognizer(PatternRecognizer):
    """Env-assignment recognizer with placeholder/entropy validation.

    validate_result returning False drops the match entirely (Presidio sets
    its score to MIN_SCORE, which excludes it from results) — this is how
    the placeholder allow-list and entropy floor are wired in, per plan §2's
    instruction to pair the env-assignment recognizer with both.
    """

    def validate_result(self, pattern_text: str) -> bool | None:
        if is_placeholder_or_low_entropy(pattern_text):
            return False
        return None


ENV_ASSIGNMENT = EnvAssignmentRecognizer(
    supported_entity="ENV_ASSIGNMENT_SECRET",
    name="EnvAssignmentRecognizer",
    supported_language="en",
    patterns=[
        Pattern("generic-api-key", ENV_ASSIGNMENT_PATTERN, 0.55),
    ],
)


def build_recognizers() -> list[PatternRecognizer]:
    """All credential recognizers required by the measured gitleaks baseline."""
    return [
        ANTHROPIC_API_KEY,
        OPENROUTER_API_KEY,
        GITHUB_OAUTH_TOKEN,
        GCP_API_KEY,
        GROQ_API_KEY,
        PRIVATE_KEY_BLOCK,
        PEM_MARKER_LITERAL,
        AWS_ACCESS_TOKEN,
        STRIPE_ACCESS_TOKEN,
        AZURE_AD_CLIENT_SECRET,
        ENV_ASSIGNMENT,
    ]


CREDENTIAL_ENTITY_TYPES = [
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_OAUTH_TOKEN",
    "GCP_API_KEY",
    "GROQ_API_KEY",
    "PRIVATE_KEY",
    "PEM_MARKER_LITERAL",
    "AWS_ACCESS_TOKEN",
    "STRIPE_ACCESS_TOKEN",
    "AZURE_AD_CLIENT_SECRET",
    "ENV_ASSIGNMENT_SECRET",
]

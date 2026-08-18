"""Wires the credential recognizers into a Presidio AnalyzerEngine +
AnonymizerEngine pair, with two redaction profiles selected by JSON path
(see sanitize/jsonl.py).

Pattern-only mode via NoOpNlpEngine — no spaCy model download. Per plan §2:
AnalyzerEngine hardcodes supported_languages=["en"] when none is passed, and
NoOpNlpEngine only skips NER recognizer registration — all ~90 predefined
pattern recognizers (EmailRecognizer, IpRecognizer, PhoneRecognizer among
them) register normally. supported_languages=["en"] is passed explicitly
anyway to pin the behaviour.
"""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NoOpNlpEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from sanitize.recognizers import CREDENTIAL_ENTITY_TYPES, build_recognizers

# Narrow profile: credentials + these PII types. Applied to human-authored
# free text (.message.content[].text, .content, .summary, .title).
NARROW_EXTRA_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"]

# Broad profile: credentials only. Applied to everything else, including
# tool_use/tool_result leaves. URL is excluded from both profiles.
BROAD_EXTRA_ENTITIES: list[str] = []


def _build_nlp_engine() -> NoOpNlpEngine:
    engine = NoOpNlpEngine(models=[{"lang_code": "en", "model_name": ""}])
    engine.load()
    return engine


def build_analyzer_engine() -> AnalyzerEngine:
    # Let AnalyzerEngine build its own default registry from the nlp_engine
    # (registry=None path) — this is what correctly skips only the NER
    # recognizer (SpacyRecognizer) for NoOpNlpEngine while registering all
    # ~90 predefined pattern recognizers. Building a RecognizerRegistry
    # ourselves via load_predefined_recognizers() and handing it in
    # pre-populated does NOT filter SpacyRecognizer, and AnalyzerEngine then
    # rejects it at validate_nlp_engine_compatibility() — verified against
    # presidio-analyzer 2.2.364 while implementing this.
    analyzer = AnalyzerEngine(
        nlp_engine=_build_nlp_engine(),
        supported_languages=["en"],
    )
    for recognizer in build_recognizers():
        analyzer.registry.add_recognizer(recognizer)
    return analyzer


def build_anonymizer_engine() -> AnonymizerEngine:
    return AnonymizerEngine()


# Fixed literal per entity type. Deterministic: no encrypt/hash/fake-data
# operator, per plan §2's "Forbidden for determinism" list.
#
# Square brackets, not angle brackets: a real full-corpus gate-4 finding
# (2026-08-18) showed two adjacent placeholder tags -- "<A><B>" landing
# back-to-back with no separator, which happens whenever Presidio finds two
# credential matches immediately next to each other in one string leaf --
# forming a shape gitleaks' generic-api-key rule matches on its own: EVERY
# one of our entity-type names contains one of gitleaks' trigger keywords
# (KEY/TOKEN/SECRET/PASSWORD/...), and ">" is itself one of gitleaks'
# recognized delimiter characters, so "...SECRET>" reads as keyword+
# delimiter and whatever follows reads as its value. "]" is not a gitleaks
# delimiter, so this bracket style cannot self-collide the same way.
def _operator_config_for(entity_type: str) -> OperatorConfig:
    return OperatorConfig("replace", {"new_value": f"[{entity_type}]"})


def _placeholder_literals() -> list[str]:
    """All fixed-literal placeholder strings, for the allow_list."""
    return [f"[{t}]" for t in CREDENTIAL_ENTITY_TYPES + NARROW_EXTRA_ENTITIES]


class RedactionEngine:
    """Analyze + anonymize a single string leaf under a given profile."""

    def __init__(self) -> None:
        self.analyzer = build_analyzer_engine()
        self.anonymizer = build_anonymizer_engine()

    def entities_for_profile(self, profile: str) -> list[str]:
        if profile == "narrow":
            return CREDENTIAL_ENTITY_TYPES + NARROW_EXTRA_ENTITIES
        if profile == "broad":
            return CREDENTIAL_ENTITY_TYPES + BROAD_EXTRA_ENTITIES
        raise ValueError(f"unknown profile: {profile!r}")

    def redact(self, text: str, profile: str) -> tuple[str, list[str]]:
        """Redact `text` under `profile`. Returns (redacted_text, entity_types_found).

        entity_types_found lists RecognizerResult.entity_type for each match
        (for the redaction-log entity-type counts — never the matched value).
        """
        if not text:
            return text, []

        entities = self.entities_for_profile(profile)
        # allow_list / allow_list_match="exact" reinforces idempotency: a
        # fixed-literal placeholder like "<ANTHROPIC_API_KEY>" never matches
        # any credential pattern structurally, but the explicit allow_list
        # pins this against future pattern changes (plan §2). This is an
        # allow_list use that only ever *reduces* redaction on our own
        # already-redacted output, never on gitleaks-flagged content.
        results = self.analyzer.analyze(
            text=text,
            entities=entities,
            language="en",
            allow_list=_placeholder_literals(),
            allow_list_match="exact",
        )
        if not results:
            return text, []

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={r.entity_type: _operator_config_for(r.entity_type) for r in results},
        )
        entity_types = [r.entity_type for r in results]
        return anonymized.text, entity_types


def is_idempotent_placeholder(text: str) -> bool:
    """True if `text` is exactly one of our fixed-literal redaction placeholders."""
    stripped = text.strip()
    return stripped.startswith("[") and stripped.endswith("]") and stripped[1:-1] in CREDENTIAL_ENTITY_TYPES + NARROW_EXTRA_ENTITIES

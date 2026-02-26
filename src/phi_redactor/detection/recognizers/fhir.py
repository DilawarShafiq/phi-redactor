"""FHIR resource reference recognizer for PHI detection."""
from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class FHIRResourceRecognizer(PatternRecognizer):
    """Detects FHIR resource references that may contain PHI identifiers."""

    PATTERNS = [
        Pattern(
            "fhir_reference",
            r"(?:Patient|Practitioner|Person|RelatedPerson)/[A-Za-z0-9._-]+",
            0.7,
        ),
        Pattern(
            "fhir_url",
            r"https?://[^\s]+/(?:Patient|Practitioner|Person|RelatedPerson)/[A-Za-z0-9._-]+",
            0.85,
        ),
        Pattern(
            "fhir_oid",
            r"urn:oid:[0-9]+(?:\.[0-9]+){3,}",
            0.6,
        ),
    ]
    CONTEXT = [
        "fhir",
        "resource",
        "reference",
        "patient",
        "practitioner",
        "bundle",
        "entry",
    ]

    def __init__(self, supported_language: str = "en", **kwargs) -> None:
        super().__init__(
            supported_entity="FHIR_REFERENCE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            **kwargs,
        )

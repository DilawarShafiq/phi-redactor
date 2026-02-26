"""HL7v2 segment recognizer for PHI detection."""
from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class HL7v2Recognizer(PatternRecognizer):
    """Detects HL7v2 message segments that typically contain PHI."""

    PATTERNS = [
        Pattern("hl7_pid", r"PID\|[^\n]+", 0.9),
        Pattern("hl7_nk1", r"NK1\|[^\n]+", 0.85),
        Pattern("hl7_gt1", r"GT1\|[^\n]+", 0.8),
        Pattern("hl7_in1", r"IN1\|[^\n]+", 0.8),
    ]
    CONTEXT = ["hl7", "message", "segment", "pid", "patient", "adt", "oru"]

    def __init__(self, supported_language: str = "en", **kwargs) -> None:
        super().__init__(
            supported_entity="HL7V2_SEGMENT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            **kwargs,
        )

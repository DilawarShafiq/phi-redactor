"""Unit tests for FHIR and HL7v2 recognizers."""
from __future__ import annotations

import pytest

try:
    import spacy

    spacy.load("en_core_web_lg")
    _SPACY_AVAILABLE = True
except (ImportError, OSError):
    _SPACY_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SPACY_AVAILABLE, reason="spaCy model not available"
)

from phi_redactor.detection import PhiDetectionEngine
from phi_redactor.models import PHICategory


@pytest.fixture(scope="module")
def engine() -> PhiDetectionEngine:
    return PhiDetectionEngine(sensitivity=0.7)


class TestFHIRRecognition:
    def test_detect_fhir_patient_reference(self, engine: PhiDetectionEngine) -> None:
        text = "Refer to FHIR resource Patient/12345 for demographics."
        detections = engine.detect(text)
        cats = [d.category for d in detections]
        assert PHICategory.OTHER_UNIQUE_ID in cats or any(
            "12345" in d.original_text for d in detections
        )

    def test_detect_fhir_url(self, engine: PhiDetectionEngine) -> None:
        text = "See resource at https://fhir.hospital.org/Patient/abc-123."
        detections = engine.detect(text)
        assert len(detections) >= 1

    def test_detect_fhir_oid(self, engine: PhiDetectionEngine) -> None:
        text = "System identifier urn:oid:2.16.840.1.113883.4.1 used."
        detections = engine.detect(text)
        assert len(detections) >= 1


class TestHL7v2Recognition:
    def test_detect_hl7_pid_segment(self, engine: PhiDetectionEngine) -> None:
        text = "PID|1||12345^^^Hospital^MR||Smith^John||19560315|M|||742 Evergreen^^Springfield^IL^62704"
        detections = engine.detect(text)
        assert len(detections) >= 1

    def test_detect_hl7_nk1_segment(self, engine: PhiDetectionEngine) -> None:
        text = "NK1|1|DOE^JANE|SPO|742 Evergreen^^Springfield^IL^62704|(555)123-4567"
        detections = engine.detect(text)
        assert len(detections) >= 1

"""Unit tests for the PHI detection engine.

Tests cover:
- Detection of individual PHI types (person names, SSNs, phone numbers, emails, dates)
- Empty input handling
- Confidence score validation
- Sensitivity parameter behavior

Note: These tests require the spaCy ``en_core_web_lg`` model. If the model is
not installed, tests are skipped gracefully via ``pytest.importorskip``.
"""

from __future__ import annotations

import pytest

# Skip entire module if spaCy model is not available
try:
    import spacy

    spacy.load("en_core_web_lg")
    _SPACY_AVAILABLE = True
except (ImportError, OSError):
    _SPACY_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SPACY_AVAILABLE,
    reason="spaCy en_core_web_lg model not installed",
)


from phi_redactor.detection import PhiDetectionEngine
from phi_redactor.models import PHICategory, PHIDetection

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine() -> PhiDetectionEngine:
    """Create a single detection engine for all tests in this module.

    Module-scoped to avoid re-loading spaCy and Presidio for every test.
    """
    return PhiDetectionEngine(sensitivity=0.7)


@pytest.fixture(scope="module")
def high_sensitivity_engine() -> PhiDetectionEngine:
    """Engine configured with high sensitivity (accepts more detections)."""
    return PhiDetectionEngine(sensitivity=0.9)


@pytest.fixture(scope="module")
def low_sensitivity_engine() -> PhiDetectionEngine:
    """Engine configured with low sensitivity (requires high confidence)."""
    return PhiDetectionEngine(sensitivity=0.1)


# ---------------------------------------------------------------------------
# Test: Person name detection
# ---------------------------------------------------------------------------


class TestPersonNameDetection:
    """Tests for person name (PERSON_NAME) detection."""

    def test_detect_doctor_name(self, engine: PhiDetectionEngine) -> None:
        """Dr. Maria Garcia should be detected as PERSON_NAME."""
        text = "The patient was referred by Dr. Maria Garcia for evaluation."
        detections = engine.detect(text)

        person_detections = [d for d in detections if d.category == PHICategory.PERSON_NAME]
        assert len(person_detections) >= 1, (
            f"Expected at least one PERSON_NAME detection, got {len(person_detections)}. "
            f"All detections: {detections}"
        )

        # At least one detection should contain "Maria Garcia"
        matched_texts = [d.original_text for d in person_detections]
        assert any("Maria" in t and "Garcia" in t for t in matched_texts), (
            f"Expected 'Maria Garcia' in detected texts, got: {matched_texts}"
        )

    def test_detect_patient_name(self, engine: PhiDetectionEngine) -> None:
        """A plain patient name should be detected."""
        text = "Patient John Smith presented to the emergency department."
        detections = engine.detect(text)

        person_detections = [d for d in detections if d.category == PHICategory.PERSON_NAME]
        assert len(person_detections) >= 1, (
            f"Expected PERSON_NAME detection for 'John Smith', got: {detections}"
        )


# ---------------------------------------------------------------------------
# Test: SSN detection
# ---------------------------------------------------------------------------


class TestSSNDetection:
    """Tests for Social Security Number (SSN) detection."""

    def test_detect_ssn_dashed_format(self, engine: PhiDetectionEngine) -> None:
        """SSN in XXX-XX-XXXX format should be detected."""
        text = "The patient's SSN is 456-78-9012 on file."
        detections = engine.detect(text)

        ssn_detections = [d for d in detections if d.category == PHICategory.SSN]
        assert len(ssn_detections) >= 1, (
            f"Expected SSN detection for '456-78-9012', got: {detections}"
        )
        assert any("456-78-9012" in d.original_text for d in ssn_detections), (
            f"Expected '456-78-9012' in detected text, got: "
            f"{[d.original_text for d in ssn_detections]}"
        )


# ---------------------------------------------------------------------------
# Test: Phone number detection
# ---------------------------------------------------------------------------


class TestPhoneDetection:
    """Tests for phone number detection."""

    def test_detect_phone_parenthesized(self, engine: PhiDetectionEngine) -> None:
        """Phone number in (XXX) XXX-XXXX format should be detected."""
        text = "Contact the patient at (555) 123-4567 for follow-up."
        detections = engine.detect(text)

        phone_detections = [d for d in detections if d.category == PHICategory.PHONE_NUMBER]
        assert len(phone_detections) >= 1, (
            f"Expected PHONE_NUMBER detection for '(555) 123-4567', got: {detections}"
        )


# ---------------------------------------------------------------------------
# Test: Email detection
# ---------------------------------------------------------------------------


class TestEmailDetection:
    """Tests for email address detection."""

    def test_detect_email(self, engine: PhiDetectionEngine) -> None:
        """Email address should be detected as EMAIL_ADDRESS."""
        text = "Send records to john.smith@email.com per patient request."
        detections = engine.detect(text)

        email_detections = [d for d in detections if d.category == PHICategory.EMAIL_ADDRESS]
        assert len(email_detections) >= 1, (
            f"Expected EMAIL_ADDRESS detection for 'john.smith@email.com', got: {detections}"
        )
        assert any("john.smith@email.com" in d.original_text for d in email_detections)


# ---------------------------------------------------------------------------
# Test: Date detection
# ---------------------------------------------------------------------------


class TestDateDetection:
    """Tests for date/time detection."""

    def test_detect_date_written_format(self, engine: PhiDetectionEngine) -> None:
        """A written-out date should be detected as DATE."""
        text = "The patient visited on January 15, 2026 for a routine checkup."
        detections = engine.detect(text)

        date_detections = [d for d in detections if d.category == PHICategory.DATE]
        assert len(date_detections) >= 1, (
            f"Expected DATE detection for 'January 15, 2026', got: {detections}"
        )


# ---------------------------------------------------------------------------
# Test: Empty and edge-case inputs
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for empty text, whitespace-only, and other edge cases."""

    def test_empty_text_returns_empty_list(self, engine: PhiDetectionEngine) -> None:
        """Empty string should return an empty detection list."""
        assert engine.detect("") == []

    def test_whitespace_only_returns_empty_list(self, engine: PhiDetectionEngine) -> None:
        """Whitespace-only string should return an empty detection list."""
        assert engine.detect("   \n\t  ") == []

    def test_no_phi_text(self, engine: PhiDetectionEngine) -> None:
        """Text without PHI should produce zero or very few detections."""
        text = (
            "Type 2 Diabetes Mellitus is a metabolic disease characterized by "
            "high blood sugar levels. Treatment with metformin is recommended."
        )
        detections = engine.detect(text)
        # There may be a few false positives, but not many
        assert len(detections) < 5, (
            f"Expected very few detections for PHI-free text, got {len(detections)}: {detections}"
        )


# ---------------------------------------------------------------------------
# Test: Confidence score validation
# ---------------------------------------------------------------------------


class TestConfidenceScores:
    """Tests that confidence scores are properly bounded."""

    def test_confidence_in_valid_range(self, engine: PhiDetectionEngine) -> None:
        """All confidence scores should be in the [0.0, 1.0] range."""
        text = (
            "Patient John Smith (DOB: 03/15/1956, SSN: 456-78-9012) was seen by "
            "Dr. Maria Garcia. Contact: (555) 123-4567, john.smith@email.com."
        )
        detections = engine.detect(text)
        assert len(detections) > 0, "Expected at least one detection"

        for detection in detections:
            assert 0.0 <= detection.confidence <= 1.0, (
                f"Confidence {detection.confidence} out of range for "
                f"{detection.category}: '{detection.original_text}'"
            )

    def test_detections_are_phi_detection_instances(self, engine: PhiDetectionEngine) -> None:
        """All results should be PHIDetection model instances."""
        text = "Patient John Smith, SSN 456-78-9012."
        detections = engine.detect(text)
        for detection in detections:
            assert isinstance(detection, PHIDetection)


# ---------------------------------------------------------------------------
# Test: Sensitivity parameter
# ---------------------------------------------------------------------------


class TestSensitivityParameter:
    """Tests that the sensitivity parameter controls detection aggressiveness."""

    def test_higher_sensitivity_finds_more(
        self,
        engine: PhiDetectionEngine,
        high_sensitivity_engine: PhiDetectionEngine,
    ) -> None:
        """Higher sensitivity (closer to 1.0) should find at least as many detections."""
        text = (
            "Patient John Smith (DOB: 03/15/1956, SSN: 456-78-9012) presented to "
            "Springfield General Hospital on January 15, 2026. "
            "Contact: (555) 123-4567, john.smith@email.com. "
            "Address: 742 Evergreen Terrace, Springfield, IL 62704."
        )
        normal_detections = engine.detect(text)
        high_detections = high_sensitivity_engine.detect(text)

        assert len(high_detections) >= len(normal_detections), (
            f"Higher sensitivity should find >= detections: "
            f"high={len(high_detections)}, normal={len(normal_detections)}"
        )

    def test_lower_sensitivity_finds_fewer(
        self,
        engine: PhiDetectionEngine,
        low_sensitivity_engine: PhiDetectionEngine,
    ) -> None:
        """Lower sensitivity (closer to 0.0) should find at most as many detections."""
        text = (
            "Patient John Smith (DOB: 03/15/1956, SSN: 456-78-9012) presented to "
            "Springfield General Hospital on January 15, 2026. "
            "Contact: (555) 123-4567, john.smith@email.com. "
            "Address: 742 Evergreen Terrace, Springfield, IL 62704."
        )
        normal_detections = engine.detect(text)
        low_detections = low_sensitivity_engine.detect(text)

        assert len(low_detections) <= len(normal_detections), (
            f"Lower sensitivity should find <= detections: "
            f"low={len(low_detections)}, normal={len(normal_detections)}"
        )

    def test_per_call_sensitivity_override(self, engine: PhiDetectionEngine) -> None:
        """Passing sensitivity to detect() should override the engine default."""
        text = (
            "Patient John Smith, SSN 456-78-9012, phone (555) 123-4567, "
            "email john.smith@email.com, DOB January 15, 2026."
        )
        high_results = engine.detect(text, sensitivity=1.0)
        low_results = engine.detect(text, sensitivity=0.05)

        assert len(high_results) >= len(low_results), (
            f"sensitivity=1.0 should find >= detections than sensitivity=0.05: "
            f"high={len(high_results)}, low={len(low_results)}"
        )

    def test_invalid_sensitivity_raises(self, engine: PhiDetectionEngine) -> None:
        """Invalid sensitivity values should raise ValueError."""
        with pytest.raises(ValueError, match="sensitivity must be between"):
            engine.detect("some text", sensitivity=1.5)

        with pytest.raises(ValueError, match="sensitivity must be between"):
            engine.detect("some text", sensitivity=-0.1)


# ---------------------------------------------------------------------------
# Test: Detection ordering
# ---------------------------------------------------------------------------


class TestDetectionOrdering:
    """Tests that detections are returned in a stable, position-based order."""

    def test_detections_sorted_by_position(self, engine: PhiDetectionEngine) -> None:
        """Detections should be sorted by start position (ascending)."""
        text = (
            "Patient John Smith, SSN 456-78-9012, email john.smith@email.com, phone (555) 123-4567."
        )
        detections = engine.detect(text)
        if len(detections) >= 2:
            for i in range(len(detections) - 1):
                assert detections[i].start <= detections[i + 1].start, (
                    f"Detections not sorted by position: {detections[i]} vs {detections[i + 1]}"
                )


# ---------------------------------------------------------------------------
# Test: Engine initialization
# ---------------------------------------------------------------------------


class TestEngineInitialization:
    """Tests for engine construction and validation."""

    def test_invalid_init_sensitivity_raises(self) -> None:
        """Creating an engine with invalid sensitivity should raise ValueError."""
        with pytest.raises(ValueError, match="sensitivity must be between"):
            PhiDetectionEngine(sensitivity=2.0)

        with pytest.raises(ValueError, match="sensitivity must be between"):
            PhiDetectionEngine(sensitivity=-1.0)

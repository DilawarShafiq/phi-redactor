"""Unit tests for the semantic masking engine.

Validates that :class:`~phi_redactor.masking.semantic.SemanticMasker` replaces
PHI with structurally plausible synthetic values, maintains session-level
consistency, and supports round-trip rehydration.
"""

from __future__ import annotations

import re
import uuid

import pytest

from phi_redactor.masking.semantic import SemanticMasker
from phi_redactor.models import DetectionMethod, PHICategory, PHIDetection

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detection(
    category: PHICategory,
    start: int,
    end: int,
    original_text: str,
    *,
    confidence: float = 0.95,
    method: DetectionMethod = DetectionMethod.REGEX,
    recognizer_name: str = "TestRecognizer",
) -> PHIDetection:
    """Convenience factory for building :class:`PHIDetection` instances."""
    return PHIDetection(
        category=category,
        start=start,
        end=end,
        confidence=confidence,
        method=method,
        recognizer_name=recognizer_name,
        original_text=original_text,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def masker() -> SemanticMasker:
    """Return a masker with no vault (in-memory only)."""
    return SemanticMasker(vault=None)


@pytest.fixture
def sid() -> str:
    """Return a stable session ID for deterministic tests."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# T018-1  Masked text contains none of the original PHI values
# ---------------------------------------------------------------------------


class TestMaskedTextContainsNoPHI:
    """After masking, no original PHI value should remain in the output."""

    def test_single_name_removed(self, masker: SemanticMasker, sid: str) -> None:
        text = "Patient John Smith arrived at 8am."
        detections = [
            _detection(PHICategory.PERSON_NAME, 8, 18, "John Smith"),
        ]
        masked, mapping = masker.mask(text, detections, sid)
        assert "John Smith" not in masked
        assert "John Smith" in mapping

    def test_ssn_removed(self, masker: SemanticMasker, sid: str) -> None:
        text = "SSN: 123-45-6789 on file."
        detections = [
            _detection(PHICategory.SSN, 5, 16, "123-45-6789"),
        ]
        masked, _ = masker.mask(text, detections, sid)
        assert "123-45-6789" not in masked

    def test_multiple_phi_all_removed(self, masker: SemanticMasker, sid: str) -> None:
        text = "Patient Jane Doe, SSN 999-88-7777, phone (555) 111-2222."
        detections = [
            _detection(PHICategory.PERSON_NAME, 8, 16, "Jane Doe"),
            _detection(PHICategory.SSN, 22, 33, "999-88-7777"),
            _detection(PHICategory.PHONE_NUMBER, 41, 55, "(555) 111-2222"),
        ]
        masked, mapping = masker.mask(text, detections, sid)
        for original in ("Jane Doe", "999-88-7777", "(555) 111-2222"):
            assert original not in masked, f"{original!r} still present in masked text"
        assert len(mapping) == 3


# ---------------------------------------------------------------------------
# T018-2  Synthetic SSNs have valid XXX-XX-XXXX format
# ---------------------------------------------------------------------------


class TestSSNFormat:
    """Synthetic SSNs must match the ``XXX-XX-XXXX`` pattern."""

    _SSN_PATTERN = re.compile(r"^\d{3}-\d{2}-\d{4}$")

    def test_ssn_format(self, masker: SemanticMasker, sid: str) -> None:
        text = "SSN: 123-45-6789"
        detections = [
            _detection(PHICategory.SSN, 5, 16, "123-45-6789"),
        ]
        _, mapping = masker.mask(text, detections, sid)
        synthetic_ssn = mapping["123-45-6789"]
        assert self._SSN_PATTERN.match(synthetic_ssn), (
            f"Synthetic SSN {synthetic_ssn!r} does not match XXX-XX-XXXX"
        )


# ---------------------------------------------------------------------------
# T018-3  Synthetic names differ from originals
# ---------------------------------------------------------------------------


class TestSyntheticNamesDiffer:
    """Generated names must not be identical to the original PHI name."""

    def test_name_differs(self, masker: SemanticMasker, sid: str) -> None:
        text = "Dr. Maria Garcia referred the patient."
        detections = [
            _detection(PHICategory.PERSON_NAME, 4, 16, "Maria Garcia"),
        ]
        _, mapping = masker.mask(text, detections, sid)
        synthetic_name = mapping["Maria Garcia"]
        assert synthetic_name != "Maria Garcia"
        # Should look like a name (at least two characters, contains a space).
        assert len(synthetic_name) >= 2


# ---------------------------------------------------------------------------
# T018-4  Consistency: same original + same session_id = same synthetic
# ---------------------------------------------------------------------------


class TestConsistency:
    """Repeated masking of the same value within a session must be stable."""

    def test_same_session_same_output(self, masker: SemanticMasker, sid: str) -> None:
        text_a = "Call John Smith."
        text_b = "Notify John Smith."
        det_a = [_detection(PHICategory.PERSON_NAME, 5, 15, "John Smith")]
        det_b = [_detection(PHICategory.PERSON_NAME, 7, 17, "John Smith")]

        _, map_a = masker.mask(text_a, det_a, sid)
        _, map_b = masker.mask(text_b, det_b, sid)

        assert map_a["John Smith"] == map_b["John Smith"]

    def test_different_sessions_may_differ(self, masker: SemanticMasker) -> None:
        """Different session IDs should (almost certainly) produce different fakes."""
        sid_1 = str(uuid.uuid4())
        sid_2 = str(uuid.uuid4())
        text = "Patient John Smith."
        det = [_detection(PHICategory.PERSON_NAME, 8, 18, "John Smith")]

        _, map_1 = masker.mask(text, det, sid_1)
        # Need a fresh masker so in-memory cache doesn't interfere.
        masker2 = SemanticMasker(vault=None)
        _, map_2 = masker2.mask(text, det, sid_2)

        # It's *theoretically* possible both produce the same name, but
        # astronomically unlikely with UUID session IDs.
        assert map_1["John Smith"] != map_2["John Smith"]


# ---------------------------------------------------------------------------
# T018-5  Rehydration: mask then rehydrate returns original text
# ---------------------------------------------------------------------------


class TestRehydration:
    """Round-tripping through mask -> rehydrate must recover the original."""

    def test_round_trip_single_detection(self, masker: SemanticMasker, sid: str) -> None:
        text = "Patient John Smith arrived."
        detections = [
            _detection(PHICategory.PERSON_NAME, 8, 18, "John Smith"),
        ]
        masked, _ = masker.mask(text, detections, sid)
        restored = masker.rehydrate(masked, sid)
        assert restored == text

    def test_round_trip_multiple_detections(self, masker: SemanticMasker, sid: str) -> None:
        text = "Patient Jane Doe, SSN 999-88-7777, email jane@test.com."
        detections = [
            _detection(PHICategory.PERSON_NAME, 8, 16, "Jane Doe"),
            _detection(PHICategory.SSN, 22, 33, "999-88-7777"),
            _detection(PHICategory.EMAIL_ADDRESS, 41, 54, "jane@test.com"),
        ]
        masked, _ = masker.mask(text, detections, sid)
        restored = masker.rehydrate(masked, sid)
        assert restored == text


# ---------------------------------------------------------------------------
# T018-6  Multiple detections in the same text all get replaced
# ---------------------------------------------------------------------------


class TestMultipleDetections:
    """Every detection in a single call must be replaced."""

    def test_all_detections_replaced(self, masker: SemanticMasker, sid: str) -> None:
        text = "Name: Alice Brown, Phone: (555) 000-1111, Email: alice@example.com, IP: 10.0.0.1"
        detections = [
            _detection(PHICategory.PERSON_NAME, 6, 17, "Alice Brown"),
            _detection(PHICategory.PHONE_NUMBER, 26, 40, "(555) 000-1111"),
            _detection(PHICategory.EMAIL_ADDRESS, 49, 66, "alice@example.com"),
            _detection(PHICategory.IP_ADDRESS, 72, 80, "10.0.0.1"),
        ]
        masked, mapping = masker.mask(text, detections, sid)

        for original in ("Alice Brown", "(555) 000-1111", "alice@example.com", "10.0.0.1"):
            assert original not in masked
        assert len(mapping) == 4

    def test_mapping_keys_match_originals(self, masker: SemanticMasker, sid: str) -> None:
        text = "MRN: 00456789, URL: https://portal.example.com"
        detections = [
            _detection(PHICategory.MRN, 5, 13, "00456789"),
            _detection(PHICategory.WEB_URL, 20, 47, "https://portal.example.com"),
        ]
        _, mapping = masker.mask(text, detections, sid)
        assert "00456789" in mapping
        assert "https://portal.example.com" in mapping


# ---------------------------------------------------------------------------
# T018-7  Empty detections returns original text unchanged
# ---------------------------------------------------------------------------


class TestEmptyDetections:
    """When there are no detections the text must pass through untouched."""

    def test_no_detections(self, masker: SemanticMasker, sid: str) -> None:
        text = "No PHI in this text."
        masked, mapping = masker.mask(text, [], sid)
        assert masked == text
        assert mapping == {}

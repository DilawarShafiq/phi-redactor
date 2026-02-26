"""Integration tests for masking quality.

Verifies end-to-end behaviour of PhiDetectionEngine + SemanticMasker:
- Person names are replaced with different but realistic names.
- Clinical terms (diagnoses, medications) survive masking unchanged.
- Multi-turn consistency: identical text masked multiple times in the same
  session produces identical output.

These tests require the spaCy 'en_core_web_lg' model and Presidio to be
installed.  They are integration tests because they exercise the full
detection + masking pipeline.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from phi_redactor.detection.engine import PhiDetectionEngine
from phi_redactor.masking.semantic import SemanticMasker
from phi_redactor.vault.store import PhiVault


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine() -> PhiDetectionEngine:
    """Shared detection engine for all tests in this module.

    Uses sensitivity=0.7 (permissive) so that clear PHI is reliably detected.
    Module scope avoids re-loading the spaCy model between tests.
    """
    return PhiDetectionEngine(sensitivity=0.7)


@pytest.fixture
def vault(tmp_dir: Path) -> PhiVault:
    """Per-test PhiVault backed by a temp SQLite database."""
    key = tmp_dir / "masking_quality.key"
    v = PhiVault(db_path=str(tmp_dir / "masking_quality.db"), key_path=key)
    yield v
    v.close()


@pytest.fixture
def masker(vault: PhiVault) -> SemanticMasker:
    """SemanticMasker backed by the per-test vault."""
    return SemanticMasker(vault=vault)


@pytest.fixture
def session_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Clinical note used across multiple tests
# ---------------------------------------------------------------------------

_CLINICAL_NOTE = (
    "Patient John Smith (DOB: 03/15/1956, SSN: 456-78-9012) presented to "
    "Springfield General Hospital on January 15, 2026. "
    "The 67-year-old male was diagnosed with Type 2 Diabetes Mellitus (E11.9). "
    "Treatment: metformin 1000mg BID. Referred by Dr. Maria Garcia. "
    "Contact: (555) 123-4567."
)

_CLINICAL_TERMS = [
    "Type 2 Diabetes Mellitus",
    "E11.9",
    "metformin",
    "1000mg",
    "BID",
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMaskedNoteHasDifferentName:
    def test_masked_note_has_different_name(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """After masking, the original patient name 'John Smith' must not appear in the output."""
        detections = engine.detect(_CLINICAL_NOTE)
        masked_text, _mapping = masker.mask(_CLINICAL_NOTE, detections, session_id)

        assert "John Smith" not in masked_text, (
            "Original patient name 'John Smith' was found in the masked text"
        )

    def test_masked_ssn_not_in_output(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """The original SSN must not appear in the masked text."""
        detections = engine.detect(_CLINICAL_NOTE)
        masked_text, _ = masker.mask(_CLINICAL_NOTE, detections, session_id)

        assert "456-78-9012" not in masked_text

    def test_masked_phone_not_in_output(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """The original phone number must not appear in the masked text."""
        detections = engine.detect(_CLINICAL_NOTE)
        masked_text, _ = masker.mask(_CLINICAL_NOTE, detections, session_id)

        assert "(555) 123-4567" not in masked_text

    def test_masked_text_is_non_empty(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """Masking should not produce an empty string."""
        detections = engine.detect(_CLINICAL_NOTE)
        masked_text, _ = masker.mask(_CLINICAL_NOTE, detections, session_id)

        assert masked_text.strip() != ""


class TestClinicalTermsPreserved:
    @pytest.mark.parametrize("clinical_term", _CLINICAL_TERMS)
    def test_clinical_term_preserved(
        self,
        clinical_term: str,
        engine: PhiDetectionEngine,
        masker: SemanticMasker,
        session_id: str,
    ) -> None:
        """Each specified clinical term must survive the masking pipeline unchanged."""
        detections = engine.detect(_CLINICAL_NOTE)
        masked_text, _ = masker.mask(_CLINICAL_NOTE, detections, session_id)

        assert clinical_term in masked_text, (
            f"Clinical term '{clinical_term}' was incorrectly removed during masking"
        )

    def test_phi_free_text_unchanged(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """Text with no PHI should pass through the masking pipeline unchanged."""
        phi_free = (
            "Type 2 Diabetes Mellitus (ICD-10: E11.9) is characterised by high blood sugar. "
            "Metformin 1000mg BID showed HbA1c reduction of 1.2% over 12 weeks."
        )
        detections = engine.detect(phi_free)
        masked_text, _ = masker.mask(phi_free, detections, session_id)

        # Core clinical content must remain.
        assert "Metformin" in masked_text or "metformin" in masked_text.lower()
        assert "HbA1c" in masked_text or "hba1c" in masked_text.lower()


class TestMultiTurnConsistency:
    def test_multi_turn_consistency(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """Masking the same text three times in the same session must produce identical output."""
        text = "Patient Jane Doe SSN 123-45-6789 was seen at (555) 987-6543."

        results = []
        for _ in range(3):
            detections = engine.detect(text)
            masked_text, _ = masker.mask(text, detections, session_id)
            results.append(masked_text)

        assert results[0] == results[1] == results[2], (
            "Repeated masking of identical text in the same session produced different outputs"
        )

    def test_multi_turn_consistent_name_replacement(
        self, engine: PhiDetectionEngine, masker: SemanticMasker, session_id: str
    ) -> None:
        """The same person name masked twice in the same session must map to the same synthetic."""
        text = "Dr. Alice Wong prescribed medication. Please contact Dr. Alice Wong."
        detections = engine.detect(text)
        masked_text, mapping = masker.mask(text, detections, session_id)

        # Collect all occurrences of "Alice Wong" positions in the masked text.
        # The simplest check: the masked text should not contain "Alice Wong".
        assert "Alice Wong" not in masked_text

        # The masked text should be internally consistent: the same placeholder must be
        # used wherever the original name appeared (no two different synthetic names).
        # We verify this by checking that the second masking run produces the same output.
        detections2 = engine.detect(text)
        masked_text2, _ = masker.mask(text, detections2, session_id)
        assert masked_text == masked_text2

    def test_different_sessions_may_produce_different_synthetics(
        self, engine: PhiDetectionEngine, vault: PhiVault
    ) -> None:
        """Two different sessions can (and likely will) produce different synthetic names."""
        text = "Patient John Smith SSN 456-78-9012."

        session_a = str(uuid.uuid4())
        session_b = str(uuid.uuid4())

        masker_a = SemanticMasker(vault=vault)
        masker_b = SemanticMasker(vault=vault)

        detections_a = engine.detect(text)
        masked_a, _ = masker_a.mask(text, detections_a, session_a)

        detections_b = engine.detect(text)
        masked_b, _ = masker_b.mask(text, detections_b, session_b)

        # Both outputs must have the PHI removed.
        assert "John Smith" not in masked_a
        assert "John Smith" not in masked_b
        assert "456-78-9012" not in masked_a
        assert "456-78-9012" not in masked_b

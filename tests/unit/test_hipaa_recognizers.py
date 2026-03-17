"""Unit tests for all 8 custom HIPAA recognizers.

Each test class exercises a single recognizer with:
- True positives: text that SHOULD be detected.
- False positives / negatives: text that should NOT be detected or should
  score below threshold.

Tests call the recognizer's ``analyze()`` method directly (via a lightweight
Presidio ``AnalyzerEngine``) to isolate recognizer logic from the full
detection pipeline.
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

from phi_redactor.detection.recognizers.account import AccountRecognizer
from phi_redactor.detection.recognizers.biometric import BiometricRecognizer
from phi_redactor.detection.recognizers.device import DeviceRecognizer
from phi_redactor.detection.recognizers.fax import FaxRecognizer
from phi_redactor.detection.recognizers.health_plan import HealthPlanRecognizer
from phi_redactor.detection.recognizers.license import LicenseRecognizer
from phi_redactor.detection.recognizers.mrn import MRNRecognizer
from phi_redactor.detection.recognizers.vehicle import VehicleRecognizer

# ---------------------------------------------------------------------------
# Helper: build a minimal Presidio AnalyzerEngine with a single recognizer
# ---------------------------------------------------------------------------


def _build_analyzer(*recognizers) -> AnalyzerEngine:
    """Create an AnalyzerEngine with only the given recognizer(s) loaded.

    Uses a simple regex NLP engine (no spaCy required) to keep tests fast.
    """
    registry = RecognizerRegistry()
    # Do NOT load predefined recognizers -- we want isolation
    for rec in recognizers:
        registry.add_recognizer(rec)

    return AnalyzerEngine(
        registry=registry,
        supported_languages=["en"],
        nlp_engine=None,
    )


def _detect_entities(analyzer: AnalyzerEngine, text: str, entities: list[str]):
    """Run analysis and return results for the specified entity types."""
    return analyzer.analyze(
        text=text,
        language="en",
        entities=entities,
    )


# ===========================================================================
# T042: MRN Recognizer
# ===========================================================================


class TestMRNRecognizer:
    """Tests for MRNRecognizer -- Medical Record Numbers."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = MRNRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "MRN"

    def test_mrn_with_prefix(self):
        """MRN: 00456789 should be detected when preceded by 'MRN:'."""
        text = "Patient MRN: 00456789 was admitted."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1
        matched = text[results[0].start : results[0].end]
        assert "00456789" in matched

    def test_mrn_with_context_medical_record(self):
        """Medical record number 12345678 should be detected."""
        text = "The medical record number is 12345678."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_mrn_with_chart_number_context(self):
        """Chart number context should trigger detection."""
        text = "Chart number 9876543 on file."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_mrn_six_digit(self):
        """6-digit MRN with context should be detected."""
        text = "MRN: 123456 in the system."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_mrn_ten_digit(self):
        """10-digit MRN should be detected."""
        text = "Patient ID: 1234567890 assigned."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_year(self):
        """A year like 2026 (4 digits) should NOT be detected as MRN."""
        text = "The study was conducted in 2026 across 5 sites."
        results = _detect_entities(self.analyzer, text, [self.entity])
        # Should have no results (4 digits < 6 minimum)
        assert len(results) == 0

    def test_false_positive_no_context(self):
        """Bare digits without context should score low (below 0.5)."""
        text = "The measurement was 12345678 units."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0


# ===========================================================================
# T043: Health Plan Recognizer
# ===========================================================================


class TestHealthPlanRecognizer:
    """Tests for HealthPlanRecognizer -- Health Plan Beneficiary IDs."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = HealthPlanRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "HEALTH_PLAN_ID"

    def test_member_id_with_prefix(self):
        """Member ID with explicit prefix should be detected."""
        text = "Member ID: BCBS-987654321 is active."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_policy_number_context(self):
        """Policy number with context should be detected."""
        text = "Policy number ABC123456789 expires next month."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_subscriber_id_context(self):
        """Subscriber ID with context should be detected."""
        text = "Subscriber ID: H12345678 on the plan."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_insurance_id_context(self):
        """Insurance ID with context should be detected."""
        text = "Insurance ID UHC987654321 verified."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_group_number_context(self):
        """Group number with context should be detected."""
        text = "Group number: GRP1234567 for the employer plan."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_random_alpha_num(self):
        """Random alphanumeric string without context should score low."""
        text = "The code XYZ123 was entered."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0

    def test_false_positive_icd_code(self):
        """ICD-10 codes should NOT be detected as health plan IDs."""
        text = "Diagnosis: E11.9 Type 2 Diabetes Mellitus."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0


# ===========================================================================
# T044: Account Recognizer
# ===========================================================================


class TestAccountRecognizer:
    """Tests for AccountRecognizer -- Account Numbers."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = AccountRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "ACCOUNT_NUMBER"

    def test_account_number_with_prefix(self):
        """Account number with explicit prefix should be detected."""
        text = "Account number: 001234567890 on file."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_acct_hash_prefix(self):
        """Acct # prefix should be detected."""
        text = "Acct # 12345678 for billing."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_billing_context(self):
        """Billing context should trigger detection."""
        text = "Billing account 87654321 was charged."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_acc_prefixed_format(self):
        """ACC- prefixed format should be detected."""
        text = "Account number: ACC-00112233 active."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_phone_number(self):
        """Phone number format should NOT match high-confidence account."""
        text = "Call us at 5551234567 for information."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0

    def test_false_positive_no_context(self):
        """Bare digits without context should score low."""
        text = "The total was 12345678 items."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0


# ===========================================================================
# T045: License Recognizer
# ===========================================================================


class TestLicenseRecognizer:
    """Tests for LicenseRecognizer -- DEA, NPI, and state license numbers."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = LicenseRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "LICENSE_NUMBER"

    def test_dea_number(self):
        """DEA number AB1234563 should be detected."""
        text = "Provider DEA number: AB1234563 on file."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1
        matched_texts = [text[r.start : r.end] for r in results]
        assert any("AB1234563" in m for m in matched_texts)

    def test_npi_number(self):
        """10-digit NPI should be detected with context."""
        text = "NPI: 1234567893 for the provider."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_state_license_with_context(self):
        """State license number with context should be detected."""
        text = "Medical license number: MD12345678 active."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_license_hash_format(self):
        """License # format should be detected."""
        text = "License # AB1234567 issued by the state."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_random_digits(self):
        """Random 10-digit number without context should score low."""
        text = "The population of the city is 3456789012 people."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.7]
        assert len(high_confidence) == 0

    def test_false_positive_five_digits(self):
        """5-digit number should NOT match NPI or DEA pattern."""
        text = "Zip code 62704 is in Illinois."
        results = _detect_entities(self.analyzer, text, [self.entity])
        # DEA needs 2 letters + 7 digits; NPI needs 10 digits; state needs 5+
        # A 5-digit number alone shouldn't strongly match
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0


# ===========================================================================
# T046: Vehicle Recognizer
# ===========================================================================


class TestVehicleRecognizer:
    """Tests for VehicleRecognizer -- VIN and license plates."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = VehicleRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "VEHICLE_ID"

    def test_vin_17_char(self):
        """Standard 17-character VIN should be detected."""
        text = "VIN: 1HGBH41JXMN109186 on the record."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1
        matched_texts = [text[r.start : r.end] for r in results]
        assert any("1HGBH41JXMN109186" in m for m in matched_texts)

    def test_vin_with_context(self):
        """VIN with 'vehicle identification number' context."""
        text = "Vehicle identification number 2T1BURHE0JC034461 registered."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_license_plate_with_context(self):
        """License plate with context should be detected."""
        text = "License plate number: ABC 1234 on file."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_plate_number_format(self):
        """Plate # format should be detected."""
        text = "Plate # XYZ5678 registered to the patient."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_short_string(self):
        """Short alphanumeric without context should not match VIN."""
        text = "The code A1B2C3 was used."
        results = _detect_entities(self.analyzer, text, [self.entity])
        # VIN requires exactly 17 chars; plate pattern is context-dependent
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0

    def test_false_positive_vin_with_ioq(self):
        """VIN containing I, O, or Q is invalid per ISO 3779."""
        text = "VIN: 1HGBH41IXON109186 on the record."
        results = _detect_entities(self.analyzer, text, [self.entity])
        # The I and O should prevent the 17-char VIN pattern from matching
        vin_matches = [r for r in results if r.score >= 0.7 and (r.end - r.start) == 17]
        assert len(vin_matches) == 0


# ===========================================================================
# T047: Device Recognizer
# ===========================================================================


class TestDeviceRecognizer:
    """Tests for DeviceRecognizer -- UDI and device serial numbers."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = DeviceRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "DEVICE_ID"

    def test_gs1_udi(self):
        """GS1 UDI format (01) + 14 digits should be detected."""
        text = "Device UDI: (01)00884521356148 implanted."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1
        matched_texts = [text[r.start : r.end] for r in results]
        assert any("(01)00884521356148" in m for m in matched_texts)

    def test_hibcc_udi(self):
        """HIBCC UDI format + prefix should be detected."""
        text = "UDI: +H123456789012 on the device label."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_iccbba_udi(self):
        """ICCBBA UDI format = prefix should be detected."""
        text = "Device identifier =A12345678901 scanned."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_serial_number_with_context(self):
        """Device serial number with context should be detected."""
        text = "Device serial number: SN1234567890 recorded."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_implant_serial(self):
        """Implant serial with context should be detected."""
        text = "Implant serial: IMP98765432 placed during surgery."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_random_string(self):
        """Random short alphanumeric without context should score low."""
        text = "The result was AB12 for the test."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0


# ===========================================================================
# T048: Biometric Recognizer
# ===========================================================================


class TestBiometricRecognizer:
    """Tests for BiometricRecognizer -- biometric identifier mentions."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = BiometricRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "BIOMETRIC_ID"

    def test_fingerprint_mention(self):
        """'fingerprint' keyword should be detected."""
        text = "Patient fingerprint was collected for identification."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_retinal_scan(self):
        """'retinal scan' should be detected."""
        text = "A retinal scan was performed for access control."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_voiceprint(self):
        """'voiceprint' should be detected."""
        text = "The voiceprint was recorded for authentication."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_facial_recognition(self):
        """'facial recognition' should be detected."""
        text = "Facial recognition data was stored securely."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_dna_profile(self):
        """'DNA profile' should be detected."""
        text = "The DNA profile was sent to the genetics lab."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_genetic_data(self):
        """'genetic data' should be detected."""
        text = "Genetic data analysis revealed carrier status."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_iris_scan(self):
        """'iris scan' should be detected."""
        text = "An iris scan was used for secure facility access."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_palm_print(self):
        """'palm print' should be detected."""
        text = "Palm print captured for biometric verification."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_biometric_data_reference(self):
        """'biometric data' reference should be detected."""
        text = "All biometric data must be encrypted at rest."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_general_biology(self):
        """General biology terms should NOT trigger detection."""
        text = "The cell biology experiment showed positive results."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) == 0

    def test_false_positive_dna_abbreviation_alone(self):
        """Bare 'DNA' without profile/sample/test context should not match highly."""
        text = "DNA is the molecule of heredity."
        results = _detect_entities(self.analyzer, text, [self.entity])
        # The pattern requires "DNA profile/sample/test/analysis/etc."
        # Bare "DNA" alone should not match
        assert len(results) == 0


# ===========================================================================
# Fax Recognizer (supplementary -- needed for FAX_NUMBER coverage)
# ===========================================================================


class TestFaxRecognizer:
    """Tests for FaxRecognizer -- Fax Numbers."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.recognizer = FaxRecognizer()
        self.analyzer = _build_analyzer(self.recognizer)
        self.entity = "FAX_NUMBER"

    def test_fax_with_prefix(self):
        """Fax number with 'Fax:' prefix should be detected."""
        text = "Fax: (555) 987-6543 for medical records."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_fax_number_context(self):
        """Fax number with 'fax number' context should be detected."""
        text = "Fax number: 555-987-6543 on file."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_facsimile_context(self):
        """'facsimile' context should trigger detection."""
        text = "Send via facsimile to 555-123-4567."
        results = _detect_entities(self.analyzer, text, [self.entity])
        assert len(results) >= 1

    def test_false_positive_bare_phone(self):
        """Bare phone number without fax context should score low."""
        text = "Call 555-123-4567 for appointments."
        results = _detect_entities(self.analyzer, text, [self.entity])
        high_confidence = [r for r in results if r.score >= 0.5]
        assert len(high_confidence) == 0

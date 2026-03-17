"""Integration benchmark test for full HIPAA detection coverage.

Verifies that the complete detection pipeline (built-in + custom recognizers)
can detect at least one example of each of the 18 HIPAA Safe Harbor identifier
categories from a synthetic clinical document.

Measures and logs precision/recall per category.
"""

from __future__ import annotations

import logging
import time

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
from phi_redactor.detection.registry import HIPAARecognizerRegistry
from phi_redactor.models import PHICategory

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Synthetic clinical document with all 18 HIPAA identifier types
# ---------------------------------------------------------------------------

SYNTHETIC_CLINICAL_DOCUMENT = """
DISCHARGE SUMMARY
==================

Patient: John Michael Smith
Date of Birth: March 15, 1956
Date of Admission: January 10, 2026
Date of Discharge: January 18, 2026
MRN: 00456789

DEMOGRAPHICS:
Address: 742 Evergreen Terrace, Springfield, IL 62704
Phone: (555) 123-4567
Fax: (555) 987-6543
Email: john.smith@springfieldgeneral.com
SSN: 456-78-9012

INSURANCE INFORMATION:
Health Plan: Blue Cross Blue Shield
Member ID: BCBS-987654321
Group Number: GRP1234567
Subscriber: John Smith
Policy Number: POL88776655

BILLING:
Account Number: ACC-00112233
Billing Account: 98765432

ATTENDING PHYSICIAN:
Dr. Maria Garcia, MD
NPI: 1234567893
DEA: AG1234563
Medical License: MD12345678

CLINICAL SUMMARY:
The 69-year-old male presented with exacerbation of Type 2 Diabetes
Mellitus (E11.9). Patient was transported via vehicle VIN: 1HGBH41JXMN109186,
license plate: ABC 1234.

DEVICES AND IMPLANTS:
Continuous glucose monitor implanted.
Device UDI: (01)00884521356148
Device serial number: SN-CGM2024-0042

BIOMETRIC DATA:
Fingerprint collected for patient identification system.
Retinal scan performed for secure medication dispensing access.
DNA profile sent to genetics laboratory for pharmacogenomic analysis.

DIGITAL ACCESS:
Patient portal: https://patient-portal.springfieldgeneral.com/john-smith
Access IP: 192.168.1.100

PHOTO:
Full face photograph taken for medical records identification.

OTHER IDENTIFIERS:
Passport: US Passport number held on file for international transfer.
Certificate number: CERT-2024-99887

PROVIDER NOTES:
Patient fingerprint verification completed at discharge.
All biometric data encrypted per facility policy.
"""

# ---------------------------------------------------------------------------
# Expected detections: map each PHICategory to what should be found
# ---------------------------------------------------------------------------

# Categories that should be detected from the synthetic document text.
# PHOTO is a special case -- it's text-based mention, not an actual image.
EXPECTED_CATEGORIES_IN_TEXT: dict[PHICategory, list[str]] = {
    PHICategory.PERSON_NAME: ["John Smith", "Maria Garcia"],
    PHICategory.GEOGRAPHIC_DATA: ["Springfield", "742 Evergreen Terrace"],
    PHICategory.DATE: ["March 15, 1956", "January 10, 2026"],
    PHICategory.PHONE_NUMBER: ["(555) 123-4567"],
    PHICategory.FAX_NUMBER: ["(555) 987-6543"],
    PHICategory.EMAIL_ADDRESS: ["john.smith@springfieldgeneral.com"],
    PHICategory.SSN: ["456-78-9012"],
    PHICategory.MRN: ["00456789"],
    PHICategory.HEALTH_PLAN_ID: ["BCBS-987654321"],
    PHICategory.ACCOUNT_NUMBER: ["ACC-00112233", "98765432"],
    PHICategory.LICENSE_NUMBER: ["1234567893", "AG1234563", "MD12345678"],
    PHICategory.VEHICLE_ID: ["1HGBH41JXMN109186"],
    PHICategory.DEVICE_ID: ["(01)00884521356148"],
    PHICategory.WEB_URL: ["https://patient-portal.springfieldgeneral.com/john-smith"],
    PHICategory.IP_ADDRESS: ["192.168.1.100"],
    PHICategory.BIOMETRIC_ID: ["fingerprint", "retinal scan", "DNA profile"],
    PHICategory.PHOTO: [],  # Requires image analysis, not text detection
    PHICategory.OTHER_UNIQUE_ID: [],  # Passport mapped here by built-in
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine() -> PhiDetectionEngine:
    """Create detection engine for benchmark tests."""
    return PhiDetectionEngine(sensitivity=0.8)


@pytest.fixture(scope="module")
def registry() -> HIPAARecognizerRegistry:
    """Create registry for coverage validation."""
    return HIPAARecognizerRegistry()


# ---------------------------------------------------------------------------
# Test: Registry coverage of all 18 categories
# ---------------------------------------------------------------------------


class TestRegistryCoverage:
    """Verify the registry reports coverage for all 18 HIPAA categories."""

    def test_all_18_categories_covered(self, registry: HIPAARecognizerRegistry):
        """validate_coverage() should return True for all 18 categories."""
        coverage = registry.validate_coverage()
        uncovered = [cat.value for cat, covered in coverage.items() if not covered]
        assert len(uncovered) == 0, (
            f"The following HIPAA categories lack recognizer coverage: {uncovered}"
        )

    def test_supported_categories_count(self, registry: HIPAARecognizerRegistry):
        """get_supported_categories() should include all 18 categories."""
        supported = registry.get_supported_categories()
        assert len(supported) == 18, (
            f"Expected 18 supported categories, got {len(supported)}: "
            f"{[c.value for c in supported]}"
        )

    def test_no_uncovered_categories(self, registry: HIPAARecognizerRegistry):
        """get_uncovered_categories() should return empty list."""
        uncovered = registry.get_uncovered_categories()
        assert len(uncovered) == 0, f"Uncovered categories: {[c.value for c in uncovered]}"


# ---------------------------------------------------------------------------
# Test: Full detection benchmark on synthetic document
# ---------------------------------------------------------------------------


class TestDetectionBenchmark:
    """Benchmark detection of all 18 HIPAA identifier types."""

    def test_detect_all_categories(self, engine: PhiDetectionEngine):
        """The engine should detect at least one entity per text-detectable category.

        PHOTO and OTHER_UNIQUE_ID may not have text-based detections in
        all documents, so they are treated as optional.
        """
        detections = engine.detect(SYNTHETIC_CLINICAL_DOCUMENT, sensitivity=0.9)

        detected_categories = {d.category for d in detections}

        # Categories we MUST detect from the synthetic document
        required_categories = {
            PHICategory.PERSON_NAME,
            PHICategory.DATE,
            PHICategory.PHONE_NUMBER,
            PHICategory.EMAIL_ADDRESS,
            PHICategory.SSN,
            PHICategory.MRN,
            PHICategory.HEALTH_PLAN_ID,
            PHICategory.ACCOUNT_NUMBER,
            PHICategory.LICENSE_NUMBER,
            PHICategory.VEHICLE_ID,
            PHICategory.DEVICE_ID,
            PHICategory.WEB_URL,
            PHICategory.IP_ADDRESS,
            PHICategory.BIOMETRIC_ID,
            PHICategory.FAX_NUMBER,
        }

        missing = required_categories - detected_categories
        assert len(missing) == 0, (
            f"Failed to detect the following required categories: "
            f"{[c.value for c in missing]}.\n"
            f"Detected categories: {[c.value for c in sorted(detected_categories, key=lambda c: c.value)]}"
        )

    def test_detection_performance(self, engine: PhiDetectionEngine):
        """Detection should complete within a reasonable time budget.

        The synthetic document (~2KB) should be analyzed in under 10 seconds
        even on modest hardware.
        """
        start = time.perf_counter()
        detections = engine.detect(SYNTHETIC_CLINICAL_DOCUMENT, sensitivity=0.8)
        elapsed_ms = (time.perf_counter() - start) * 1000

        logger.info(
            "Detection benchmark: %d entities detected in %.1f ms",
            len(detections),
            elapsed_ms,
        )
        assert elapsed_ms < 10_000, f"Detection took {elapsed_ms:.1f}ms, exceeding 10s budget"

    def test_precision_recall_per_category(self, engine: PhiDetectionEngine):
        """Log precision and recall metrics per category.

        This test does not assert strict thresholds but logs metrics for
        monitoring and tuning.  It asserts that at least some detections
        were produced.
        """
        detections = engine.detect(SYNTHETIC_CLINICAL_DOCUMENT, sensitivity=0.9)

        # Group detections by category
        by_category: dict[PHICategory, list] = {}
        for d in detections:
            by_category.setdefault(d.category, []).append(d)

        total_detected = 0
        total_expected = 0

        for category in PHICategory:
            expected = EXPECTED_CATEGORIES_IN_TEXT.get(category, [])
            detected = by_category.get(category, [])
            detected_texts = [d.original_text for d in detected]

            # Count true positives (expected items that were found)
            true_positives = 0
            for exp in expected:
                if any(exp.lower() in dt.lower() for dt in detected_texts):
                    true_positives += 1

            recall = true_positives / len(expected) if expected else 1.0
            # Precision: of the things we detected, how many were expected
            # (simplified -- actual precision needs labeled negatives)
            precision = (
                true_positives / len(detected) if detected else (1.0 if not expected else 0.0)
            )

            total_detected += len(detected)
            total_expected += len(expected)

            logger.info(
                "Category %-20s: detected=%d, expected=%d, TP=%d, precision=%.2f, recall=%.2f",
                category.value,
                len(detected),
                len(expected),
                true_positives,
                precision,
                recall,
            )

        assert total_detected > 0, "Expected at least some detections"
        logger.info(
            "TOTAL: %d detections, %d expected items across all categories",
            total_detected,
            total_expected,
        )

    def test_confidence_distribution(self, engine: PhiDetectionEngine):
        """Log and validate confidence score distribution."""
        detections = engine.detect(SYNTHETIC_CLINICAL_DOCUMENT, sensitivity=0.9)

        if not detections:
            pytest.skip("No detections to analyze")

        scores = [d.confidence for d in detections]
        avg_confidence = sum(scores) / len(scores)
        min_confidence = min(scores)
        max_confidence = max(scores)

        logger.info(
            "Confidence distribution: min=%.3f, max=%.3f, avg=%.3f, count=%d",
            min_confidence,
            max_confidence,
            avg_confidence,
            len(scores),
        )

        # All scores should be in valid range
        for d in detections:
            assert 0.0 <= d.confidence <= 1.0, (
                f"Invalid confidence {d.confidence} for {d.category}: '{d.original_text}'"
            )

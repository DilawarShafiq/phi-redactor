"""HIPAA recognizer registry for Presidio-based PHI detection.

Registers all built-in Presidio recognizers and custom HIPAA recognizers,
mapping them to the 18 HIPAA Safe Harbor identifier categories.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from presidio_analyzer import PatternRecognizer, RecognizerRegistry

from phi_redactor.detection.recognizers import (
    AccountRecognizer,
    BiometricRecognizer,
    DeviceRecognizer,
    FaxRecognizer,
    FHIRResourceRecognizer,
    HL7v2Recognizer,
    HealthPlanRecognizer,
    LicenseRecognizer,
    MRNRecognizer,
    VehicleRecognizer,
)
from phi_redactor.models import PHICategory

if TYPE_CHECKING:
    from presidio_analyzer import EntityRecognizer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapping from Presidio entity types to our PHICategory enum
# ---------------------------------------------------------------------------

PRESIDIO_TO_PHI_CATEGORY: dict[str, PHICategory] = {
    # Built-in Presidio entity types
    "PERSON": PHICategory.PERSON_NAME,
    "LOCATION": PHICategory.GEOGRAPHIC_DATA,
    "DATE_TIME": PHICategory.DATE,
    "PHONE_NUMBER": PHICategory.PHONE_NUMBER,
    "EMAIL_ADDRESS": PHICategory.EMAIL_ADDRESS,
    "US_SSN": PHICategory.SSN,
    "URL": PHICategory.WEB_URL,
    "IP_ADDRESS": PHICategory.IP_ADDRESS,
    "US_DRIVER_LICENSE": PHICategory.LICENSE_NUMBER,
    "CREDIT_CARD": PHICategory.ACCOUNT_NUMBER,
    "US_BANK_NUMBER": PHICategory.ACCOUNT_NUMBER,
    "US_PASSPORT": PHICategory.OTHER_UNIQUE_ID,
    "US_ITIN": PHICategory.OTHER_UNIQUE_ID,
    "NRP": PHICategory.OTHER_UNIQUE_ID,
    "MEDICAL_LICENSE": PHICategory.LICENSE_NUMBER,
    # Aliases used by some Presidio versions
    "IBAN_CODE": PHICategory.ACCOUNT_NUMBER,
    "CRYPTO": PHICategory.OTHER_UNIQUE_ID,
    # Custom HIPAA recognizer entity types (Phase 4)
    "MRN": PHICategory.MRN,
    "HEALTH_PLAN_ID": PHICategory.HEALTH_PLAN_ID,
    "ACCOUNT_NUMBER": PHICategory.ACCOUNT_NUMBER,
    "LICENSE_NUMBER": PHICategory.LICENSE_NUMBER,
    "VEHICLE_ID": PHICategory.VEHICLE_ID,
    "DEVICE_ID": PHICategory.DEVICE_ID,
    "BIOMETRIC_ID": PHICategory.BIOMETRIC_ID,
    "FAX_NUMBER": PHICategory.FAX_NUMBER,
    # FHIR/HL7 recognizer entity types (Phase 9)
    "FHIR_REFERENCE": PHICategory.OTHER_UNIQUE_ID,
    "HL7V2_SEGMENT": PHICategory.OTHER_UNIQUE_ID,
}

# ---------------------------------------------------------------------------
# Custom recognizer classes to register
# ---------------------------------------------------------------------------

_CUSTOM_RECOGNIZER_CLASSES: list[type[PatternRecognizer]] = [
    MRNRecognizer,
    HealthPlanRecognizer,
    AccountRecognizer,
    LicenseRecognizer,
    VehicleRecognizer,
    DeviceRecognizer,
    BiometricRecognizer,
    FaxRecognizer,
    FHIRResourceRecognizer,
    HL7v2Recognizer,
]


class HIPAARecognizerRegistry:
    """Registers all recognizers needed for 18 HIPAA Safe Harbor identifiers.

    Loads Presidio's built-in recognizers and adds 8 custom recognizers for
    healthcare-specific identifier categories:

    **Built-in coverage:**
    - PERSON_NAME -- via spaCy NER (SpacyRecognizer)
    - PHONE_NUMBER -- built-in pattern recognizer
    - EMAIL_ADDRESS -- built-in pattern recognizer
    - SSN (US_SSN) -- built-in pattern recognizer
    - WEB_URL (URL) -- built-in pattern recognizer
    - IP_ADDRESS -- built-in pattern recognizer
    - DATE_TIME -- built-in pattern + spaCy NER
    - GEOGRAPHIC_DATA -- via spaCy NER (LOCATION entities)
    - LICENSE_NUMBER -- US_DRIVER_LICENSE + MEDICAL_LICENSE built-in
    - ACCOUNT_NUMBER -- CREDIT_CARD + US_BANK_NUMBER + IBAN_CODE built-in
    - OTHER_UNIQUE_ID -- US_PASSPORT + US_ITIN + NRP + CRYPTO built-in

    **Custom coverage (Phase 4):**
    - MRN -- MRNRecognizer
    - HEALTH_PLAN_ID -- HealthPlanRecognizer
    - ACCOUNT_NUMBER -- AccountRecognizer (supplements built-in)
    - LICENSE_NUMBER -- LicenseRecognizer (supplements built-in)
    - VEHICLE_ID -- VehicleRecognizer
    - DEVICE_ID -- DeviceRecognizer
    - BIOMETRIC_ID -- BiometricRecognizer
    - FAX_NUMBER -- FaxRecognizer

    **Categories without pattern-based detection:**
    - PHOTO -- requires image analysis (not text-based); marked as covered
      via metadata flag.
    """

    def __init__(self) -> None:
        self._recognizers: list[EntityRecognizer] = []
        self._registry = RecognizerRegistry()
        self._registry.load_predefined_recognizers()

        # Register all custom HIPAA recognizers
        for recognizer_cls in _CUSTOM_RECOGNIZER_CLASSES:
            recognizer = recognizer_cls()
            self._registry.add_recognizer(recognizer)
            logger.debug("Registered custom recognizer: %s", recognizer.name)

        self._recognizers = list(self._registry.recognizers)
        logger.info(
            "Loaded %d recognizers (%d built-in + %d custom)",
            len(self._recognizers),
            len(self._recognizers) - len(_CUSTOM_RECOGNIZER_CLASSES),
            len(_CUSTOM_RECOGNIZER_CLASSES),
        )

    @property
    def registry(self) -> RecognizerRegistry:
        """Return the underlying Presidio RecognizerRegistry."""
        return self._registry

    def get_recognizers(self) -> list[EntityRecognizer]:
        """Return list of all registered recognizer instances."""
        return list(self._recognizers)

    def get_supported_entities(self) -> list[str]:
        """Return list of all Presidio entity type strings that are supported."""
        entities: set[str] = set()
        for recognizer in self._recognizers:
            entities.update(recognizer.supported_entities)
        return sorted(entities)

    def get_supported_categories(self) -> list[PHICategory]:
        """Return list of PHICategory values that have at least one recognizer.

        Only categories that can be mapped from a registered Presidio entity
        type are included.  PHOTO is always included since it is handled
        outside the text-analysis pipeline (image analysis).
        """
        supported_entities = self.get_supported_entities()
        categories: set[PHICategory] = set()
        for entity in supported_entities:
            if entity in PRESIDIO_TO_PHI_CATEGORY:
                categories.add(PRESIDIO_TO_PHI_CATEGORY[entity])
        # PHOTO is always considered covered -- it requires image analysis,
        # not text pattern matching.
        categories.add(PHICategory.PHOTO)
        return sorted(categories, key=lambda c: c.value)

    def validate_coverage(self) -> dict[PHICategory, bool]:
        """Return dict mapping each of the 18 HIPAA categories to coverage status.

        A category is considered covered if at least one registered recognizer
        can detect the corresponding entity type, OR if the category is handled
        outside the text pipeline (e.g., PHOTO via image analysis).

        Returns:
            Dictionary mapping every PHICategory to a boolean indicating
            whether at least one recognizer covers it.
        """
        supported = set(self.get_supported_categories())
        return {category: category in supported for category in PHICategory}

    def get_uncovered_categories(self) -> list[PHICategory]:
        """Return list of HIPAA categories that have NO recognizer coverage.

        Returns:
            List of PHICategory values that are not covered by any recognizer.
            Empty list means full 18/18 coverage.
        """
        coverage = self.validate_coverage()
        return [cat for cat, covered in coverage.items() if not covered]

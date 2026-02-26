"""Custom HIPAA recognizers for Presidio-based PHI detection.

This package provides 10 custom recognizers that, together with Presidio's
built-in recognizers, cover all 18 HIPAA Safe Harbor identifier categories
plus FHIR and HL7v2 healthcare data format detection.

Public API::

    from phi_redactor.detection.recognizers import (
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
    )
"""

from __future__ import annotations

from phi_redactor.detection.recognizers.account import AccountRecognizer
from phi_redactor.detection.recognizers.biometric import BiometricRecognizer
from phi_redactor.detection.recognizers.device import DeviceRecognizer
from phi_redactor.detection.recognizers.fax import FaxRecognizer
from phi_redactor.detection.recognizers.fhir import FHIRResourceRecognizer
from phi_redactor.detection.recognizers.health_plan import HealthPlanRecognizer
from phi_redactor.detection.recognizers.hl7 import HL7v2Recognizer
from phi_redactor.detection.recognizers.license import LicenseRecognizer
from phi_redactor.detection.recognizers.mrn import MRNRecognizer
from phi_redactor.detection.recognizers.vehicle import VehicleRecognizer

__all__ = [
    "AccountRecognizer",
    "BiometricRecognizer",
    "DeviceRecognizer",
    "FaxRecognizer",
    "FHIRResourceRecognizer",
    "HL7v2Recognizer",
    "HealthPlanRecognizer",
    "LicenseRecognizer",
    "MRNRecognizer",
    "VehicleRecognizer",
]

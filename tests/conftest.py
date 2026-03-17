"""Shared pytest fixtures for phi-redactor tests."""

from __future__ import annotations

import tempfile
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def tmp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_clinical_text() -> str:
    """Sample clinical note containing various PHI types."""
    return (
        "Patient John Smith (DOB: 03/15/1956, SSN: 456-78-9012) presented to "
        "Springfield General Hospital on January 15, 2026. MRN: 00456789. "
        "The 67-year-old male was referred by Dr. Maria Garcia (NPI: 1234567890) "
        "for evaluation of Type 2 Diabetes Mellitus (E11.9). "
        "Contact: (555) 123-4567, john.smith@email.com. "
        "Address: 742 Evergreen Terrace, Springfield, IL 62704. "
        "Health Plan ID: BCBS-987654321. Account: ACC-00112233. "
        "IP: 192.168.1.100. URL: https://patient-portal.example.com/john-smith"
    )


@pytest.fixture
def sample_phi_free_text() -> str:
    """Sample text with no PHI for false positive testing."""
    return (
        "Type 2 Diabetes Mellitus (ICD-10: E11.9) is a metabolic disease "
        "characterized by high blood sugar. The study enrolled 123 patients "
        "across 5 clinical sites. Treatment with metformin 1000mg BID showed "
        "HbA1c reduction of 1.2% over 12 weeks."
    )


@pytest.fixture
def sample_fhir_patient() -> dict:
    """Sample FHIR Patient resource containing PHI."""
    return {
        "resourceType": "Patient",
        "id": "example",
        "active": True,
        "name": [{"use": "official", "family": "Smith", "given": ["John"]}],
        "gender": "male",
        "birthDate": "1956-03-15",
        "address": [
            {
                "use": "home",
                "line": ["742 Evergreen Terrace"],
                "city": "Springfield",
                "state": "IL",
                "postalCode": "62704",
            }
        ],
        "telecom": [
            {"system": "phone", "value": "(555) 123-4567", "use": "home"},
            {"system": "email", "value": "john.smith@email.com"},
        ],
        "identifier": [
            {"system": "http://hl7.org/fhir/sid/us-ssn", "value": "456-78-9012"},
            {"system": "http://hospital.example.com/mrn", "value": "00456789"},
        ],
    }


@pytest.fixture
def session_id() -> str:
    """Generate a test session ID."""
    return str(uuid.uuid4())


@pytest.fixture
def vault_path(tmp_dir: Path) -> Path:
    """Provide a temporary vault database path."""
    return tmp_dir / "test_vault.db"


@pytest.fixture
def audit_path(tmp_dir: Path) -> Path:
    """Provide a temporary audit trail directory."""
    audit_dir = tmp_dir / "audit"
    audit_dir.mkdir()
    return audit_dir

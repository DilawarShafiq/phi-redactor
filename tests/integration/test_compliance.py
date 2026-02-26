"""Integration tests for compliance reports.

Verifies:
- generate_report returns a dict containing all required top-level sections.
- The report body contains no PHI strings from the audit events.
- Integrity verification passes for a freshly populated audit trail.
- An empty audit trail produces a report with compliance status 'no_data'.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from phi_redactor.audit.reports import ComplianceReportGenerator
from phi_redactor.audit.trail import AuditTrail


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_trail(audit_path: Path) -> AuditTrail:
    """AuditTrail instance backed by a temporary directory."""
    return AuditTrail(audit_dir=audit_path)


@pytest.fixture
def report_generator(audit_trail: AuditTrail) -> ComplianceReportGenerator:
    """ComplianceReportGenerator backed by the per-test audit trail."""
    return ComplianceReportGenerator(audit_trail)


def _populate_audit_trail(trail: AuditTrail, n: int = 5) -> str:
    """Log *n* audit events for a single session and return the session ID."""
    session_id = str(uuid.uuid4())
    categories = ["PERSON_NAME", "SSN", "DATE", "PHONE_NUMBER", "EMAIL_ADDRESS"]
    methods = ["regex", "ner", "regex", "regex", "ner"]
    for i in range(n):
        trail.log_event(
            session_id=session_id,
            request_id=str(uuid.uuid4()),
            category=categories[i % len(categories)],
            confidence=0.85,
            action="redacted",
            detection_method=methods[i % len(methods)],
            text_length=10 + i,
        )
    return session_id


# ---------------------------------------------------------------------------
# Required report sections
# ---------------------------------------------------------------------------

_REQUIRED_SECTIONS = {
    "report_metadata",
    "summary",
    "category_coverage",
    "confidence_analysis",
    "detection_methods",
    "integrity_verification",
    "compliance_status",
}


class TestReportContainsAllSections:
    def test_report_contains_all_sections(
        self, report_generator: ComplianceReportGenerator, audit_trail: AuditTrail
    ) -> None:
        """generate_report must return a dict that includes every required top-level key."""
        _populate_audit_trail(audit_trail)
        report = report_generator.generate_report()

        missing = _REQUIRED_SECTIONS - set(report.keys())
        assert not missing, f"Report is missing sections: {missing}"

    def test_report_metadata_has_expected_keys(
        self, report_generator: ComplianceReportGenerator, audit_trail: AuditTrail
    ) -> None:
        """report_metadata must contain title, generated_at, reporting_period, and standard."""
        _populate_audit_trail(audit_trail)
        report = report_generator.generate_report()
        metadata = report["report_metadata"]

        assert "title" in metadata
        assert "generated_at" in metadata
        assert "reporting_period" in metadata
        assert "standard" in metadata

    def test_report_summary_has_expected_keys(
        self, report_generator: ComplianceReportGenerator, audit_trail: AuditTrail
    ) -> None:
        """summary section must include total_redaction_events and unique_sessions."""
        _populate_audit_trail(audit_trail)
        report = report_generator.generate_report()
        summary = report["summary"]

        assert "total_redaction_events" in summary
        assert "unique_sessions" in summary
        assert "phi_entities_detected" in summary

    def test_compliance_status_has_overall_key(
        self, report_generator: ComplianceReportGenerator, audit_trail: AuditTrail
    ) -> None:
        """compliance_status must contain an 'overall' key."""
        _populate_audit_trail(audit_trail)
        report = report_generator.generate_report()
        assert "overall" in report["compliance_status"]


class TestReportContainsNoPhi:
    def test_report_contains_no_phi(
        self,
        report_generator: ComplianceReportGenerator,
        audit_trail: AuditTrail,
    ) -> None:
        """The serialised report must not contain any of the PHI strings from audit events.

        AuditTrail is designed to never store original PHI, so the report should
        be free of PHI by design.  This test acts as a regression guard.
        """
        phi_strings = [
            "John Smith",
            "456-78-9012",
            "john.smith@email.com",
            "(555) 123-4567",
        ]

        _populate_audit_trail(audit_trail)
        report = report_generator.generate_report()
        report_json = json.dumps(report)

        for phi in phi_strings:
            assert phi not in report_json, (
                f"PHI value '{phi}' found in the compliance report"
            )

    def test_report_does_not_contain_original_text(
        self,
        report_generator: ComplianceReportGenerator,
        audit_trail: AuditTrail,
    ) -> None:
        """Even text_length is an integer; the original text itself must never appear."""
        session_id = str(uuid.uuid4())
        sensitive_text = "SENSITIVE_PHI_MARKER_DO_NOT_LOG"

        # Log an event — the AuditTrail only records length, category, etc.
        audit_trail.log_event(
            session_id=session_id,
            request_id=str(uuid.uuid4()),
            category="PERSON_NAME",
            confidence=0.9,
            action="redacted",
            detection_method="regex",
            text_length=len(sensitive_text),  # Only length, not text.
        )

        report = report_generator.generate_report()
        report_json = json.dumps(report)

        assert sensitive_text not in report_json


class TestIntegrityVerification:
    def test_integrity_verification_passes(
        self,
        report_generator: ComplianceReportGenerator,
        audit_trail: AuditTrail,
    ) -> None:
        """After logging events normally, integrity_verification.hash_chain_valid must be True."""
        _populate_audit_trail(audit_trail, n=10)
        report = report_generator.generate_report()

        integrity = report["integrity_verification"]
        assert integrity["hash_chain_valid"] is True
        assert integrity["status"] == "passed"

    def test_integrity_verification_directly(self, audit_trail: AuditTrail) -> None:
        """AuditTrail.verify_integrity() must return True for a fresh, unmodified trail."""
        _populate_audit_trail(audit_trail, n=3)
        assert audit_trail.verify_integrity() is True


class TestEmptyReportNoData:
    def test_empty_report_no_data(
        self, report_generator: ComplianceReportGenerator
    ) -> None:
        """An empty audit trail must produce a report where compliance_status.overall is 'no_data'."""
        report = report_generator.generate_report()

        compliance = report["compliance_status"]
        assert compliance["overall"] == "no_data", (
            f"Expected 'no_data' compliance status for empty audit trail, "
            f"got '{compliance['overall']}'"
        )

    def test_empty_report_summary_zeros(
        self, report_generator: ComplianceReportGenerator
    ) -> None:
        """Summary for an empty audit trail should report zero events and sessions."""
        report = report_generator.generate_report()
        summary = report["summary"]

        assert summary["total_redaction_events"] == 0
        assert summary["unique_sessions"] == 0
        assert summary["phi_entities_detected"] == 0

    def test_empty_report_category_coverage_not_observed(
        self, report_generator: ComplianceReportGenerator
    ) -> None:
        """With no events, every HIPAA category in category_coverage should be 'not_observed'."""
        report = report_generator.generate_report()
        coverage = report["category_coverage"]["categories"]

        for cat_name, cat_data in coverage.items():
            assert cat_data["status"] == "not_observed", (
                f"Category '{cat_name}' has unexpected status '{cat_data['status']}' "
                "when no events have been logged"
            )

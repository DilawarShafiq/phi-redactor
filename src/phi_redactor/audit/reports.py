"""HIPAA Safe Harbor compliance report generator.

Produces structured evidence reports that demonstrate de-identification
compliance with the HIPAA Safe Harbor method (45 CFR 164.514(b)(2)).
Reports can be used for:

- Internal compliance audits
- External regulatory reviews
- Breach risk assessments
- Continuous monitoring dashboards
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phi_redactor.audit.trail import AuditTrail
from phi_redactor.models import AuditEvent, PHICategory

# All 18 HIPAA Safe Harbor identifier categories
_SAFE_HARBOR_CATEGORIES = [cat.value for cat in PHICategory]


class ComplianceReportGenerator:
    """Generates HIPAA Safe Harbor compliance evidence reports.

    Parameters
    ----------
    audit_trail:
        The :class:`AuditTrail` instance to query for redaction events.
    """

    def __init__(self, audit_trail: AuditTrail) -> None:
        self._audit = audit_trail

    def generate_report(
        self,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate a full compliance report.

        Args:
            from_dt: Inclusive start of the reporting period (UTC).
            to_dt: Inclusive end of the reporting period (UTC).
            session_id: Optional filter to a specific session.

        Returns:
            A structured dict containing the full compliance report.
        """
        now = datetime.now(timezone.utc)
        events = self._audit.query(
            session_id=session_id,
            from_dt=from_dt,
            to_dt=to_dt,
            limit=100_000,
        )

        return {
            "report_metadata": {
                "title": "HIPAA Safe Harbor De-identification Compliance Report",
                "generated_at": now.isoformat(),
                "reporting_period": {
                    "from": from_dt.isoformat() if from_dt else "inception",
                    "to": to_dt.isoformat() if to_dt else now.isoformat(),
                },
                "session_filter": session_id,
                "standard": "45 CFR 164.514(b)(2) - Safe Harbor Method",
            },
            "summary": self._build_summary(events),
            "category_coverage": self._build_category_coverage(events),
            "confidence_analysis": self._build_confidence_analysis(events),
            "detection_methods": self._build_detection_methods(events),
            "integrity_verification": self._verify_integrity(),
            "compliance_status": self._assess_compliance(events),
        }

    def generate_summary(
        self,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> dict[str, Any]:
        """Generate a lightweight summary report.

        Suitable for dashboards and quick status checks.
        """
        events = self._audit.query(from_dt=from_dt, to_dt=to_dt, limit=100_000)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **self._build_summary(events),
            "compliance_status": self._assess_compliance(events),
        }

    def export_report(
        self,
        output_path: str | Path,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        session_id: str | None = None,
    ) -> Path:
        """Generate and write the full report as a JSON file.

        Returns the path to the written file.
        """
        report = self.generate_report(
            from_dt=from_dt, to_dt=to_dt, session_id=session_id,
        )
        path = Path(output_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Report sections
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(events: list[AuditEvent]) -> dict[str, Any]:
        """High-level statistics."""
        if not events:
            return {
                "total_redaction_events": 0,
                "unique_sessions": 0,
                "unique_requests": 0,
                "phi_entities_detected": 0,
                "categories_detected": 0,
            }

        sessions = {e.session_id for e in events}
        requests = {e.request_id for e in events}
        categories = {e.phi_category.value for e in events}

        return {
            "total_redaction_events": len(events),
            "unique_sessions": len(sessions),
            "unique_requests": len(requests),
            "phi_entities_detected": len(events),
            "categories_detected": len(categories),
        }

    def _build_category_coverage(self, events: list[AuditEvent]) -> dict[str, Any]:
        """Show which of the 18 HIPAA categories were detected and redacted."""
        detected = Counter(e.phi_category.value for e in events)

        coverage = {}
        for cat in _SAFE_HARBOR_CATEGORIES:
            count = detected.get(cat, 0)
            coverage[cat] = {
                "detected_count": count,
                "status": "covered" if count > 0 else "not_observed",
            }

        covered_count = sum(1 for c in coverage.values() if c["status"] == "covered")

        return {
            "total_categories": len(_SAFE_HARBOR_CATEGORIES),
            "categories_covered": covered_count,
            "coverage_percentage": round(covered_count / len(_SAFE_HARBOR_CATEGORIES) * 100, 1),
            "categories": coverage,
        }

    @staticmethod
    def _build_confidence_analysis(events: list[AuditEvent]) -> dict[str, Any]:
        """Analyze detection confidence distribution."""
        if not events:
            return {
                "average_confidence": 0.0,
                "min_confidence": 0.0,
                "max_confidence": 0.0,
                "distribution": {},
            }

        confidences = [e.confidence for e in events]
        avg = sum(confidences) / len(confidences)

        # Bucket into ranges
        buckets = {"0.0-0.5": 0, "0.5-0.7": 0, "0.7-0.9": 0, "0.9-1.0": 0}
        for c in confidences:
            if c < 0.5:
                buckets["0.0-0.5"] += 1
            elif c < 0.7:
                buckets["0.5-0.7"] += 1
            elif c < 0.9:
                buckets["0.7-0.9"] += 1
            else:
                buckets["0.9-1.0"] += 1

        return {
            "average_confidence": round(avg, 4),
            "min_confidence": round(min(confidences), 4),
            "max_confidence": round(max(confidences), 4),
            "distribution": buckets,
        }

    @staticmethod
    def _build_detection_methods(events: list[AuditEvent]) -> dict[str, int]:
        """Count events by detection method."""
        return dict(Counter(e.detection_method.value for e in events))

    def _verify_integrity(self) -> dict[str, Any]:
        """Verify audit trail hash-chain integrity."""
        is_valid = self._audit.verify_integrity()
        return {
            "hash_chain_valid": is_valid,
            "status": "passed" if is_valid else "FAILED",
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def generate_safe_harbor(
        self,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate full Safe Harbor attestation document."""
        report = self.generate_report(from_dt=from_dt, to_dt=to_dt, session_id=session_id)
        report["attestation"] = {
            "method": "Safe Harbor",
            "standard": "45 CFR 164.514(b)(2)",
            "statement": (
                "This report attests that the PHI redaction system employs the "
                "HIPAA Safe Harbor method for de-identification. All 18 categories "
                "of identifiers specified in 45 CFR 164.514(b)(2) are addressed "
                "by the detection and masking pipeline."
            ),
            "methodology": (
                "Detection uses a combination of pattern-based regular expressions "
                "and named-entity recognition (NER) via spaCy and Microsoft Presidio. "
                "Masking replaces detected PHI with clinically coherent synthetic values "
                "generated by Faker with healthcare-specific providers. All mappings are "
                "encrypted at rest using Fernet (AES-128-CBC) and tracked in a tamper-evident "
                "hash-chain audit trail."
            ),
        }
        return report

    @staticmethod
    def _assess_compliance(events: list[AuditEvent]) -> dict[str, Any]:
        """Assess overall compliance status based on evidence."""
        if not events:
            return {
                "overall": "no_data",
                "message": "No redaction events found in the reporting period.",
                "checks": {},
            }

        checks: dict[str, dict[str, Any]] = {}

        # Check 1: All detections were redacted
        redacted = sum(1 for e in events if e.action.value == "redacted")
        checks["all_detections_redacted"] = {
            "passed": redacted == len(events),
            "detail": f"{redacted}/{len(events)} detections were redacted",
        }

        # Check 2: Confidence threshold
        low_confidence = sum(1 for e in events if e.confidence < 0.3)
        checks["confidence_threshold"] = {
            "passed": low_confidence == 0,
            "detail": f"{low_confidence} detections below 0.3 confidence threshold",
        }

        # Check 3: Multiple detection methods used
        methods = {e.detection_method.value for e in events}
        checks["multiple_detection_methods"] = {
            "passed": len(methods) >= 2,
            "detail": f"Used {len(methods)} detection method(s): {', '.join(sorted(methods))}",
        }

        # Check 4: Multiple PHI categories handled
        categories = {e.phi_category.value for e in events}
        checks["multi_category_coverage"] = {
            "passed": len(categories) >= 3,
            "detail": f"Covered {len(categories)} PHI categories",
        }

        all_passed = all(c["passed"] for c in checks.values())

        return {
            "overall": "compliant" if all_passed else "review_needed",
            "message": (
                "All compliance checks passed."
                if all_passed
                else "Some checks require review. See details."
            ),
            "checks": checks,
        }


# ---------------------------------------------------------------------------
# Report rendering helpers (module-level)
# ---------------------------------------------------------------------------


def render_markdown(report: dict) -> str:
    """Render a compliance report as Markdown."""
    lines = []
    meta = report.get("report_metadata", {})
    lines.append(f"# {meta.get('title', 'Compliance Report')}")
    lines.append(f"\n**Generated:** {meta.get('generated_at', 'N/A')}")
    lines.append(f"**Standard:** {meta.get('standard', 'N/A')}")
    lines.append(
        f"**Period:** "
        f"{report.get('report_metadata', {}).get('reporting_period', {}).get('from', 'N/A')}"
        f" to "
        f"{report.get('report_metadata', {}).get('reporting_period', {}).get('to', 'N/A')}"
    )

    # Summary
    summary = report.get("summary", {})
    lines.append("\n## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for key, val in summary.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {val} |")

    # Category coverage
    coverage = report.get("category_coverage", {})
    if coverage:
        lines.append(f"\n## Category Coverage ({coverage.get('coverage_percentage', 0)}%)\n")
        lines.append("| Category | Count | Status |")
        lines.append("|----------|-------|--------|")
        for cat, info in coverage.get("categories", {}).items():
            lines.append(f"| {cat} | {info['detected_count']} | {info['status']} |")

    # Confidence
    confidence = report.get("confidence_analysis", {})
    if confidence:
        lines.append("\n## Confidence Analysis\n")
        lines.append(f"- Average: {confidence.get('average_confidence', 0)}")
        lines.append(f"- Min: {confidence.get('min_confidence', 0)}")
        lines.append(f"- Max: {confidence.get('max_confidence', 0)}")

    # Compliance status
    status = report.get("compliance_status", {})
    lines.append(f"\n## Compliance Status: {status.get('overall', 'unknown').upper()}\n")
    lines.append(f"{status.get('message', '')}\n")
    for name, check in status.get("checks", {}).items():
        icon = "PASS" if check["passed"] else "FAIL"
        lines.append(f"- [{icon}] **{name}**: {check['detail']}")

    # Integrity
    integrity = report.get("integrity_verification", {})
    if integrity:
        lines.append(f"\n## Audit Trail Integrity: {integrity.get('status', 'unknown')}\n")

    # Attestation
    attestation = report.get("attestation", {})
    if attestation:
        lines.append("\n## Attestation\n")
        lines.append(f"**Method:** {attestation.get('method', 'N/A')}")
        lines.append(f"**Standard:** {attestation.get('standard', 'N/A')}")
        lines.append(f"\n{attestation.get('statement', '')}")
        lines.append(f"\n### Methodology\n\n{attestation.get('methodology', '')}")

    return "\n".join(lines)


def render_html(report: dict) -> str:
    """Render a compliance report as standalone HTML."""
    md_content = render_markdown(report)
    # Convert basic markdown to HTML
    html_lines = []
    for line in md_content.split("\n"):
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("| ") and "---|" not in line:
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if html_lines and "<thead>" not in "".join(html_lines[-5:]):
                html_lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            else:
                html_lines.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
        elif line.startswith("|") and "---" in line:
            html_lines.append("")  # skip separator
        elif line.startswith("- ["):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.startswith("**"):
            html_lines.append(f"<p><strong>{line.strip('*')}</strong></p>")
        elif line.strip():
            html_lines.append(f"<p>{line}</p>")

    body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HIPAA Compliance Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; color: #333; }}
h1 {{ color: #1a365d; border-bottom: 2px solid #2b6cb0; padding-bottom: 0.5rem; }}
h2 {{ color: #2b6cb0; margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #e2e8f0; padding: 0.5rem 1rem; text-align: left; }}
th {{ background: #edf2f7; font-weight: 600; }}
tr:nth-child(even) {{ background: #f7fafc; }}
li {{ margin: 0.3rem 0; }}
.pass {{ color: #276749; }} .fail {{ color: #c53030; }}
@media print {{ body {{ max-width: 100%; }} }}
</style>
</head>
<body>
{body}
<footer><p style="color:#718096;font-size:0.85rem;margin-top:3rem;border-top:1px solid #e2e8f0;padding-top:1rem;">Generated by phi-redactor Compliance Report Engine</p></footer>
</body>
</html>"""

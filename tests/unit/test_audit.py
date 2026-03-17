"""Unit tests for the audit trail: logging, hash-chain, integrity, and queries.

Covers tasks T024-T026 acceptance criteria:
1. Event logging creates JSONL file with correct fields.
2. Hash chain: log 3 events, verify each entry_hash links to previous.
3. Integrity verification passes on a valid trail.
4. Integrity verification fails when an entry is tampered.
5. Query filtering by session_id and category.
6. Audit trail NEVER contains PHI text.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phi_redactor.audit.trail import _GENESIS_HASH, AuditTrail
from phi_redactor.models import (
    DetectionMethod,
    PHICategory,
    RedactionAction,
)

# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------


@pytest.fixture
def trail(audit_path: Path) -> AuditTrail:
    """AuditTrail instance backed by a temp directory."""
    return AuditTrail(audit_dir=audit_path)


def _log_sample_event(
    trail: AuditTrail,
    *,
    session_id: str = "sess-001",
    request_id: str = "req-001",
    category: str = "PERSON_NAME",
    confidence: float = 0.95,
    action: str = "redacted",
    detection_method: str = "regex",
    text_length: int = 10,
) -> AuditEvent:  # noqa: F821
    """Helper to log a single sample event."""
    return trail.log_event(
        session_id=session_id,
        request_id=request_id,
        category=category,
        confidence=confidence,
        action=action,
        detection_method=detection_method,
        text_length=text_length,
    )


# -----------------------------------------------------------------------
# T025/T026-1 – Event logging creates JSONL with correct fields
# -----------------------------------------------------------------------


class TestEventLogging:
    """Tests for basic event logging (T025)."""

    def test_log_creates_jsonl_file(self, trail: AuditTrail, audit_path: Path) -> None:
        """Logging an event must create a .jsonl file in the audit directory."""
        _log_sample_event(trail)
        jsonl_files = list(audit_path.glob("*.jsonl"))
        assert len(jsonl_files) == 1

    def test_log_event_fields(self, trail: AuditTrail, audit_path: Path) -> None:
        """Logged event must contain all required fields with correct values."""
        event = _log_sample_event(
            trail,
            session_id="sess-abc",
            request_id="req-xyz",
            category="SSN",
            confidence=0.99,
            action="redacted",
            detection_method="regex",
            text_length=11,
        )

        assert event.session_id == "sess-abc"
        assert event.request_id == "req-xyz"
        assert event.phi_category == PHICategory.SSN
        assert event.confidence == 0.99
        assert event.action == RedactionAction.REDACTED
        assert event.detection_method == DetectionMethod.REGEX
        assert event.text_length == 11
        assert event.entry_hash
        assert event.previous_hash == _GENESIS_HASH

        # Verify on-disk JSON record matches.
        jsonl_file = next(audit_path.glob("*.jsonl"))
        record = json.loads(jsonl_file.read_text(encoding="utf-8").strip())
        assert record["session_id"] == "sess-abc"
        assert record["phi_category"] == "SSN"
        assert record["confidence"] == 0.99

    def test_event_id_increments(self, trail: AuditTrail) -> None:
        """Event IDs must auto-increment."""
        e1 = _log_sample_event(trail)
        e2 = _log_sample_event(trail)
        e3 = _log_sample_event(trail)
        assert e1.id == 1
        assert e2.id == 2
        assert e3.id == 3


# -----------------------------------------------------------------------
# T026-2 – Hash chain integrity
# -----------------------------------------------------------------------


class TestHashChain:
    """Tests for the SHA-256 hash chain (T025/T026)."""

    def test_hash_chain_links(self, trail: AuditTrail) -> None:
        """Each entry's previous_hash must equal the prior entry's entry_hash."""
        e1 = _log_sample_event(trail, session_id="s1")
        e2 = _log_sample_event(trail, session_id="s1")
        e3 = _log_sample_event(trail, session_id="s1")

        assert e1.previous_hash == _GENESIS_HASH
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash

    def test_entry_hashes_are_unique(self, trail: AuditTrail) -> None:
        """Even identical payloads should produce different hashes (timestamps differ)."""
        e1 = _log_sample_event(trail)
        e2 = _log_sample_event(trail)
        assert e1.entry_hash != e2.entry_hash


# -----------------------------------------------------------------------
# T026-3 – Integrity verification passes on valid trail
# -----------------------------------------------------------------------


class TestVerifyIntegrity:
    """Tests for verify_integrity (T025/T026)."""

    def test_valid_trail_passes(self, trail: AuditTrail) -> None:
        """A non-tampered trail must pass integrity verification."""
        for i in range(5):
            _log_sample_event(trail, session_id=f"s-{i}")

        assert trail.verify_integrity() is True

    def test_empty_trail_passes(self, trail: AuditTrail) -> None:
        """An empty trail is trivially valid."""
        assert trail.verify_integrity() is True

    def test_tampered_entry_fails(self, trail: AuditTrail, audit_path: Path) -> None:
        """Modifying a field in a logged entry must cause verification failure."""
        _log_sample_event(trail, session_id="s1", confidence=0.9)
        _log_sample_event(trail, session_id="s2", confidence=0.8)
        _log_sample_event(trail, session_id="s3", confidence=0.7)

        # Tamper with the second entry.
        jsonl_file = next(audit_path.glob("*.jsonl"))
        lines = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[1])
        record["confidence"] = 0.01  # Tamper!
        lines[1] = json.dumps(record, separators=(",", ":"))
        jsonl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Re-create trail from disk to verify.
        fresh_trail = AuditTrail(audit_dir=audit_path)
        assert fresh_trail.verify_integrity() is False

    def test_tampered_hash_field_fails(self, trail: AuditTrail, audit_path: Path) -> None:
        """Directly editing entry_hash must cause verification failure."""
        _log_sample_event(trail)
        _log_sample_event(trail)

        jsonl_file = next(audit_path.glob("*.jsonl"))
        lines = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[0])
        record["entry_hash"] = "0" * 64  # Tamper the hash itself.
        lines[0] = json.dumps(record, separators=(",", ":"))
        jsonl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        fresh_trail = AuditTrail(audit_dir=audit_path)
        assert fresh_trail.verify_integrity() is False


# -----------------------------------------------------------------------
# T026-5 – Query filtering
# -----------------------------------------------------------------------


class TestQueryFiltering:
    """Tests for the query method (T025)."""

    def test_filter_by_session_id(self, trail: AuditTrail) -> None:
        """Query must filter by session_id."""
        _log_sample_event(trail, session_id="alpha")
        _log_sample_event(trail, session_id="beta")
        _log_sample_event(trail, session_id="alpha")

        results = trail.query(session_id="alpha")
        assert len(results) == 2
        assert all(e.session_id == "alpha" for e in results)

    def test_filter_by_category(self, trail: AuditTrail) -> None:
        """Query must filter by PHI category."""
        _log_sample_event(trail, category="PERSON_NAME")
        _log_sample_event(trail, category="SSN")
        _log_sample_event(trail, category="PERSON_NAME")

        results = trail.query(category="SSN")
        assert len(results) == 1
        assert results[0].phi_category == PHICategory.SSN

    def test_filter_combined(self, trail: AuditTrail) -> None:
        """Session + category filters must compose."""
        _log_sample_event(trail, session_id="s1", category="PERSON_NAME")
        _log_sample_event(trail, session_id="s1", category="SSN")
        _log_sample_event(trail, session_id="s2", category="PERSON_NAME")

        results = trail.query(session_id="s1", category="SSN")
        assert len(results) == 1
        assert results[0].session_id == "s1"
        assert results[0].phi_category == PHICategory.SSN

    def test_limit_and_offset(self, trail: AuditTrail) -> None:
        """Limit and offset must paginate results."""
        for i in range(10):
            _log_sample_event(trail, session_id=f"s-{i}")

        page = trail.query(limit=3, offset=2)
        assert len(page) == 3
        assert page[0].id == 3  # 0-indexed offset of 2 -> 3rd event


# -----------------------------------------------------------------------
# T026-6 – Audit trail never contains PHI text
# -----------------------------------------------------------------------


class TestNoPHIInAudit:
    """Verify that no original PHI text leaks into the audit trail (T026)."""

    def test_no_phi_in_jsonl(self, trail: AuditTrail, audit_path: Path) -> None:
        """JSONL files must not contain any original PHI strings."""
        phi_strings = [
            "John Smith",
            "123-45-6789",
            "john.smith@email.com",
            "(555) 123-4567",
            "742 Evergreen Terrace",
        ]

        # Log events using only category / metadata -- never PHI text.
        for phi in phi_strings:
            _log_sample_event(trail, text_length=len(phi))

        # Read raw file contents.
        for jsonl_file in audit_path.glob("*.jsonl"):
            raw = jsonl_file.read_text(encoding="utf-8")
            for phi in phi_strings:
                assert phi not in raw, f"PHI string '{phi}' found in audit file {jsonl_file.name}"

    def test_event_model_has_no_text_field(self, trail: AuditTrail) -> None:
        """AuditEvent must not expose any field that could hold PHI text."""
        event = _log_sample_event(trail)
        field_names = set(event.model_fields.keys())
        # These fields must NOT exist.
        forbidden = {"original_text", "phi_text", "redacted_text", "raw_text", "text"}
        assert field_names.isdisjoint(forbidden), (
            f"AuditEvent contains forbidden fields: {field_names & forbidden}"
        )

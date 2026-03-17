"""Append-only hash-chain audit log for PHI redaction events.

Events are stored as JSON Lines (``.jsonl``) files, one per calendar day,
inside the configured audit directory.  Every entry includes a SHA-256
``entry_hash`` that chains to the previous entry's hash, making any
post-hoc modification detectable.

**Security invariant**: this module NEVER logs original PHI text.  Only
category, confidence, detection method, and text length are recorded.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phi_redactor.models import (
    AuditEvent,
    DetectionMethod,
    PHICategory,
    RedactionAction,
)

_GENESIS_HASH = "0" * 64  # SHA-256 zero hash for the first entry in the chain.


class AuditTrail:
    """Append-only hash-chain audit log for PHI redaction events.

    Parameters
    ----------
    audit_dir:
        Directory where daily ``.jsonl`` files are written.
        Defaults to ``~/.phi-redactor/audit/``.
    """

    def __init__(self, audit_dir: str | Path = "~/.phi-redactor/audit/") -> None:
        self._audit_dir = Path(audit_dir).expanduser()
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._previous_hash: str = self._recover_last_hash()
        self._event_counter: int = self._recover_last_id()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_event(
        self,
        session_id: str,
        request_id: str,
        category: str,
        confidence: float,
        action: str,
        detection_method: str,
        text_length: int,
    ) -> AuditEvent:
        """Append a new redaction event to today's audit file.

        Returns the fully-populated :class:`AuditEvent`.
        """
        self._event_counter += 1
        timestamp = datetime.now(UTC)

        entry_hash = self._compute_hash(
            timestamp=timestamp,
            session_id=session_id,
            category=category,
            confidence=confidence,
            action=action,
            previous_hash=self._previous_hash,
        )

        event = AuditEvent(
            id=self._event_counter,
            session_id=session_id,
            timestamp=timestamp,
            request_id=request_id,
            phi_category=PHICategory(category),
            confidence=confidence,
            action=RedactionAction(action),
            detection_method=DetectionMethod(detection_method),
            text_length=text_length,
            entry_hash=entry_hash,
            previous_hash=self._previous_hash,
        )

        self._append_event(event)
        self._previous_hash = entry_hash
        return event

    def query(
        self,
        session_id: str | None = None,
        category: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Query audit events with optional filters.

        Parameters
        ----------
        session_id:
            Filter by session UUID.
        category:
            Filter by PHI category name (e.g. ``"PERSON_NAME"``).
        from_dt:
            Inclusive lower bound on event timestamp.
        to_dt:
            Inclusive upper bound on event timestamp.
        limit:
            Maximum number of events to return.
        offset:
            Number of matching events to skip before returning.
        """
        events: list[AuditEvent] = []

        for jsonl_path in sorted(self._audit_dir.glob("*.jsonl")):
            # Coarse date-range pruning based on filename.
            file_date_str = jsonl_path.stem  # e.g. "2026-02-26"
            if from_dt is not None or to_dt is not None:
                try:
                    file_date = datetime.strptime(file_date_str, "%Y-%m-%d").replace(
                        tzinfo=UTC,
                    )
                except ValueError:
                    continue
                if from_dt is not None and file_date.date() > (
                    to_dt.date() if to_dt else file_date.date()
                ):
                    continue
                if to_dt is not None and file_date.date() < (
                    from_dt.date() if from_dt else file_date.date()
                ):
                    continue

            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                event = self._dict_to_event(data)

                if session_id is not None and event.session_id != session_id:
                    continue
                if category is not None and event.phi_category.value != category:
                    continue
                if from_dt is not None and event.timestamp < from_dt:
                    continue
                if to_dt is not None and event.timestamp > to_dt:
                    continue

                events.append(event)

        # Apply offset and limit.
        return events[offset : offset + limit]

    def verify_integrity(self) -> bool:
        """Re-compute the hash chain and verify every entry matches.

        Returns *True* if the entire chain is valid, *False* on the first
        mismatch.
        """
        previous_hash = _GENESIS_HASH

        for jsonl_path in sorted(self._audit_dir.glob("*.jsonl")):
            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)

                if data.get("previous_hash") != previous_hash:
                    return False

                expected_hash = self._compute_hash(
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    session_id=data["session_id"],
                    category=data["phi_category"],
                    confidence=data["confidence"],
                    action=data["action"],
                    previous_hash=previous_hash,
                )

                if data.get("entry_hash") != expected_hash:
                    return False

                previous_hash = data["entry_hash"]

        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hash(
        *,
        timestamp: datetime,
        session_id: str,
        category: str,
        confidence: float,
        action: str,
        previous_hash: str,
    ) -> str:
        """SHA-256 hash of the canonical fields for chain integrity."""
        payload = (
            f"{timestamp.isoformat()}|{session_id}|{category}|{confidence}|{action}|{previous_hash}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _append_event(self, event: AuditEvent) -> None:
        """Serialize *event* to JSON and append to today's ``.jsonl`` file."""
        today_str = event.timestamp.strftime("%Y-%m-%d")
        path = self._audit_dir / f"{today_str}.jsonl"
        record = {
            "id": event.id,
            "session_id": event.session_id,
            "timestamp": event.timestamp.isoformat(),
            "request_id": event.request_id,
            "phi_category": event.phi_category.value,
            "confidence": event.confidence,
            "action": event.action.value,
            "detection_method": event.detection_method.value,
            "text_length": event.text_length,
            "entry_hash": event.entry_hash,
            "previous_hash": event.previous_hash,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def _recover_last_hash(self) -> str:
        """Read the last ``entry_hash`` from existing files, or genesis."""
        files = sorted(self._audit_dir.glob("*.jsonl"))
        if not files:
            return _GENESIS_HASH
        last_file = files[-1]
        lines = last_file.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return _GENESIS_HASH
        data = json.loads(lines[-1])
        return data.get("entry_hash", _GENESIS_HASH)

    def _recover_last_id(self) -> int:
        """Read the last ``id`` from existing files, or 0."""
        files = sorted(self._audit_dir.glob("*.jsonl"))
        if not files:
            return 0
        last_file = files[-1]
        lines = last_file.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return 0
        data = json.loads(lines[-1])
        return int(data.get("id", 0))

    @staticmethod
    def _dict_to_event(data: dict[str, Any]) -> AuditEvent:
        """Deserialize a JSON dict to an :class:`AuditEvent`."""
        return AuditEvent(
            id=data["id"],
            session_id=data["session_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            request_id=data["request_id"],
            phi_category=PHICategory(data["phi_category"]),
            confidence=data["confidence"],
            action=RedactionAction(data["action"]),
            detection_method=DetectionMethod(data["detection_method"]),
            text_length=data["text_length"],
            entry_hash=data["entry_hash"],
            previous_hash=data["previous_hash"],
        )

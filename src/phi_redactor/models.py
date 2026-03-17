"""Domain models for PHI detection, redaction, auditing, and session management.

All 18 HIPAA Safe Harbor identifier categories are represented as a StrEnum,
along with supporting enums for detection methods, redaction actions, and
session lifecycle states.  Pydantic ``BaseModel`` subclasses enforce runtime
validation and serialization guarantees.

**Security invariant**: ``PHIDetection.original_text`` must NEVER appear in
logs, error messages, or any output channel.  Consumers are responsible for
clearing this field before any external exposure.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PHICategory(str, enum.Enum):
    """HIPAA Safe Harbor de-identification: all 18 identifier categories.

    Each member maps to one of the 18 categories defined in 45 CFR 164.514(b)(2).
    """

    PERSON_NAME = "PERSON_NAME"
    """Names."""

    GEOGRAPHIC_DATA = "GEOGRAPHIC_DATA"
    """Geographic subdivisions smaller than a state."""

    DATE = "DATE"
    """All elements of dates (except year) directly related to an individual."""

    PHONE_NUMBER = "PHONE_NUMBER"
    """Telephone numbers."""

    FAX_NUMBER = "FAX_NUMBER"
    """Fax numbers."""

    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    """Electronic mail addresses."""

    SSN = "SSN"
    """Social Security numbers."""

    MRN = "MRN"
    """Medical record numbers."""

    HEALTH_PLAN_ID = "HEALTH_PLAN_ID"
    """Health plan beneficiary numbers."""

    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    """Account numbers."""

    LICENSE_NUMBER = "LICENSE_NUMBER"
    """Certificate / license numbers (including DEA, NPI, state licenses)."""

    VEHICLE_ID = "VEHICLE_ID"
    """Vehicle identifiers and serial numbers including license plate numbers."""

    DEVICE_ID = "DEVICE_ID"
    """Device identifiers and serial numbers."""

    WEB_URL = "WEB_URL"
    """Web Universal Resource Locators (URLs)."""

    IP_ADDRESS = "IP_ADDRESS"
    """Internet Protocol (IP) address numbers."""

    BIOMETRIC_ID = "BIOMETRIC_ID"
    """Biometric identifiers, including finger and voice prints."""

    PHOTO = "PHOTO"
    """Full face photographic images and any comparable images."""

    OTHER_UNIQUE_ID = "OTHER_UNIQUE_ID"
    """Any other unique identifying number, characteristic, or code."""


class DetectionMethod(str, enum.Enum):
    """How a PHI entity was detected."""

    REGEX = "regex"
    """Pattern-based regular expression matching."""

    NER = "ner"
    """Named-entity recognition (e.g., spaCy / Presidio NER pipeline)."""

    SCHEMA = "schema"
    """Schema-aware detection (e.g., FHIR resource field mapping, HL7v2 segments)."""

    PLUGIN = "plugin"
    """Custom plugin-provided recognizer."""


class RedactionAction(str, enum.Enum):
    """Action taken on a detected PHI entity."""

    REDACTED = "redacted"
    """Entity replaced with a synthetic / masked value."""

    FLAGGED = "flagged"
    """Entity left in place but flagged for human review."""

    PASSED = "passed"
    """Entity intentionally allowed through (e.g., below sensitivity threshold)."""

    BLOCKED = "blocked"
    """Entire request blocked due to policy violation."""


class SessionStatus(str, enum.Enum):
    """Lifecycle state of a proxy session."""

    ACTIVE = "active"
    """Session is open and accepting requests."""

    EXPIRED = "expired"
    """Session timed out (idle or max lifetime exceeded)."""

    CLOSED = "closed"
    """Session was explicitly closed by the user or API."""


# ---------------------------------------------------------------------------
# Detection & Redaction Models
# ---------------------------------------------------------------------------


class PHIDetection(BaseModel):
    """A single detected PHI entity within source text.

    Attributes:
        category: The HIPAA Safe Harbor category of the detected entity.
        start: Character offset (inclusive) where the entity begins.
        end: Character offset (exclusive) where the entity ends.
        confidence: Detection confidence score in ``[0.0, 1.0]``.
        method: The detection technique that found this entity.
        recognizer_name: Identifier of the recognizer that produced the detection.
        original_text: The raw PHI value.  **Must NEVER be logged or serialized
            to any external output.**  Default is empty string for safety.
    """

    category: PHICategory
    start: int = Field(ge=0, description="Start character offset (inclusive)")
    end: int = Field(ge=0, description="End character offset (exclusive)")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Detection confidence score between 0.0 and 1.0",
    )
    method: DetectionMethod
    recognizer_name: str = Field(
        min_length=1,
        description="Name of the recognizer that produced this detection",
    )
    original_text: str = Field(
        default="",
        description=(
            "Raw PHI value. SECURITY: must never be logged or included in error messages."
        ),
    )

    model_config = {"frozen": True}


class RedactionResult(BaseModel):
    """Result of running PHI detection and masking on a text input.

    Attributes:
        redacted_text: The text with all detected PHI replaced by synthetic tokens.
        detections: Ordered list of PHI detections found in the original text.
        session_id: UUID of the session under which this redaction was performed.
        processing_time_ms: Wall-clock time spent on detection + masking (ms).
    """

    redacted_text: str
    detections: list[PHIDetection] = Field(default_factory=list)
    session_id: str = Field(
        min_length=1,
        description="Session UUID that owns the vault mappings for this result",
    )
    processing_time_ms: float = Field(
        ge=0.0,
        description="Total processing time in milliseconds",
    )


# ---------------------------------------------------------------------------
# Audit Model
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """Tamper-evident audit log entry for a single redaction action.

    The ``entry_hash`` and ``previous_hash`` fields form a hash-chain that
    makes any post-hoc modification detectable.

    **Security invariant**: This model NEVER contains original PHI text --
    only category, confidence, and metadata.
    """

    id: int = Field(description="Auto-incrementing event ID")
    session_id: str = Field(description="Parent session UUID")
    timestamp: datetime = Field(description="UTC timestamp of the redaction event")
    request_id: str = Field(description="UUID grouping events from a single proxy request")
    phi_category: PHICategory
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Detection confidence at the time of the action",
    )
    action: RedactionAction
    detection_method: DetectionMethod
    text_length: int = Field(
        ge=0,
        description="Length of the original PHI text (for statistics, NOT the text itself)",
    )
    entry_hash: str = Field(
        min_length=1,
        description="SHA-256 hash of this entry's data fields",
    )
    previous_hash: str = Field(
        description="SHA-256 hash of the preceding entry (hash-chain link)",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Session Model
# ---------------------------------------------------------------------------


class SessionInfo(BaseModel):
    """Metadata for an active or historical proxy session.

    Attributes:
        id: Unique session identifier (UUID).
        created_at: When the session was created (UTC).
        last_active_at: Timestamp of the most recent request (UTC).
        expires_at: Hard expiration based on ``created_at + max_lifetime``.
        provider: The LLM provider associated with this session.
        status: Current lifecycle state of the session.
        date_shift_offset_days: Consistent random date shift applied to all
            date-type PHI within this session.
        age_shift_offset_years: Consistent random age shift applied to all
            age values within this session.
    """

    id: str = Field(min_length=1, description="Session UUID")
    created_at: datetime = Field(description="Session creation timestamp (UTC)")
    last_active_at: datetime = Field(description="Most recent request timestamp (UTC)")
    expires_at: datetime = Field(description="Hard expiration timestamp (UTC)")
    provider: str = Field(min_length=1, description="LLM provider identifier")
    status: SessionStatus = Field(default=SessionStatus.ACTIVE)
    date_shift_offset_days: int = Field(
        description="Random date shift in days (applied consistently within the session)",
    )
    age_shift_offset_years: int = Field(
        description="Random age shift in years (applied consistently within the session)",
    )

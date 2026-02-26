"""Library API routes for direct redaction without LLM proxy.

These endpoints expose the core PHI detection and masking engine as a
standalone API -- callers can redact arbitrary text and rehydrate it
without routing through an upstream LLM provider.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from phi_redactor.models import RedactionAction

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Library"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class RedactRequest(BaseModel):
    """Request body for the ``/redact`` endpoint."""

    text: str = Field(min_length=1, description="Text to scan and redact for PHI.")
    session_id: str | None = Field(
        default=None,
        description="Optional session ID for consistent mappings across calls.",
    )
    sensitivity: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override detection sensitivity (0.0=aggressive, 1.0=permissive).",
    )


class RehydrateRequest(BaseModel):
    """Request body for the ``/rehydrate`` endpoint."""

    text: str = Field(min_length=1, description="Text containing synthetic tokens to reverse.")
    session_id: str = Field(
        min_length=1,
        description="Session ID whose vault mappings should be used for rehydration.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/redact", summary="Detect and redact PHI from text")
async def redact(request: Request, body: RedactRequest) -> JSONResponse:
    """Detect PHI in the submitted text and return a redacted version.

    Returns the masked text, a list of detections (category, confidence,
    offsets), session ID, and processing time.  If detection fails the
    request is blocked (fail-safe).
    """
    state = request.app.state
    engine = state.detection_engine
    masker = state.masker
    audit = state.audit_trail
    session_mgr = state.session_manager
    sensitivity: float = body.sensitivity if body.sensitivity is not None else state.sensitivity

    # Session.
    session = session_mgr.get_or_create(session_id=body.session_id, provider="library")
    session_id = session.id
    request_id = str(uuid.uuid4())

    # Detect.
    start_time = time.monotonic()
    try:
        detections = engine.detect(body.text, sensitivity)
    except Exception:
        logger.exception("PHI detection failed -- blocking request (fail-safe)")
        raise HTTPException(
            status_code=503,
            detail="PHI detection unavailable. Request blocked for safety.",
        )

    # Mask.
    try:
        masked_text, _mapping = masker.mask(body.text, detections, session_id)
    except Exception:
        logger.exception("PHI masking failed -- blocking request (fail-safe)")
        raise HTTPException(
            status_code=503,
            detail="PHI masking unavailable. Request blocked for safety.",
        )

    processing_ms = (time.monotonic() - start_time) * 1000

    # Audit.
    for det in detections:
        try:
            audit.log_event(
                session_id=session_id,
                request_id=request_id,
                category=det.category.value,
                confidence=det.confidence,
                action=RedactionAction.REDACTED.value,
                detection_method=det.method.value,
                text_length=len(det.original_text),
            )
        except Exception:
            logger.exception("Audit logging failed for detection")

    return JSONResponse(
        content={
            "redacted_text": masked_text,
            "session_id": session_id,
            "request_id": request_id,
            "processing_ms": round(processing_ms, 2),
            "detections": [
                {
                    "category": d.category.value,
                    "start": d.start,
                    "end": d.end,
                    "confidence": d.confidence,
                    "method": d.method.value,
                }
                for d in detections
            ],
        }
    )


@router.post("/rehydrate", summary="Reverse synthetic tokens back to original PHI")
async def rehydrate(request: Request, body: RehydrateRequest) -> JSONResponse:
    """Reverse-map synthetic tokens to their original PHI values.

    Requires the session ID that was used during the original redaction.
    """
    state = request.app.state
    masker = state.masker

    try:
        original_text = masker.rehydrate(body.text, body.session_id)
    except Exception:
        logger.exception("Rehydration failed")
        raise HTTPException(
            status_code=500,
            detail="Rehydration failed. Ensure the session ID is valid.",
        )

    return JSONResponse(
        content={
            "text": original_text,
            "session_id": body.session_id,
        }
    )

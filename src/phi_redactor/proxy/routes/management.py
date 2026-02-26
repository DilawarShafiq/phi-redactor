"""Management API routes.

Provides health checks, statistics, session management, and audit trail
query endpoints for operational visibility into the PHI redaction proxy.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Management"])

# Module-level startup timestamp; set in the lifespan handler via app.state.
_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health", summary="Health check and basic system info")
async def health(request: Request) -> JSONResponse:
    """Return proxy version, uptime, active session count, and providers."""
    state = request.app.state
    startup_time: float = getattr(state, "startup_time", time.time())
    session_mgr = state.session_manager
    uptime_seconds = round(time.time() - startup_time, 1)

    return JSONResponse(
        content={
            "status": "healthy",
            "version": _VERSION,
            "uptime_seconds": uptime_seconds,
            "active_sessions": session_mgr.active_count,
            "providers": ["openai", "anthropic"],
        }
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Aggregate redaction statistics")
async def stats(request: Request) -> JSONResponse:
    """Return aggregate statistics about redaction activity.

    Queries the audit trail for totals, category breakdowns,
    confidence distributions, and average latency.
    """
    state = request.app.state
    audit = state.audit_trail

    try:
        events = audit.query(limit=10_000)
    except Exception:
        logger.exception("Failed to query audit trail for stats")
        events = []

    total_events = len(events)
    category_counts: dict[str, int] = {}
    confidence_sum = 0.0
    method_counts: dict[str, int] = {}

    for ev in events:
        cat = ev.phi_category.value
        category_counts[cat] = category_counts.get(cat, 0) + 1
        confidence_sum += ev.confidence
        method = ev.detection_method.value
        method_counts[method] = method_counts.get(method, 0) + 1

    avg_confidence = round(confidence_sum / total_events, 4) if total_events else 0.0

    return JSONResponse(
        content={
            "total_redaction_events": total_events,
            "categories": category_counts,
            "detection_methods": method_counts,
            "average_confidence": avg_confidence,
        }
    )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@router.get("/sessions", summary="List all tracked sessions")
async def list_sessions(request: Request) -> JSONResponse:
    """Return a list of all active and recently-closed sessions."""
    state = request.app.state
    session_mgr = state.session_manager
    sessions = session_mgr.list_sessions()

    return JSONResponse(
        content={
            "count": len(sessions),
            "sessions": [
                {
                    "id": s.id,
                    "status": s.status.value,
                    "provider": s.provider,
                    "created_at": s.created_at.isoformat(),
                    "last_active_at": s.last_active_at.isoformat(),
                    "expires_at": s.expires_at.isoformat(),
                }
                for s in sessions
            ],
        }
    )


@router.get("/sessions/{session_id}", summary="Get session detail")
async def get_session(request: Request, session_id: str) -> JSONResponse:
    """Return detailed information about a specific session."""
    state = request.app.state
    session_mgr = state.session_manager
    session = session_mgr.get_session(session_id)

    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    return JSONResponse(
        content={
            "id": session.id,
            "status": session.status.value,
            "provider": session.provider,
            "created_at": session.created_at.isoformat(),
            "last_active_at": session.last_active_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "date_shift_offset_days": session.date_shift_offset_days,
            "age_shift_offset_years": session.age_shift_offset_years,
        }
    )


@router.delete("/sessions/{session_id}", summary="Close a session")
async def close_session(request: Request, session_id: str) -> JSONResponse:
    """Explicitly close a session and invalidate its mappings."""
    state = request.app.state
    session_mgr = state.session_manager
    session = session_mgr.get_session(session_id)

    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    session_mgr.close_session(session_id)
    return JSONResponse(
        content={"status": "closed", "session_id": session_id},
    )


# ---------------------------------------------------------------------------
# Compliance Report
# ---------------------------------------------------------------------------


@router.get("/compliance/report", summary="Generate HIPAA compliance report")
async def compliance_report(
    request: Request,
    session_id: str | None = Query(default=None, description="Filter by session ID"),
    from_dt: str | None = Query(
        default=None,
        alias="from",
        description="Start datetime (ISO 8601)",
    ),
    to_dt: str | None = Query(
        default=None,
        alias="to",
        description="End datetime (ISO 8601)",
    ),
) -> JSONResponse:
    """Generate a HIPAA Safe Harbor compliance evidence report."""
    from phi_redactor.audit.reports import ComplianceReportGenerator

    state = request.app.state
    audit = state.audit_trail

    parsed_from: datetime | None = None
    parsed_to: datetime | None = None

    if from_dt is not None:
        try:
            parsed_from = datetime.fromisoformat(from_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'from' datetime: {from_dt}")

    if to_dt is not None:
        try:
            parsed_to = datetime.fromisoformat(to_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'to' datetime: {to_dt}")

    generator = ComplianceReportGenerator(audit_trail=audit)
    report = generator.generate_report(
        from_dt=parsed_from,
        to_dt=parsed_to,
        session_id=session_id,
    )

    return JSONResponse(content=report)


@router.post("/reports/safe-harbor", summary="Generate a Safe Harbor attestation report file")
async def generate_safe_harbor_report(
    request: Request,
    session_id: str | None = Query(default=None, description="Filter by session ID"),
    from_dt: str | None = Query(
        default=None,
        alias="from",
        description="Start datetime (ISO 8601)",
    ),
    to_dt: str | None = Query(
        default=None,
        alias="to",
        description="End datetime (ISO 8601)",
    ),
    fmt: str = Query(
        default="json",
        alias="format",
        description="Output format: json, md, or html",
    ),
) -> JSONResponse:
    """Generate a HIPAA Safe Harbor attestation report and write it to a file.

    Returns a ``report_id`` and the ``output_path`` of the written file.
    """
    import uuid
    from pathlib import Path

    from phi_redactor.audit.reports import (
        ComplianceReportGenerator,
        render_html,
        render_markdown,
    )

    state = request.app.state
    audit = state.audit_trail

    parsed_from: datetime | None = None
    parsed_to: datetime | None = None

    if from_dt is not None:
        try:
            parsed_from = datetime.fromisoformat(from_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'from' datetime: {from_dt}")

    if to_dt is not None:
        try:
            parsed_to = datetime.fromisoformat(to_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'to' datetime: {to_dt}")

    valid_formats = {"json", "md", "html"}
    if fmt not in valid_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{fmt}'. Must be one of: {', '.join(sorted(valid_formats))}",
        )

    generator = ComplianceReportGenerator(audit_trail=audit)
    report = generator.generate_safe_harbor(
        from_dt=parsed_from,
        to_dt=parsed_to,
        session_id=session_id,
    )

    report_id = str(uuid.uuid4())
    ext = fmt if fmt != "md" else "md"

    # Resolve output directory from app config when available, else use a temp dir.
    try:
        cfg = state.config
        reports_dir = Path(cfg.audit_path).parent / "reports"
    except AttributeError:
        import tempfile
        reports_dir = Path(tempfile.gettempdir()) / "phi-redactor" / "reports"

    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / f"safe-harbor-{report_id}.{ext}"

    if fmt == "json":
        import json as _json
        output_path.write_text(_json.dumps(report, indent=2, default=str), encoding="utf-8")
    elif fmt == "md":
        output_path.write_text(render_markdown(report), encoding="utf-8")
    elif fmt == "html":
        output_path.write_text(render_html(report), encoding="utf-8")

    logger.info("Safe Harbor report generated: report_id=%s path=%s", report_id, output_path)

    return JSONResponse(
        status_code=201,
        content={
            "report_id": report_id,
            "output_path": str(output_path),
            "format": fmt,
            "session_filter": session_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
    )


@router.get("/compliance/summary", summary="Quick compliance status check")
async def compliance_summary(request: Request) -> JSONResponse:
    """Return a lightweight compliance summary for dashboards."""
    from phi_redactor.audit.reports import ComplianceReportGenerator

    state = request.app.state
    audit = state.audit_trail

    generator = ComplianceReportGenerator(audit_trail=audit)
    summary = generator.generate_summary()

    return JSONResponse(content=summary)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@router.get("/audit", summary="Query audit trail events")
async def query_audit(
    request: Request,
    session_id: str | None = Query(default=None, description="Filter by session ID"),
    category: str | None = Query(default=None, description="Filter by PHI category"),
    from_dt: str | None = Query(
        default=None,
        alias="from",
        description="Inclusive start datetime (ISO 8601)",
    ),
    to_dt: str | None = Query(
        default=None,
        alias="to",
        description="Inclusive end datetime (ISO 8601)",
    ),
    limit: int = Query(default=100, ge=1, le=10_000, description="Max events to return"),
    offset: int = Query(default=0, ge=0, description="Events to skip"),
) -> JSONResponse:
    """Query the audit trail with optional filters."""
    state = request.app.state
    audit = state.audit_trail

    parsed_from: datetime | None = None
    parsed_to: datetime | None = None

    if from_dt is not None:
        try:
            parsed_from = datetime.fromisoformat(from_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'from' datetime: {from_dt}")

    if to_dt is not None:
        try:
            parsed_to = datetime.fromisoformat(to_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'to' datetime: {to_dt}")

    try:
        events = audit.query(
            session_id=session_id,
            category=category,
            from_dt=parsed_from,
            to_dt=parsed_to,
            limit=limit,
            offset=offset,
        )
    except Exception:
        logger.exception("Audit trail query failed")
        raise HTTPException(status_code=500, detail="Audit trail query failed.")

    return JSONResponse(
        content={
            "count": len(events),
            "events": [
                {
                    "id": ev.id,
                    "session_id": ev.session_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "request_id": ev.request_id,
                    "phi_category": ev.phi_category.value,
                    "confidence": ev.confidence,
                    "action": ev.action.value,
                    "detection_method": ev.detection_method.value,
                    "text_length": ev.text_length,
                }
                for ev in events
            ],
        }
    )

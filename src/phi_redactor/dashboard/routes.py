"""Dashboard routes for the PHI redaction monitoring UI."""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/", response_class=HTMLResponse, summary="Dashboard UI")
async def dashboard_page(request: Request) -> FileResponse:
    """Serve the single-page dashboard UI."""
    from pathlib import Path
    static_dir = Path(__file__).parent / "static"
    index = static_dir / "index.html"
    if not index.exists():
        return HTMLResponse("<h1>Dashboard not found</h1><p>Static files missing.</p>", status_code=404)
    return FileResponse(str(index), media_type="text/html")


@router.get("/api/live-stats", summary="Live statistics for dashboard")
async def live_stats(request: Request) -> JSONResponse:
    """Return real-time statistics for the dashboard UI."""
    state = request.app.state
    startup_time: float = getattr(state, "startup_time", time.time())
    session_mgr = state.session_manager
    audit = state.audit_trail

    try:
        events = audit.query(limit=10_000)
    except Exception:
        events = []

    category_counts: dict[str, int] = {}
    method_counts: dict[str, int] = {}
    hourly: dict[str, int] = {}

    for ev in events:
        cat = ev.phi_category.value
        category_counts[cat] = category_counts.get(cat, 0) + 1
        method = ev.detection_method.value
        method_counts[method] = method_counts.get(method, 0) + 1
        hour_key = ev.timestamp.strftime("%Y-%m-%d %H:00")
        hourly[hour_key] = hourly.get(hour_key, 0) + 1

    return JSONResponse(content={
        "uptime_seconds": round(time.time() - startup_time, 1),
        "active_sessions": session_mgr.active_count,
        "total_redactions": len(events),
        "categories": category_counts,
        "methods": method_counts,
        "hourly_volume": hourly,
    })

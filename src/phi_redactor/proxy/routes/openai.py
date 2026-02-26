"""OpenAI-compatible proxy routes.

Provides ``/openai/v1/chat/completions`` and ``/openai/v1/embeddings``
endpoints that transparently detect and redact PHI before forwarding
requests to the real OpenAI API, then rehydrate the responses before
returning them to the caller.

A ``/v1/*`` default router mirrors the same handlers so clients can use
the proxy as a drop-in replacement without the ``/openai`` prefix.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, AsyncIterator

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from phi_redactor.models import RedactionAction
from phi_redactor.proxy.adapters.openai import OpenAIAdapter
from phi_redactor.proxy.streaming import StreamRehydrator

if TYPE_CHECKING:
    from phi_redactor.audit.trail import AuditTrail
    from phi_redactor.detection.engine import PhiDetectionEngine
    from phi_redactor.masking.semantic import SemanticMasker
    from phi_redactor.proxy.session import SessionManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/openai/v1", tags=["OpenAI Proxy"])
default_router = APIRouter(prefix="/v1", tags=["Default Proxy"])

_adapter = OpenAIAdapter()

_UPSTREAM_BASE_URL = "https://api.openai.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_components(request: Request) -> tuple[
    PhiDetectionEngine,
    SemanticMasker,
    SessionManager,
    AuditTrail,
    httpx.AsyncClient,
    float,
]:
    """Retrieve shared application components from ``request.app.state``."""
    state = request.app.state
    return (
        state.detection_engine,
        state.masker,
        state.session_manager,
        state.audit_trail,
        state.http_client,
        state.sensitivity,
    )


def _detect_and_mask(
    engine: PhiDetectionEngine,
    masker: SemanticMasker,
    audit: AuditTrail,
    session_id: str,
    request_id: str,
    texts: list[str],
    sensitivity: float,
) -> list[str]:
    """Run PHI detection and masking on a list of texts.

    For each detection, an audit event is logged.  If detection raises an
    exception the request is **blocked** (fail-safe).

    Returns:
        A list of masked texts positionally aligned with *texts*.

    Raises:
        HTTPException: If detection or masking fails (503).
    """
    masked_texts: list[str] = []

    for text in texts:
        try:
            detections = engine.detect(text, sensitivity)
        except Exception:
            logger.exception("PHI detection failed -- blocking request (fail-safe)")
            raise HTTPException(
                status_code=503,
                detail="PHI detection unavailable. Request blocked for safety.",
            )

        try:
            masked_text, _mapping = masker.mask(text, detections, session_id)
        except Exception:
            logger.exception("PHI masking failed -- blocking request (fail-safe)")
            raise HTTPException(
                status_code=503,
                detail="PHI masking unavailable. Request blocked for safety.",
            )

        # Audit each detection.
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

        masked_texts.append(masked_text)

    return masked_texts


# ---------------------------------------------------------------------------
# Chat completions
# ---------------------------------------------------------------------------


async def _chat_completions_handler(request: Request) -> StreamingResponse | JSONResponse:
    """Core handler for ``POST /chat/completions``."""
    engine, masker, session_mgr, audit, http_client, sensitivity = _get_components(request)

    # 1. Parse request body.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body.")

    request_id = str(uuid.uuid4())
    is_streaming = body.get("stream", False)

    # 2. Session management.
    client_session_id = request.headers.get("x-session-id")
    provider = "openai"
    session = session_mgr.get_or_create(session_id=client_session_id, provider=provider)
    session_id = session.id

    # 3. Extract messages.
    original_texts = _adapter.extract_messages(body)

    # 4 + 5. Detect and mask PHI.
    start_time = time.monotonic()
    masked_texts = _detect_and_mask(
        engine, masker, audit, session_id, request_id, original_texts, sensitivity,
    )
    processing_ms = (time.monotonic() - start_time) * 1000

    # 6. Build upstream request with masked content.
    upstream_body = _adapter.inject_messages(body, masked_texts)

    # 7. Build headers.
    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    auth_headers = _adapter.get_auth_headers(raw_headers)
    upstream_url = _adapter.get_upstream_url(_UPSTREAM_BASE_URL, "/v1/chat/completions")

    forward_headers = {
        "Content-Type": "application/json",
        **auth_headers,
    }

    # 8. Forward to upstream.
    if is_streaming:
        return await _handle_streaming(
            http_client=http_client,
            upstream_url=upstream_url,
            upstream_body=upstream_body,
            forward_headers=forward_headers,
            session_id=session_id,
            masker=masker,
            request_id=request_id,
            processing_ms=processing_ms,
        )

    return await _handle_non_streaming(
        http_client=http_client,
        upstream_url=upstream_url,
        upstream_body=upstream_body,
        forward_headers=forward_headers,
        session_id=session_id,
        masker=masker,
        request_id=request_id,
        processing_ms=processing_ms,
    )


async def _handle_non_streaming(
    *,
    http_client: httpx.AsyncClient,
    upstream_url: str,
    upstream_body: dict,
    forward_headers: dict[str, str],
    session_id: str,
    masker: SemanticMasker,
    request_id: str,
    processing_ms: float,
) -> JSONResponse:
    """Forward a non-streaming request and rehydrate the response."""
    try:
        upstream_resp = await http_client.post(
            upstream_url,
            json=upstream_body,
            headers=forward_headers,
        )
    except httpx.HTTPError as exc:
        logger.error("Upstream request failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Upstream provider unavailable.",
        )

    if upstream_resp.status_code >= 400:
        content_type = upstream_resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            error_content = upstream_resp.json()
        else:
            error_content = {"error": upstream_resp.text}
        return JSONResponse(
            status_code=upstream_resp.status_code,
            content=error_content,
        )

    try:
        response_body = upstream_resp.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Invalid JSON from upstream provider.",
        )

    # Rehydrate the response content.
    response_text = _adapter.parse_response_content(response_body)
    if response_text:
        rehydrated = masker.rehydrate(response_text, session_id)
        response_body = _adapter.inject_response_content(response_body, rehydrated)

    # Add proxy metadata.
    response_body["x_phi_redactor"] = {
        "session_id": session_id,
        "request_id": request_id,
        "processing_ms": round(processing_ms, 2),
    }

    return JSONResponse(content=response_body)


async def _handle_streaming(
    *,
    http_client: httpx.AsyncClient,
    upstream_url: str,
    upstream_body: dict,
    forward_headers: dict[str, str],
    session_id: str,
    masker: SemanticMasker,
    request_id: str,
    processing_ms: float,
) -> StreamingResponse:
    """Forward a streaming request and rehydrate SSE chunks."""

    async def _stream_generator() -> AsyncIterator[str]:
        rehydrator = StreamRehydrator(
            session_id=session_id,
            masker=masker,
        )

        try:
            async with http_client.stream(
                "POST",
                upstream_url,
                json=upstream_body,
                headers=forward_headers,
            ) as upstream_resp:
                if upstream_resp.status_code >= 400:
                    # Read error body and yield it.
                    error_body = b""
                    async for chunk in upstream_resp.aiter_bytes():
                        error_body += chunk
                    error_msg = error_body.decode("utf-8", errors="replace")
                    error_data = json.dumps({"error": error_msg})
                    yield f"data: {error_data}\n\n"
                    return

                async for line in upstream_resp.aiter_lines():
                    if _adapter.is_stream_done(line):
                        # Flush the rehydrator buffer.
                        remaining = rehydrator.flush()
                        if remaining:
                            # Emit final content as a data event.
                            final_payload = {
                                "choices": [{"delta": {"content": remaining}, "index": 0}],
                            }
                            yield f"data: {json.dumps(final_payload)}\n\n"
                        yield "data: [DONE]\n\n"
                        return

                    content = _adapter.parse_stream_chunk(line)
                    if content is not None:
                        safe_text = rehydrator.process_chunk(content)
                        if safe_text:
                            modified_line = _adapter.inject_stream_chunk(line, safe_text)
                            yield f"{modified_line}\n\n"
                    else:
                        # Non-content lines (e.g., role, empty) pass through.
                        if line.strip():
                            yield f"{line}\n\n"

        except httpx.HTTPError as exc:
            logger.error("Upstream streaming request failed: %s", exc)
            error_payload = {"error": {"message": "Upstream provider unavailable."}}
            yield f"data: {json.dumps(error_payload)}\n\n"

    return StreamingResponse(
        _stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-PHI-Redactor-Session-Id": session_id,
            "X-PHI-Redactor-Request-Id": request_id,
        },
    )


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------


async def _embeddings_handler(request: Request) -> JSONResponse:
    """Core handler for ``POST /embeddings``."""
    engine, masker, session_mgr, audit, http_client, sensitivity = _get_components(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body.")

    request_id = str(uuid.uuid4())

    # Session management.
    client_session_id = request.headers.get("x-session-id")
    session = session_mgr.get_or_create(session_id=client_session_id, provider="openai")
    session_id = session.id

    # Extract input text(s).
    raw_input = body.get("input", "")
    if isinstance(raw_input, str):
        input_texts = [raw_input]
    elif isinstance(raw_input, list):
        input_texts = [t for t in raw_input if isinstance(t, str)]
    else:
        input_texts = [str(raw_input)]

    # Detect and mask.
    start_time = time.monotonic()
    masked_texts = _detect_and_mask(
        engine, masker, audit, session_id, request_id, input_texts, sensitivity,
    )
    processing_ms = (time.monotonic() - start_time) * 1000

    # Rebuild input.
    upstream_body = {**body}
    if isinstance(raw_input, str):
        upstream_body["input"] = masked_texts[0] if masked_texts else raw_input
    elif isinstance(raw_input, list):
        upstream_body["input"] = masked_texts
    else:
        upstream_body["input"] = masked_texts[0] if masked_texts else str(raw_input)

    # Forward.
    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    auth_headers = _adapter.get_auth_headers(raw_headers)
    upstream_url = _adapter.get_upstream_url(_UPSTREAM_BASE_URL, "/v1/embeddings")

    forward_headers = {
        "Content-Type": "application/json",
        **auth_headers,
    }

    try:
        upstream_resp = await http_client.post(
            upstream_url,
            json=upstream_body,
            headers=forward_headers,
        )
    except httpx.HTTPError as exc:
        logger.error("Upstream embeddings request failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Upstream provider unavailable.",
        )

    if upstream_resp.status_code >= 400:
        content_type = upstream_resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            error_content = upstream_resp.json()
        else:
            error_content = {"error": upstream_resp.text}
        return JSONResponse(
            status_code=upstream_resp.status_code,
            content=error_content,
        )

    try:
        response_body = upstream_resp.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Invalid JSON from upstream provider.",
        )

    # Embeddings responses don't contain text to rehydrate, but add metadata.
    response_body["x_phi_redactor"] = {
        "session_id": session_id,
        "request_id": request_id,
        "processing_ms": round(processing_ms, 2),
    }

    return JSONResponse(content=response_body)


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

router.add_api_route(
    "/chat/completions",
    _chat_completions_handler,
    methods=["POST"],
    summary="Proxy OpenAI chat completions with PHI redaction",
)

router.add_api_route(
    "/embeddings",
    _embeddings_handler,
    methods=["POST"],
    summary="Proxy OpenAI embeddings with PHI redaction",
)

# Default /v1/* routes (drop-in replacement without /openai prefix)
default_router.add_api_route(
    "/chat/completions",
    _chat_completions_handler,
    methods=["POST"],
    summary="Proxy chat completions with PHI redaction (default)",
)

default_router.add_api_route(
    "/embeddings",
    _embeddings_handler,
    methods=["POST"],
    summary="Proxy embeddings with PHI redaction (default)",
)

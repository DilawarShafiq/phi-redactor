"""Azure OpenAI Service proxy routes.

Provides ``/azure/v1/chat/completions`` and ``/azure/v1/embeddings``
endpoints that transparently detect and redact PHI before forwarding
requests to Azure OpenAI, then rehydrate responses before returning
them to the caller.

Azure OpenAI uses the same wire format as OpenAI but requires a
resource-specific endpoint and deployment-based URL routing.

Client configuration example (Python openai SDK)::

    import openai
    client = openai.AzureOpenAI(
        base_url="http://localhost:8080/azure/v1",
        api_key="<your-azure-key>",
        api_version="2024-02-01",
    )
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from phi_redactor.models import RedactionAction
from phi_redactor.proxy.adapters.azure import AzureOpenAIAdapter
from phi_redactor.proxy.streaming import StreamRehydrator

if TYPE_CHECKING:
    from phi_redactor.audit.trail import AuditTrail
    from phi_redactor.detection.engine import PhiDetectionEngine
    from phi_redactor.masking.semantic import SemanticMasker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/azure/v1", tags=["Azure OpenAI Proxy"])

_AZURE_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
_AZURE_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")

_adapter = AzureOpenAIAdapter(endpoint=_AZURE_ENDPOINT, api_version=_AZURE_API_VERSION)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_components(request: Request) -> tuple:
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
    """Run PHI detection and masking on a list of texts."""
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


def _build_upstream_url(body: dict, path: str) -> str:
    """Build the Azure upstream URL using the deployment name from the request body.

    Azure OpenAI routes by deployment, so the ``model`` field in the request
    body is used as the deployment name in the URL.
    """
    deployment = body.get("model", "")
    if deployment:
        azure_path = f"/openai/deployments/{deployment}{path}"
    else:
        azure_path = f"/openai{path}"
    effective_endpoint = _AZURE_ENDPOINT.rstrip("/") if _AZURE_ENDPOINT else ""
    if not effective_endpoint:
        logger.warning("AZURE_OPENAI_ENDPOINT not set — upstream calls will fail")
        effective_endpoint = "https://UNCONFIGURED.openai.azure.com"
    return f"{effective_endpoint}{azure_path}?api-version={_AZURE_API_VERSION}"


# ---------------------------------------------------------------------------
# Chat completions
# ---------------------------------------------------------------------------


async def _chat_completions_handler(request: Request) -> StreamingResponse | JSONResponse:
    """Core handler for ``POST /azure/v1/chat/completions``."""
    engine, masker, session_mgr, audit, http_client, sensitivity = _get_components(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body.")

    request_id = str(uuid.uuid4())
    is_streaming = body.get("stream", False)

    client_session_id = request.headers.get("x-session-id")
    session = session_mgr.get_or_create(session_id=client_session_id, provider="azure")
    session_id = session.id

    original_texts = _adapter.extract_messages(body)

    start_time = time.monotonic()
    masked_texts = _detect_and_mask(
        engine, masker, audit, session_id, request_id, original_texts, sensitivity
    )
    processing_ms = (time.monotonic() - start_time) * 1000

    upstream_body = _adapter.inject_messages(body, masked_texts)
    upstream_url = _build_upstream_url(body, "/chat/completions")

    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    auth_headers = _adapter.get_auth_headers(raw_headers)
    forward_headers = {"Content-Type": "application/json", **auth_headers}

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
    try:
        upstream_resp = await http_client.post(
            upstream_url, json=upstream_body, headers=forward_headers
        )
    except httpx.HTTPError as exc:
        logger.error("Azure upstream request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Upstream provider unavailable.")

    if upstream_resp.status_code >= 400:
        content_type = upstream_resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            error_content = upstream_resp.json()
        else:
            error_content = {"error": upstream_resp.text}
        return JSONResponse(status_code=upstream_resp.status_code, content=error_content)

    try:
        response_body = upstream_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Invalid JSON from upstream provider.")

    response_text = _adapter.parse_response_content(response_body)
    if response_text:
        rehydrated = masker.rehydrate(response_text, session_id)
        response_body = _adapter.inject_response_content(response_body, rehydrated)

    response_body["x_phi_redactor"] = {
        "session_id": session_id,
        "request_id": request_id,
        "processing_ms": round(processing_ms, 2),
        "provider": "azure",
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
    async def _stream_generator() -> AsyncIterator[str]:
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker)

        try:
            async with http_client.stream(
                "POST", upstream_url, json=upstream_body, headers=forward_headers
            ) as upstream_resp:
                if upstream_resp.status_code >= 400:
                    error_body = b""
                    async for chunk in upstream_resp.aiter_bytes():
                        error_body += chunk
                    error_msg = error_body.decode("utf-8", errors="replace")
                    yield f"data: {json.dumps({'error': error_msg})}\n\n"
                    return

                async for line in upstream_resp.aiter_lines():
                    if _adapter.is_stream_done(line):
                        remaining = rehydrator.flush()
                        if remaining:
                            final_payload = {
                                "choices": [{"delta": {"content": remaining}, "index": 0}]
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
                        if line.strip():
                            yield f"{line}\n\n"

        except httpx.HTTPError as exc:
            logger.error("Azure upstream streaming failed: %s", exc)
            yield f"data: {json.dumps({'error': {'message': 'Upstream provider unavailable.'}})}\n\n"

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
    """Core handler for ``POST /azure/v1/embeddings``."""
    engine, masker, session_mgr, audit, http_client, sensitivity = _get_components(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body.")

    request_id = str(uuid.uuid4())

    client_session_id = request.headers.get("x-session-id")
    session = session_mgr.get_or_create(session_id=client_session_id, provider="azure")
    session_id = session.id

    raw_input = body.get("input", "")
    if isinstance(raw_input, str):
        input_texts = [raw_input]
    elif isinstance(raw_input, list):
        input_texts = [t for t in raw_input if isinstance(t, str)]
    else:
        input_texts = [str(raw_input)]

    start_time = time.monotonic()
    masked_texts = _detect_and_mask(
        engine, masker, audit, session_id, request_id, input_texts, sensitivity
    )
    processing_ms = (time.monotonic() - start_time) * 1000

    upstream_body = {**body}
    if isinstance(raw_input, str):
        upstream_body["input"] = masked_texts[0] if masked_texts else raw_input
    elif isinstance(raw_input, list):
        upstream_body["input"] = masked_texts
    else:
        upstream_body["input"] = masked_texts[0] if masked_texts else str(raw_input)

    upstream_url = _build_upstream_url(body, "/embeddings")
    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    auth_headers = _adapter.get_auth_headers(raw_headers)
    forward_headers = {"Content-Type": "application/json", **auth_headers}

    try:
        upstream_resp = await http_client.post(
            upstream_url, json=upstream_body, headers=forward_headers
        )
    except httpx.HTTPError as exc:
        logger.error("Azure upstream embeddings request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Upstream provider unavailable.")

    if upstream_resp.status_code >= 400:
        content_type = upstream_resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            error_content = upstream_resp.json()
        else:
            error_content = {"error": upstream_resp.text}
        return JSONResponse(status_code=upstream_resp.status_code, content=error_content)

    try:
        response_body = upstream_resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Invalid JSON from upstream provider.")

    response_body["x_phi_redactor"] = {
        "session_id": session_id,
        "request_id": request_id,
        "processing_ms": round(processing_ms, 2),
        "provider": "azure",
    }

    return JSONResponse(content=response_body)


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

router.add_api_route(
    "/chat/completions",
    _chat_completions_handler,
    methods=["POST"],
    summary="Proxy Azure OpenAI chat completions with PHI redaction",
    response_model=None,
)

router.add_api_route(
    "/embeddings",
    _embeddings_handler,
    methods=["POST"],
    summary="Proxy Azure OpenAI embeddings with PHI redaction",
    response_model=None,
)

---
id: 008
title: Proxy Layer FastAPI Implementation
stage: green
date: 2026-02-26
surface: agent
model: claude-opus-4-6
feature: 001-phi-redaction-proxy
branch: master
user: TechTiesIbrahim
command: implement T029-T036
labels: ["proxy", "fastapi", "openai", "streaming", "session", "management", "library"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
  - src/phi_redactor/proxy/app.py
  - src/phi_redactor/proxy/session.py
  - src/phi_redactor/proxy/streaming.py
  - src/phi_redactor/proxy/adapters/base.py
  - src/phi_redactor/proxy/adapters/openai.py
  - src/phi_redactor/proxy/routes/openai.py
  - src/phi_redactor/proxy/routes/management.py
  - src/phi_redactor/proxy/routes/library.py
tests:
  - none (production code implementation)
---

## Prompt

You are implementing the phi-redactor project. Write actual production-quality Python code.

Project at C:\Users\TechTiesIbrahim\phi_redactor. The following modules already exist and should be imported from:
- `phi_redactor.models`: PHIDetection, PHICategory, RedactionResult, DetectionMethod, RedactionAction, AuditEvent, SessionInfo, SessionStatus
- `phi_redactor.config`: PhiRedactorConfig, setup_logging
- `phi_redactor.detection.engine`: PhiDetectionEngine (has `detect(text, sensitivity) -> list[PHIDetection]`)
- `phi_redactor.masking.semantic`: SemanticMasker (has `mask(text, detections, session_id) -> tuple[str, dict]`, `rehydrate(text, session_id) -> str`)
- `phi_redactor.vault.store`: PhiVault (has `store_mapping()`, `lookup_by_original()`, `lookup_by_synthetic()`, `create_session()`, `cleanup_expired()`)
- `phi_redactor.audit.trail`: AuditTrail (has `log_event(session_id, request_id, category, confidence, action, detection_method, text_length) -> AuditEvent`)

Create these files:

**T029** `src/phi_redactor/proxy/app.py`: FastAPI application factory with lifespan management
**T030** `src/phi_redactor/proxy/session.py`: Session management for multi-turn conversation tracking
**T031** `src/phi_redactor/proxy/adapters/base.py`: Base adapter for LLM provider API format translation
**T032** `src/phi_redactor/proxy/adapters/openai.py`: OpenAI API format adapter
**T033** `src/phi_redactor/proxy/routes/openai.py`: OpenAI-compatible proxy routes
**T034** `src/phi_redactor/proxy/streaming.py`: SSE streaming re-hydration for proxy responses
**T035** `src/phi_redactor/proxy/routes/management.py`: Management API routes
**T036** `src/phi_redactor/proxy/routes/library.py`: Library API routes for direct redaction

## Response snapshot

Implemented all 8 files (T029-T036) for the proxy layer:

- **app.py**: FastAPI factory with async lifespan that initializes detection engine, vault, masker, audit trail, httpx.AsyncClient, and session manager. CORS middleware and all routers included.
- **session.py**: SessionManager with get_or_create, close_session, list_sessions, active_count, and a background cleanup_loop (every 5 min) that expires idle/max-lifetime sessions.
- **adapters/base.py**: ABC defining extract_messages, inject_messages, parse_response_content, inject_response_content, get_upstream_url, get_auth_headers.
- **adapters/openai.py**: Full OpenAI adapter with multimodal content support, SSE parsing (parse_stream_chunk, is_stream_done, inject_stream_chunk).
- **routes/openai.py**: /openai/v1/chat/completions and /embeddings with fail-safe blocking, streaming support via StreamRehydrator, audit logging. Also /v1/* default routes.
- **streaming.py**: StreamRehydrator that buffers chunks and emits safe prefixes using max-synthetic-length boundary detection.
- **routes/management.py**: /health, /stats, /sessions, /sessions/{id}, DELETE /sessions/{id}, /audit with query filters.
- **routes/library.py**: /redact and /rehydrate endpoints for direct API usage without LLM proxy.

## Outcome

- Impact: Complete proxy layer enabling PHI-safe forwarding to OpenAI with streaming support
- Tests: No tests added in this pass (production code only)
- Files: 8 files created/modified
- Next prompts: Add Anthropic adapter, write integration tests, add rate limiting
- Reflection: All modules integrate cleanly with existing detection/masking/vault/audit infrastructure

## Evaluation notes (flywheel)

- Failure modes observed: None yet -- needs integration testing with live upstream
- Graders run and results (PASS/FAIL): N/A
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): Add pytest fixtures for app and test each route

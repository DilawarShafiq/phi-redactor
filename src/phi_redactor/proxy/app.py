"""FastAPI application factory for the PHI redaction proxy.

Initializes all core components (detection engine, semantic masker, vault,
audit trail, HTTP client, session manager) during application lifespan and
stores them on ``app.state`` for access by route handlers.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phi_redactor.audit.trail import AuditTrail
from phi_redactor.config import PhiRedactorConfig, setup_logging
from phi_redactor.detection.engine import PhiDetectionEngine
from phi_redactor.masking.semantic import SemanticMasker
from phi_redactor.dashboard import routes as dashboard_routes
from phi_redactor.proxy.routes import anthropic, library, management, openai
from phi_redactor.proxy.session import SessionManager
from phi_redactor.vault.store import PhiVault

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler: initialize and tear down shared resources.

    On startup:
    - Initialises the PHI detection engine (loads Presidio + spaCy model).
    - Creates the encrypted vault and semantic masker.
    - Starts the audit trail.
    - Opens an ``httpx.AsyncClient`` for upstream LLM requests.
    - Launches the session manager with its background cleanup loop.

    All components are stored on ``app.state`` so route handlers can retrieve
    them via ``request.app.state.<component>``.

    On shutdown:
    - Cancels the session cleanup task.
    - Closes the HTTP client.
    - Runs a final vault cleanup and closes the database.
    """
    config: PhiRedactorConfig = app.state.config

    # -- Startup -----------------------------------------------------------
    logger.info("Starting PHI Redactor proxy (host=%s, port=%d)", config.host, config.port)

    # Core components.
    vault = PhiVault(
        db_path=str(config.vault_path),
        passphrase=config.vault_passphrase,
    )
    app.state.vault = vault

    engine = PhiDetectionEngine(sensitivity=config.sensitivity)
    app.state.detection_engine = engine

    masker = SemanticMasker(vault=vault)
    app.state.masker = masker

    audit = AuditTrail(audit_dir=str(config.audit_path))
    app.state.audit_trail = audit

    http_client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0))
    app.state.http_client = http_client

    session_mgr = SessionManager(
        vault=vault,
        idle_timeout=config.session_idle_timeout,
        max_lifetime=config.session_max_lifetime,
    )
    app.state.session_manager = session_mgr

    app.state.sensitivity = config.sensitivity
    app.state.startup_time = time.time()

    # Launch the session cleanup background task.
    cleanup_task = asyncio.create_task(session_mgr.cleanup_loop())
    app.state.cleanup_task = cleanup_task

    logger.info("PHI Redactor proxy started successfully")

    yield

    # -- Shutdown ----------------------------------------------------------
    logger.info("Shutting down PHI Redactor proxy")

    # Cancel the cleanup loop.
    cleanup_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await cleanup_task

    # Close HTTP client.
    await http_client.aclose()

    # Final vault cleanup and close.
    try:
        vault.cleanup_expired()
    except Exception:
        logger.exception("Final vault cleanup failed")

    vault.close()
    logger.info("PHI Redactor proxy shut down cleanly")


def create_app(config: PhiRedactorConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Application configuration.  If ``None``, a default
            :class:`PhiRedactorConfig` is loaded from environment variables.

    Returns:
        A fully-configured :class:`FastAPI` instance ready to be served by
        uvicorn or any ASGI server.
    """
    if config is None:
        config = PhiRedactorConfig()

    setup_logging(config)

    app = FastAPI(
        title="PHI Redactor Proxy",
        description=(
            "HIPAA-native PHI redaction proxy for AI/LLM interactions. "
            "Detects and masks Protected Health Information in API requests "
            "before forwarding to upstream LLM providers."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Stash config on app.state so the lifespan handler can access it.
    app.state.config = config

    # -- CORS middleware ---------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Routers -----------------------------------------------------------
    app.include_router(openai.router)
    app.include_router(openai.default_router)
    app.include_router(anthropic.router)
    app.include_router(management.router)
    app.include_router(library.router)
    app.include_router(dashboard_routes.router)

    return app

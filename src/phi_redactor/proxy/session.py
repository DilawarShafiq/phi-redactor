"""Session management for multi-turn conversation tracking.

Maintains an in-memory registry of active sessions backed by the vault's
persistent session storage.  Idle and max-lifetime expiration is enforced
by a background cleanup loop.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from phi_redactor.models import SessionInfo, SessionStatus
from phi_redactor.vault.store import PhiVault

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL_SECONDS = 300  # 5 minutes


class SessionManager:
    """Manages proxy session lifecycle with idle and max-lifetime expiry.

    Parameters
    ----------
    vault:
        The :class:`PhiVault` used for persistent session creation.
    idle_timeout:
        Seconds of inactivity before a session is considered expired.
        Defaults to 1800 (30 minutes).
    max_lifetime:
        Maximum session duration in seconds regardless of activity.
        Defaults to 86400 (24 hours).
    """

    def __init__(
        self,
        vault: PhiVault,
        idle_timeout: int = 1800,
        max_lifetime: int = 86400,
    ) -> None:
        self._vault = vault
        self._idle_timeout = idle_timeout
        self._max_lifetime = max_lifetime
        self._sessions: dict[str, SessionInfo] = {}
        self._cleanup_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(
        self,
        session_id: str | None = None,
        provider: str = "openai",
    ) -> SessionInfo:
        """Return an active session, creating one if necessary.

        If *session_id* is provided and maps to an active (non-expired,
        non-closed) session, that session is returned with its
        ``last_active_at`` timestamp refreshed.

        If the session is expired / closed, or *session_id* is ``None``,
        a brand-new session is created via the vault.

        Args:
            session_id: Optional existing session identifier.
            provider: LLM provider label (used when creating a new session).

        Returns:
            A :class:`SessionInfo` instance in ``ACTIVE`` status.
        """
        now = datetime.now(timezone.utc)

        if session_id is not None and session_id in self._sessions:
            session = self._sessions[session_id]
            if self._is_active(session, now):
                # Refresh last-active timestamp
                session = session.model_copy(update={"last_active_at": now})
                self._sessions[session_id] = session
                return session

            # Session exists but is no longer valid -- remove it.
            self._expire_session(session_id)

        # Create a new session via the vault.
        new_session = self._vault.create_session(provider=provider)

        # Overwrite expires_at to respect our max_lifetime setting.
        new_session = new_session.model_copy(
            update={
                "expires_at": now + timedelta(seconds=self._max_lifetime),
            }
        )
        self._sessions[new_session.id] = new_session

        logger.info(
            "Created session %s for provider=%s (idle_timeout=%ds, max_lifetime=%ds)",
            new_session.id,
            provider,
            self._idle_timeout,
            self._max_lifetime,
        )
        return new_session

    def close_session(self, session_id: str) -> None:
        """Explicitly close a session.

        The session is marked ``CLOSED`` and removed from the active registry.

        Args:
            session_id: The session to close.
        """
        session = self._sessions.get(session_id)
        if session is not None:
            self._sessions[session_id] = session.model_copy(
                update={"status": SessionStatus.CLOSED}
            )
            logger.info("Session %s closed explicitly", session_id)
        else:
            logger.debug("Attempted to close unknown session %s", session_id)

    def list_sessions(self) -> list[SessionInfo]:
        """Return a snapshot of all tracked sessions (active and recently closed)."""
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> SessionInfo | None:
        """Return a single session by ID, or ``None``."""
        return self._sessions.get(session_id)

    @property
    def active_count(self) -> int:
        """Number of sessions currently in ACTIVE status."""
        now = datetime.now(timezone.utc)
        return sum(1 for s in self._sessions.values() if self._is_active(s, now))

    # ------------------------------------------------------------------
    # Background cleanup
    # ------------------------------------------------------------------

    async def cleanup_loop(self) -> None:
        """Periodically expire idle and over-lifetime sessions.

        Runs every 5 minutes.  Intended to be launched as a background
        ``asyncio.Task`` during application lifespan.
        """
        logger.info("Session cleanup loop started (interval=%ds)", _CLEANUP_INTERVAL_SECONDS)
        try:
            while True:
                await asyncio.sleep(_CLEANUP_INTERVAL_SECONDS)
                self._run_cleanup()
        except asyncio.CancelledError:
            logger.info("Session cleanup loop cancelled")

    def _run_cleanup(self) -> None:
        """Single pass: expire sessions that have exceeded their limits."""
        now = datetime.now(timezone.utc)
        expired_ids: list[str] = []

        for sid, session in self._sessions.items():
            if session.status != SessionStatus.ACTIVE:
                continue
            if not self._is_active(session, now):
                expired_ids.append(sid)

        for sid in expired_ids:
            self._expire_session(sid)

        # Also let the vault clean up its own expired data.
        try:
            cleaned = self._vault.cleanup_expired()
            if cleaned > 0:
                logger.info("Vault cleaned up %d expired sessions", cleaned)
        except Exception:
            logger.exception("Vault cleanup failed")

        if expired_ids:
            logger.info("Expired %d sessions during cleanup", len(expired_ids))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_active(self, session: SessionInfo, now: datetime) -> bool:
        """Return ``True`` if the session is still valid."""
        if session.status != SessionStatus.ACTIVE:
            return False

        # Max lifetime check.
        if now >= session.expires_at:
            return False

        # Idle timeout check.
        idle_deadline = session.last_active_at + timedelta(seconds=self._idle_timeout)
        if now >= idle_deadline:
            return False

        return True

    def _expire_session(self, session_id: str) -> None:
        """Mark a session as expired."""
        session = self._sessions.get(session_id)
        if session is not None:
            self._sessions[session_id] = session.model_copy(
                update={"status": SessionStatus.EXPIRED}
            )
            logger.debug("Session %s expired", session_id)

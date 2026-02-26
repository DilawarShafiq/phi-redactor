"""Local encrypted SQLite vault for PHI token mappings.

Provides persistent, encrypted storage of original-PHI-to-synthetic-value
mappings keyed by session.  Original PHI is never stored in plaintext --
it is Fernet-encrypted at rest and identified via SHA-256 hashes for
deduplication lookups.
"""

from __future__ import annotations

import hashlib
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from phi_redactor.models import SessionInfo, SessionStatus
from phi_redactor.vault.encryption import VaultEncryption


_DEFAULT_SESSION_LIFETIME_HOURS = 24


class PhiVault:
    """Local encrypted SQLite vault for PHI token mappings.

    Parameters
    ----------
    db_path:
        Filesystem path for the SQLite database.  Tilde-expanded automatically.
        Defaults to ``~/.phi-redactor/vault.db``.
    passphrase:
        Optional passphrase forwarded to :class:`VaultEncryption` for
        key derivation.
    key_path:
        Optional explicit path for the encryption key file.  When *None*
        the key is stored next to *db_path* with a ``.key`` suffix.
    """

    def __init__(
        self,
        db_path: str = "~/.phi-redactor/vault.db",
        passphrase: str | None = None,
        key_path: str | Path | None = None,
    ) -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        effective_key_path = (
            Path(key_path) if key_path else self._db_path.with_suffix(".key")
        )

        self._encryption = VaultEncryption(
            key_path=effective_key_path,
            passphrase=passphrase,
        )

        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_db()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create database tables and indexes if they do not exist."""
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id                      TEXT PRIMARY KEY,
                    created_at              TEXT NOT NULL,
                    last_active_at          TEXT NOT NULL,
                    expires_at              TEXT NOT NULL,
                    provider                TEXT NOT NULL,
                    status                  TEXT NOT NULL DEFAULT 'active',
                    date_shift_offset_days  INTEGER NOT NULL,
                    age_shift_offset_years  INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_entries (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id          TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    original_hash       TEXT NOT NULL,
                    original_encrypted  BLOB NOT NULL,
                    synthetic_value     TEXT NOT NULL,
                    phi_category        TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    expires_at          TEXT NOT NULL,
                    UNIQUE(session_id, original_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_vault_session_synthetic
                    ON vault_entries(session_id, synthetic_value);
                """
            )

    # ------------------------------------------------------------------
    # Mapping CRUD
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_original(original: str) -> str:
        """Return the SHA-256 hex digest of *original*."""
        return hashlib.sha256(original.encode("utf-8")).hexdigest()

    def ensure_session(self, session_id: str, provider: str = "unknown") -> None:
        """Create a session row if one does not already exist.

        This is called automatically by :meth:`store_mapping` so that vault
        entries can be stored without requiring the caller to pre-create a
        session via :meth:`create_session`.
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=_DEFAULT_SESSION_LIFETIME_HOURS)
        date_shift = random.randint(-365, 365)
        age_shift = random.randint(-5, 5)

        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO sessions
                    (id, created_at, last_active_at, expires_at, provider,
                     status, date_shift_offset_days, age_shift_offset_years)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now.isoformat(),
                    now.isoformat(),
                    expires.isoformat(),
                    provider,
                    SessionStatus.ACTIVE.value,
                    date_shift,
                    age_shift,
                ),
            )

    def store_mapping(
        self,
        session_id: str,
        original: str,
        synthetic: str,
        category: str,
    ) -> None:
        """Store an original-to-synthetic mapping (deduplicates by hash).

        If a mapping for the same *(session_id, original)* pair already
        exists, the insertion is silently ignored.  The session is
        auto-created if it does not yet exist.
        """
        self.ensure_session(session_id)

        original_hash = self._hash_original(original)
        encrypted = self._encryption.encrypt(original)
        now = datetime.now(timezone.utc).isoformat()
        expires = (
            datetime.now(timezone.utc)
            + timedelta(hours=_DEFAULT_SESSION_LIFETIME_HOURS)
        ).isoformat()

        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO vault_entries
                    (session_id, original_hash, original_encrypted,
                     synthetic_value, phi_category, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, original_hash, encrypted, synthetic, category, now, expires),
            )

    def lookup_by_original(self, session_id: str, original: str) -> str | None:
        """Return the synthetic value for *original* in *session_id*, or None."""
        original_hash = self._hash_original(original)
        row = self._conn.execute(
            """
            SELECT synthetic_value FROM vault_entries
            WHERE session_id = ? AND original_hash = ?
            """,
            (session_id, original_hash),
        ).fetchone()
        return row[0] if row else None

    def lookup_by_synthetic(self, session_id: str, synthetic: str) -> str | None:
        """Decrypt and return the original PHI for a synthetic value, or None."""
        row = self._conn.execute(
            """
            SELECT original_encrypted FROM vault_entries
            WHERE session_id = ? AND synthetic_value = ?
            """,
            (session_id, synthetic),
        ).fetchone()
        if row is None:
            return None
        return self._encryption.decrypt(row[0])

    def get_reverse_map(self, session_id: str) -> dict[str, str]:
        """Return ``{synthetic_value: original_plaintext}`` for all entries in a session.

        Used by :meth:`SemanticMasker.rehydrate` to reverse-map every synthetic
        token back to its original PHI value.
        """
        rows = self._conn.execute(
            """
            SELECT synthetic_value, original_encrypted FROM vault_entries
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchall()
        return {
            synthetic: self._encryption.decrypt(encrypted)
            for synthetic, encrypted in rows
        }

    def get_session_mappings(self, session_id: str) -> list[dict[str, str]]:
        """Return all mappings for a session as a list of dicts.

        Each dict contains ``original``, ``synthetic``, and ``category``.
        """
        rows = self._conn.execute(
            """
            SELECT original_encrypted, synthetic_value, phi_category
            FROM vault_entries WHERE session_id = ?
            """,
            (session_id,),
        ).fetchall()
        return [
            {
                "original": self._encryption.decrypt(encrypted),
                "synthetic": synthetic,
                "category": category,
            }
            for encrypted, synthetic, category in rows
        ]

    def get_session_count(self) -> int:
        """Return the total number of sessions."""
        row = self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
        return row[0] if row else 0

    def get_mapping_count(self, session_id: str | None = None) -> int:
        """Return the number of vault entries, optionally filtered by session."""
        if session_id:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM vault_entries WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM vault_entries").fetchone()
        return row[0] if row else 0

    def export_anonymized(self, session_id: str) -> dict:
        """Return anonymized session statistics without any PHI."""
        mapping_count = self.get_mapping_count(session_id)
        categories = self._conn.execute(
            "SELECT phi_category, COUNT(*) FROM vault_entries WHERE session_id = ? GROUP BY phi_category",
            (session_id,),
        ).fetchall()

        date_range = self._conn.execute(
            "SELECT MIN(created_at), MAX(created_at) FROM vault_entries WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        return {
            "session_id": session_id,
            "total_entries": mapping_count,
            "categories": {cat: count for cat, count in categories},
            "date_range": {"earliest": date_range[0], "latest": date_range[1]} if date_range[0] else None,
        }

    def purge_session(self, session_id: str) -> int:
        """Securely delete all entries and the session itself. Returns entries deleted."""
        with self._conn:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM vault_entries WHERE session_id = ?", (session_id,)
            )
            count = cursor.fetchone()[0]
            self._conn.execute("DELETE FROM vault_entries WHERE session_id = ?", (session_id,))
            self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        return count

    def get_vault_stats(self) -> dict:
        """Return overall vault statistics."""
        import os
        session_count = self.get_session_count()
        entry_count = self.get_mapping_count()
        db_size = os.path.getsize(str(self._db_path)) if self._db_path.exists() else 0
        return {
            "total_sessions": session_count,
            "total_entries": entry_count,
            "database_size_bytes": db_size,
            "database_path": str(self._db_path),
        }

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(self, provider: str = "openai") -> SessionInfo:
        """Create a new vault session and return its metadata."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=_DEFAULT_SESSION_LIFETIME_HOURS)
        date_shift = random.randint(-365, 365)
        age_shift = random.randint(-5, 5)

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO sessions
                    (id, created_at, last_active_at, expires_at, provider,
                     status, date_shift_offset_days, age_shift_offset_years)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now.isoformat(),
                    now.isoformat(),
                    expires.isoformat(),
                    provider,
                    SessionStatus.ACTIVE.value,
                    date_shift,
                    age_shift,
                ),
            )

        return SessionInfo(
            id=session_id,
            created_at=now,
            last_active_at=now,
            expires_at=expires,
            provider=provider,
            status=SessionStatus.ACTIVE,
            date_shift_offset_days=date_shift,
            age_shift_offset_years=age_shift,
        )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Delete expired sessions and their vault entries.

        Returns the number of sessions removed.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:
            # Count before deletion.
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE expires_at < ?",
                (now,),
            )
            count = cursor.fetchone()[0]

            if count > 0:
                # Foreign-key ON DELETE CASCADE removes vault_entries too.
                self._conn.execute(
                    "DELETE FROM sessions WHERE expires_at < ?",
                    (now,),
                )
        return count

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

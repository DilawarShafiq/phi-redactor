"""Integration tests for vault session isolation.

Verifies that:
- Concurrent sessions receive different synthetic values for the same original.
- A session cannot read another session's mappings.
- Expired session entries are removed by cleanup.
- get_reverse_map is scoped to the specified session.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from phi_redactor.vault.store import PhiVault


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault(vault_path: Path, tmp_dir: Path) -> PhiVault:
    """PhiVault backed by a temporary SQLite database."""
    key = tmp_dir / "isolation_test.key"
    v = PhiVault(db_path=str(vault_path), key_path=key)
    yield v
    v.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConcurrentSessionsDifferentMappings:
    def test_concurrent_sessions_different_mappings(self, vault: PhiVault) -> None:
        """Same original PHI stored in two sessions should yield different synthetic values."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        original = "John Smith"
        synthetic_a = "SYNTH_SESSION_A"
        synthetic_b = "SYNTH_SESSION_B"

        vault.store_mapping(session_a.id, original, synthetic_a, "PERSON_NAME")
        vault.store_mapping(session_b.id, original, synthetic_b, "PERSON_NAME")

        result_a = vault.lookup_by_original(session_a.id, original)
        result_b = vault.lookup_by_original(session_b.id, original)

        assert result_a == synthetic_a
        assert result_b == synthetic_b
        assert result_a != result_b

    def test_concurrent_sessions_independent_counts(self, vault: PhiVault) -> None:
        """Mappings stored in one session do not inflate another session's count."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "phi-a-1", "synth-a-1", "PERSON_NAME")
        vault.store_mapping(session_a.id, "phi-a-2", "synth-a-2", "PERSON_NAME")
        vault.store_mapping(session_b.id, "phi-b-1", "synth-b-1", "PERSON_NAME")

        count_a = vault.get_mapping_count(session_a.id)
        count_b = vault.get_mapping_count(session_b.id)

        assert count_a == 2
        assert count_b == 1


class TestSessionCannotAccessOtherSession:
    def test_session_cannot_access_other_session_by_original(
        self, vault: PhiVault
    ) -> None:
        """lookup_by_original for session B must return None for session A's mapping."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "secret-phi", "synth-a", "SSN")

        # Session B must not see session A's data.
        assert vault.lookup_by_original(session_b.id, "secret-phi") is None

    def test_session_cannot_access_other_session_by_synthetic(
        self, vault: PhiVault
    ) -> None:
        """lookup_by_synthetic for session B must return None for session A's mapping."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "phi-value", "synth-a-value", "PHONE_NUMBER")

        # Session B must not be able to reverse-look up session A's synthetic.
        assert vault.lookup_by_synthetic(session_b.id, "synth-a-value") is None

    def test_get_session_mappings_isolated(self, vault: PhiVault) -> None:
        """get_session_mappings must only return entries belonging to the requested session."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "phi-a", "synth-a", "PERSON_NAME")
        vault.store_mapping(session_b.id, "phi-b", "synth-b", "PERSON_NAME")

        mappings_a = vault.get_session_mappings(session_a.id)
        originals_a = [m["original"] for m in mappings_a]

        assert "phi-a" in originals_a
        assert "phi-b" not in originals_a


class TestExpiredSessionEntriesCleaned:
    def test_expired_session_entries_cleaned(self, vault: PhiVault) -> None:
        """Creating a session with an expired time then running cleanup removes all its entries."""
        session = vault.create_session()
        vault.store_mapping(session.id, "old-phi", "old-synth", "PERSON_NAME")

        # Backdate the session's expiry to the past.
        past = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        vault._conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (past, session.id),
        )
        vault._conn.commit()

        removed = vault.cleanup_expired()

        assert removed >= 1
        # The vault entries associated with the expired session are removed by CASCADE.
        assert vault.lookup_by_original(session.id, "old-phi") is None

    def test_active_session_not_cleaned(self, vault: PhiVault) -> None:
        """Active (non-expired) sessions and their entries survive cleanup."""
        session = vault.create_session()
        vault.store_mapping(session.id, "active-phi", "active-synth", "PERSON_NAME")

        removed = vault.cleanup_expired()

        assert removed == 0
        assert vault.lookup_by_original(session.id, "active-phi") == "active-synth"

    def test_mixed_sessions_only_expired_cleaned(self, vault: PhiVault) -> None:
        """Only expired sessions are removed; active sessions survive cleanup."""
        active_session = vault.create_session()
        expired_session = vault.create_session()

        vault.store_mapping(active_session.id, "keep-me", "synth-keep", "PERSON_NAME")
        vault.store_mapping(expired_session.id, "remove-me", "synth-remove", "PERSON_NAME")

        # Expire one session.
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        vault._conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (past, expired_session.id),
        )
        vault._conn.commit()

        removed = vault.cleanup_expired()

        assert removed == 1
        # Active session data intact.
        assert vault.lookup_by_original(active_session.id, "keep-me") == "synth-keep"
        # Expired session data gone.
        assert vault.lookup_by_original(expired_session.id, "remove-me") is None


class TestGetReverseMapScoped:
    def test_get_reverse_map_scoped(self, vault: PhiVault) -> None:
        """get_reverse_map must return only entries belonging to the specified session."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "phi-alpha", "synth-alpha", "PERSON_NAME")
        vault.store_mapping(session_a.id, "phi-beta", "synth-beta", "SSN")
        vault.store_mapping(session_b.id, "phi-gamma", "synth-gamma", "PERSON_NAME")

        reverse_a = vault.get_reverse_map(session_a.id)

        # Session A's reverse map must include both its entries.
        assert "synth-alpha" in reverse_a
        assert reverse_a["synth-alpha"] == "phi-alpha"
        assert "synth-beta" in reverse_a
        assert reverse_a["synth-beta"] == "phi-beta"

        # Session B's entry must NOT appear in session A's reverse map.
        assert "synth-gamma" not in reverse_a

    def test_get_reverse_map_empty_for_empty_session(self, vault: PhiVault) -> None:
        """get_reverse_map for a session with no entries should return an empty dict."""
        session = vault.create_session()
        reverse = vault.get_reverse_map(session.id)
        assert reverse == {}

    def test_get_reverse_map_session_b_only_b(self, vault: PhiVault) -> None:
        """Session B's reverse map must not contain Session A entries."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "phi-only-a", "synth-only-a", "PERSON_NAME")
        vault.store_mapping(session_b.id, "phi-only-b", "synth-only-b", "PERSON_NAME")

        reverse_b = vault.get_reverse_map(session_b.id)

        assert "synth-only-b" in reverse_b
        assert "synth-only-a" not in reverse_b

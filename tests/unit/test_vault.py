"""Unit tests for the PHI vault: encryption, store, session isolation, and dedup.

Covers tasks T019-T022 acceptance criteria:
1. Encryption round-trip (encrypt then decrypt equals original).
2. Vault store and lookup cycle.
3. Session isolation (session A cannot read session B mappings).
4. Deduplication (same original in same session returns same synthetic).
5. Expired session cleanup removes entries.
6. Vault file on disk is not readable as plaintext.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phi_redactor.vault.encryption import VaultEncryption
from phi_redactor.vault.session_map import SessionTokenMap
from phi_redactor.vault.store import PhiVault

# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------


@pytest.fixture
def key_path(tmp_dir: Path) -> Path:
    """Temporary key file path."""
    return tmp_dir / "test.key"


@pytest.fixture
def encryption(key_path: Path) -> VaultEncryption:
    """VaultEncryption instance backed by a temp key file."""
    return VaultEncryption(key_path=key_path)


@pytest.fixture
def vault(vault_path: Path, tmp_dir: Path) -> PhiVault:
    """PhiVault backed by a temp SQLite DB."""
    key = tmp_dir / "vault_test.key"
    v = PhiVault(db_path=str(vault_path), key_path=key)
    yield v
    v.close()


# -----------------------------------------------------------------------
# T020 – Encryption round-trip
# -----------------------------------------------------------------------


class TestVaultEncryption:
    """Tests for VaultEncryption (T020)."""

    def test_encrypt_decrypt_round_trip(self, encryption: VaultEncryption) -> None:
        """Encrypting then decrypting must reproduce the original text."""
        original = "John Smith, SSN 123-45-6789"
        ciphertext = encryption.encrypt(original)
        assert encryption.decrypt(ciphertext) == original

    def test_encrypt_produces_bytes(self, encryption: VaultEncryption) -> None:
        """Ciphertext must be bytes, not str."""
        ct = encryption.encrypt("hello")
        assert isinstance(ct, bytes)

    def test_different_plaintexts_different_ciphertexts(self, encryption: VaultEncryption) -> None:
        """Two different plaintexts should never produce the same ciphertext."""
        ct1 = encryption.encrypt("Alice")
        ct2 = encryption.encrypt("Bob")
        assert ct1 != ct2

    def test_passphrase_derived_key(self, tmp_dir: Path) -> None:
        """A passphrase-derived encryption must also round-trip correctly."""
        kp = tmp_dir / "pass.key"
        enc = VaultEncryption(key_path=kp, passphrase="my-secret-passphrase")
        original = "Sensitive PHI data"
        ct = enc.encrypt(original)
        assert enc.decrypt(ct) == original

    def test_key_rotation(self, encryption: VaultEncryption) -> None:
        """After rotation, old ciphertexts remain decryptable."""
        original = "pre-rotation data"
        old_ct = encryption.encrypt(original)

        encryption.rotate_key()

        # Old ciphertext still decryptable via MultiFernet.
        assert encryption.decrypt(old_ct) == original

        # New encryption still works.
        new_original = "post-rotation data"
        new_ct = encryption.encrypt(new_original)
        assert encryption.decrypt(new_ct) == new_original


# -----------------------------------------------------------------------
# T021 – Vault store and lookup
# -----------------------------------------------------------------------


class TestPhiVaultStoreLookup:
    """Tests for PhiVault store / lookup cycle (T021)."""

    def test_store_and_lookup_by_original(self, vault: PhiVault) -> None:
        """Stored mapping must be retrievable by original text."""
        session = vault.create_session()
        vault.store_mapping(session.id, "John Smith", "SYNTH_NAME_1", "PERSON_NAME")
        result = vault.lookup_by_original(session.id, "John Smith")
        assert result == "SYNTH_NAME_1"

    def test_store_and_lookup_by_synthetic(self, vault: PhiVault) -> None:
        """Stored mapping must be retrievable by synthetic value."""
        session = vault.create_session()
        vault.store_mapping(session.id, "123-45-6789", "XXX-XX-0001", "SSN")
        result = vault.lookup_by_synthetic(session.id, "XXX-XX-0001")
        assert result == "123-45-6789"

    def test_lookup_missing_returns_none(self, vault: PhiVault) -> None:
        """Lookups for non-existent mappings must return None."""
        session = vault.create_session()
        assert vault.lookup_by_original(session.id, "nonexistent") is None
        assert vault.lookup_by_synthetic(session.id, "nonexistent") is None


# -----------------------------------------------------------------------
# T021 – Session isolation
# -----------------------------------------------------------------------


class TestSessionIsolation:
    """Session A must not see session B's mappings (T021)."""

    def test_sessions_are_isolated(self, vault: PhiVault) -> None:
        """A mapping stored under session A is invisible to session B."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "John Smith", "SYNTH_A", "PERSON_NAME")

        assert vault.lookup_by_original(session_a.id, "John Smith") == "SYNTH_A"
        assert vault.lookup_by_original(session_b.id, "John Smith") is None

    def test_reverse_lookup_isolated(self, vault: PhiVault) -> None:
        """Reverse lookup must also be session-scoped."""
        session_a = vault.create_session()
        session_b = vault.create_session()

        vault.store_mapping(session_a.id, "555-1234", "SYNTH_PHONE", "PHONE_NUMBER")

        assert vault.lookup_by_synthetic(session_a.id, "SYNTH_PHONE") == "555-1234"
        assert vault.lookup_by_synthetic(session_b.id, "SYNTH_PHONE") is None


# -----------------------------------------------------------------------
# T021 – Deduplication
# -----------------------------------------------------------------------


class TestDeduplication:
    """Same original in same session must return the same synthetic (T021)."""

    def test_dedup_same_session(self, vault: PhiVault) -> None:
        """Inserting the same original twice in one session is a no-op."""
        session = vault.create_session()
        vault.store_mapping(session.id, "John Smith", "SYNTH_1", "PERSON_NAME")
        # Second insert with different synthetic -- should be ignored (UNIQUE constraint).
        vault.store_mapping(session.id, "John Smith", "SYNTH_2", "PERSON_NAME")

        assert vault.lookup_by_original(session.id, "John Smith") == "SYNTH_1"

    def test_dedup_different_sessions(self, vault: PhiVault) -> None:
        """Same original in different sessions should each have their own mapping."""
        s1 = vault.create_session()
        s2 = vault.create_session()

        vault.store_mapping(s1.id, "John Smith", "SYNTH_S1", "PERSON_NAME")
        vault.store_mapping(s2.id, "John Smith", "SYNTH_S2", "PERSON_NAME")

        assert vault.lookup_by_original(s1.id, "John Smith") == "SYNTH_S1"
        assert vault.lookup_by_original(s2.id, "John Smith") == "SYNTH_S2"


# -----------------------------------------------------------------------
# T021 – Expired session cleanup
# -----------------------------------------------------------------------


class TestCleanupExpired:
    """Cleanup must remove expired sessions and their vault entries (T021)."""

    def test_cleanup_removes_expired(self, vault: PhiVault) -> None:
        """Sessions whose expires_at is in the past should be deleted."""
        session = vault.create_session()
        vault.store_mapping(session.id, "Jane Doe", "SYNTH_J", "PERSON_NAME")

        # Manually backdate the session to make it expired.
        past = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        vault._conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (past, session.id),
        )
        vault._conn.commit()

        removed = vault.cleanup_expired()
        assert removed == 1

        # Mappings should also be gone (CASCADE).
        assert vault.lookup_by_original(session.id, "Jane Doe") is None

    def test_cleanup_keeps_active(self, vault: PhiVault) -> None:
        """Non-expired sessions must survive cleanup."""
        session = vault.create_session()
        vault.store_mapping(session.id, "Active PHI", "SYNTH_ACT", "PERSON_NAME")

        removed = vault.cleanup_expired()
        assert removed == 0
        assert vault.lookup_by_original(session.id, "Active PHI") == "SYNTH_ACT"


# -----------------------------------------------------------------------
# T021 – Vault file not readable as plaintext
# -----------------------------------------------------------------------


class TestDiskEncryption:
    """Verify the on-disk vault does not contain plaintext PHI (T021)."""

    def test_db_file_not_plaintext(self, vault: PhiVault, vault_path: Path) -> None:
        """Raw database bytes must not contain the original PHI strings."""
        session = vault.create_session()
        phi_values = [
            "John Quincy Smith",
            "987-65-4321",
            "john.q.smith@private-hospital.org",
            "(555) 999-8888",
        ]
        for i, phi in enumerate(phi_values):
            vault.store_mapping(session.id, phi, f"SYNTH_{i}", "PERSON_NAME")

        # Force WAL checkpoint so data is in the main DB file.
        vault._conn.execute("PRAGMA wal_checkpoint(FULL)")

        raw = vault_path.read_bytes()
        for phi in phi_values:
            assert phi.encode("utf-8") not in raw, (
                f"Plaintext PHI '{phi}' found in raw database file"
            )


# -----------------------------------------------------------------------
# T022 – SessionTokenMap
# -----------------------------------------------------------------------


class TestSessionTokenMap:
    """Tests for the in-memory cache layer (T022)."""

    def test_get_or_create_caches(self, vault: PhiVault) -> None:
        """First call generates, subsequent calls return cached value."""
        session = vault.create_session()
        token_map = SessionTokenMap(vault)
        call_count = 0

        def generator() -> str:
            nonlocal call_count
            call_count += 1
            return f"GENERATED_{call_count}"

        result1 = token_map.get_or_create_synthetic(
            session.id,
            "John Smith",
            "PERSON_NAME",
            generator,
        )
        result2 = token_map.get_or_create_synthetic(
            session.id,
            "John Smith",
            "PERSON_NAME",
            generator,
        )

        assert result1 == result2 == "GENERATED_1"
        assert call_count == 1  # Generator called only once.

    def test_get_original_reverse_lookup(self, vault: PhiVault) -> None:
        """Reverse lookup must return the original PHI."""
        session = vault.create_session()
        token_map = SessionTokenMap(vault)

        synthetic = token_map.get_or_create_synthetic(
            session.id,
            "123-45-6789",
            "SSN",
            lambda: "SYNTH_SSN_1",
        )
        original = token_map.get_original(session.id, synthetic)
        assert original == "123-45-6789"

    def test_get_original_falls_through_to_vault(self, vault: PhiVault) -> None:
        """A fresh SessionTokenMap should still find vault-persisted mappings."""
        session = vault.create_session()

        # Write directly to vault, bypassing the token map.
        vault.store_mapping(session.id, "Direct Write", "DIRECT_SYNTH", "PERSON_NAME")

        # New token map (empty caches) should fall through to DB.
        token_map = SessionTokenMap(vault)
        assert token_map.get_original(session.id, "DIRECT_SYNTH") == "Direct Write"

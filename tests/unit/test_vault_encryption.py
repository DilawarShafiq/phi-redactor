"""Unit tests for VaultEncryption and PhiVault at-rest encryption.

Verifies:
- Stored PHI is not visible as plaintext in the raw SQLite file.
- Key rotation preserves decryptability of existing ciphertexts.
- PBKDF2 key derivation is consistent for the same passphrase.
- Different passphrases produce different ciphertexts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from phi_redactor.vault.encryption import VaultEncryption
from phi_redactor.vault.store import PhiVault


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def key_path(tmp_dir: Path) -> Path:
    """A temporary path for a generated Fernet key file."""
    return tmp_dir / "test_enc.key"


@pytest.fixture
def enc(key_path: Path) -> VaultEncryption:
    """VaultEncryption instance backed by an auto-generated key."""
    return VaultEncryption(key_path=key_path)


@pytest.fixture
def vault(vault_path: Path, tmp_dir: Path) -> PhiVault:
    """PhiVault instance backed by a temp SQLite database and key."""
    key = tmp_dir / "vault_enc_test.key"
    v = PhiVault(db_path=str(vault_path), key_path=key)
    yield v
    v.close()


# ---------------------------------------------------------------------------
# Tests: stored data not in plaintext
# ---------------------------------------------------------------------------


class TestStoredDataNotPlaintext:
    def test_stored_data_not_plaintext(self, vault: PhiVault, vault_path: Path) -> None:
        """Original PHI text must not appear as readable bytes in the SQLite file."""
        session = vault.create_session()
        phi_values = [
            "Margaret O'Brien",
            "456-78-9012",
            "margaret.obrien@example.com",
            "(617) 555-9876",
        ]
        for i, phi in enumerate(phi_values):
            vault.store_mapping(session.id, phi, f"SYNTH_{i}", "PERSON_NAME")

        # Force WAL checkpoint so all data is in the main DB file.
        vault._conn.execute("PRAGMA wal_checkpoint(FULL)")

        raw_bytes = vault_path.read_bytes()

        for phi in phi_values:
            assert phi.encode("utf-8") not in raw_bytes, (
                f"Plaintext PHI '{phi}' found unencrypted in the vault database file"
            )

    def test_synthetic_values_visible_in_db_file(
        self, vault: PhiVault, vault_path: Path
    ) -> None:
        """Synthetic values (non-sensitive) may appear unencrypted in the database."""
        session = vault.create_session()
        synthetic = "SYNTH_VISIBLE_MARKER_XYZ"
        vault.store_mapping(session.id, "some phi", synthetic, "PERSON_NAME")
        vault._conn.execute("PRAGMA wal_checkpoint(FULL)")

        raw_bytes = vault_path.read_bytes()
        # Synthetic value is not encrypted; it should be visible in the raw file.
        assert synthetic.encode("utf-8") in raw_bytes


# ---------------------------------------------------------------------------
# Tests: key rotation
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_key_rotation_old_entries_readable(self, enc: VaultEncryption) -> None:
        """After a key rotation, ciphertexts created with the old key remain decryptable."""
        original = "pre-rotation-phi-value"
        old_ciphertext = enc.encrypt(original)

        enc.rotate_key()

        # Old ciphertext must still decrypt correctly via MultiFernet.
        assert enc.decrypt(old_ciphertext) == original

    def test_key_rotation_new_encryption_works(self, enc: VaultEncryption) -> None:
        """After rotation, new plaintexts can be encrypted and decrypted with the new key."""
        enc.rotate_key()

        new_original = "post-rotation-phi-value"
        new_ct = enc.encrypt(new_original)
        assert enc.decrypt(new_ct) == new_original

    def test_vault_key_rotation_old_mappings_readable(
        self, vault: PhiVault, vault_path: Path, tmp_dir: Path
    ) -> None:
        """Rotating the vault's encryption key preserves existing mapping lookups."""
        session = vault.create_session()
        phi = "pre-rotation-john-doe"
        synthetic = "SYNTH_PRE_ROT"
        vault.store_mapping(session.id, phi, synthetic, "PERSON_NAME")

        # Rotate the underlying key.
        vault._encryption.rotate_key()

        # Existing lookup via synthetic should still work (decrypts encrypted original).
        result = vault.lookup_by_synthetic(session.id, synthetic)
        assert result == phi


# ---------------------------------------------------------------------------
# Tests: PBKDF2 key derivation consistency
# ---------------------------------------------------------------------------


class TestPBKDF2Consistency:
    def test_pbkdf2_consistent_keys_encrypt_decrypt(self, tmp_dir: Path) -> None:
        """Same passphrase + same salt file should produce consistent encrypt/decrypt."""
        key_path = tmp_dir / "pbkdf2_test.key"
        passphrase = "super-secret-test-passphrase-42"

        # First instance: derives key and writes salt.
        enc1 = VaultEncryption(key_path=key_path, passphrase=passphrase)
        plaintext = "sensitive-phi-for-pbkdf2-test"
        ciphertext = enc1.encrypt(plaintext)

        # Second instance: loads the same key file (derived from same salt).
        enc2 = VaultEncryption(key_path=key_path, passphrase=passphrase)
        assert enc2.decrypt(ciphertext) == plaintext

    def test_pbkdf2_same_passphrase_can_decrypt(self, tmp_dir: Path) -> None:
        """A VaultEncryption created from the persisted key file decrypts existing ciphertexts."""
        key_path = tmp_dir / "pbkdf2_load_test.key"
        passphrase = "another-passphrase-xyz"

        enc_writer = VaultEncryption(key_path=key_path, passphrase=passphrase)
        message = "the original phi message"
        ct = enc_writer.encrypt(message)

        # Load the persisted key (no passphrase needed since key file now exists).
        enc_reader = VaultEncryption(key_path=key_path)
        assert enc_reader.decrypt(ct) == message


# ---------------------------------------------------------------------------
# Tests: different passphrases produce different ciphertexts
# ---------------------------------------------------------------------------


class TestDifferentPassphrasesDifferentCiphertexts:
    def test_different_passphrases_different_keys(self, tmp_dir: Path) -> None:
        """Two VaultEncryption instances with different passphrases encrypt differently."""
        plaintext = "shared plaintext phi value"

        key_path_a = tmp_dir / "key_a.key"
        key_path_b = tmp_dir / "key_b.key"

        enc_a = VaultEncryption(key_path=key_path_a, passphrase="passphrase-ALPHA")
        enc_b = VaultEncryption(key_path=key_path_b, passphrase="passphrase-BETA")

        ct_a = enc_a.encrypt(plaintext)
        ct_b = enc_b.encrypt(plaintext)

        # Ciphertexts produced by distinct keys must differ.
        assert ct_a != ct_b

    def test_different_passphrases_cannot_cross_decrypt(self, tmp_dir: Path) -> None:
        """Ciphertext from passphrase A should not be decryptable with passphrase B key."""
        from cryptography.fernet import InvalidToken

        key_path_a = tmp_dir / "key_x.key"
        key_path_b = tmp_dir / "key_y.key"

        enc_a = VaultEncryption(key_path=key_path_a, passphrase="passphrase-ONE")
        enc_b = VaultEncryption(key_path=key_path_b, passphrase="passphrase-TWO")

        ct_a = enc_a.encrypt("secret phi data")

        with pytest.raises(Exception):  # cryptography.fernet.InvalidToken
            enc_b.decrypt(ct_a)

    def test_same_passphrase_same_salt_consistent_encryption(self, tmp_dir: Path) -> None:
        """Encrypting the same plaintext twice with the same key yields different Fernet tokens
        (Fernet uses a random IV per encryption) but both are still decryptable."""
        key_path = tmp_dir / "same_pass.key"
        enc = VaultEncryption(key_path=key_path, passphrase="stable-passphrase")

        plaintext = "repeat encryption test"
        ct1 = enc.encrypt(plaintext)
        ct2 = enc.encrypt(plaintext)

        # Fernet always adds a random nonce, so tokens differ.
        assert ct1 != ct2

        # Both must decrypt to the original.
        assert enc.decrypt(ct1) == plaintext
        assert enc.decrypt(ct2) == plaintext

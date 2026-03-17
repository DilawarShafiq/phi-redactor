"""Fernet-based encryption for vault entries.

Provides symmetric encryption using the ``cryptography`` library's Fernet
implementation.  Keys can be derived from a passphrase via PBKDF2-HMAC-SHA256
(480 000 iterations) or generated fresh and persisted to disk.  Key rotation is
supported through ``MultiFernet``.
"""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_PBKDF2_ITERATIONS = 480_000
_SALT_LENGTH = 16


class VaultEncryption:
    """Fernet-based encryption for vault entries.

    Construction priority:
    1. If *passphrase* is supplied, derive the key via PBKDF2-HMAC-SHA256.
    2. If a key file already exists at *key_path*, load it.
    3. Otherwise generate a new random Fernet key and save it to *key_path*.

    Parameters
    ----------
    key_path:
        Filesystem path where the key (or salt + key material) is stored.
        Defaults to ``~/.phi-redactor/vault.key``.
    passphrase:
        If provided, the Fernet key is derived deterministically from this
        passphrase plus a random salt (persisted alongside the key).
    """

    def __init__(
        self,
        key_path: str | Path | None = None,
        passphrase: str | None = None,
    ) -> None:
        self._key_path = Path(key_path or "~/.phi-redactor/vault.key").expanduser()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)

        if passphrase is not None:
            self._key, self._salt = self._derive_key_from_passphrase(passphrase)
        elif self._key_path.exists():
            self._key, self._salt = self._load_key()
        else:
            self._key = Fernet.generate_key()
            self._salt = None
            self._save_key()

        self._fernet: Fernet | MultiFernet = Fernet(self._key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt *plaintext* and return the Fernet ciphertext bytes."""
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt *ciphertext* and return the original plaintext string.

        Raises
        ------
        cryptography.fernet.InvalidToken
            If the ciphertext is invalid or the key does not match.
        """
        return self._fernet.decrypt(ciphertext).decode("utf-8")

    def rotate_key(self, new_passphrase: str | None = None) -> None:
        """Rotate to a new key while retaining the ability to decrypt old data.

        After rotation the encryption object uses a ``MultiFernet`` with the
        new key first (for encryption) and the old key second (for decryption
        of legacy ciphertexts).
        """
        old_fernet = Fernet(self._key)

        if new_passphrase is not None:
            new_key, new_salt = self._derive_key_from_passphrase(new_passphrase)
        else:
            new_key = Fernet.generate_key()
            new_salt = None

        self._key = new_key
        self._salt = new_salt
        self._save_key()

        new_fernet = Fernet(new_key)
        self._fernet = MultiFernet([new_fernet, old_fernet])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _derive_key_from_passphrase(self, passphrase: str) -> tuple[bytes, bytes]:
        """Derive a Fernet key from *passphrase* using PBKDF2-HMAC-SHA256.

        If a salt file already exists alongside the key file it is reused;
        otherwise a new random salt is generated and persisted.
        """
        salt_path = self._key_path.with_suffix(".salt")
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = secrets.token_bytes(_SALT_LENGTH)
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            salt_path.write_bytes(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        # Persist key material so that subsequent loads without passphrase work.
        self._key_path.write_bytes(key)
        return key, salt

    def _load_key(self) -> tuple[bytes, bytes | None]:
        """Load an existing key (and optional salt) from disk."""
        key = self._key_path.read_bytes()
        salt_path = self._key_path.with_suffix(".salt")
        salt = salt_path.read_bytes() if salt_path.exists() else None
        return key, salt

    def _save_key(self) -> None:
        """Persist the current key to disk."""
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key_path.write_bytes(self._key)
        if self._salt is not None:
            salt_path = self._key_path.with_suffix(".salt")
            salt_path.write_bytes(self._salt)

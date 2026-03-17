"""Semantic masking engine that replaces detected PHI with clinically coherent fakes.

The :class:`SemanticMasker` uses `Faker <https://faker.readthedocs.io/>`_ to
generate synthetic values that preserve the *structure* and *plausibility* of
the original data while being entirely fictitious.  When an optional
:class:`~phi_redactor.vault.store.PhiVault` is provided, every mapping is
persisted so that:

* the **same** original value within a session always maps to the **same**
  synthetic replacement (consistency); and
* the mapping can later be reversed via :meth:`rehydrate`.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING

from faker import Faker

from phi_redactor.masking.providers import HealthcareFakerProvider
from phi_redactor.models import PHICategory, PHIDetection

if TYPE_CHECKING:
    from phi_redactor.vault.store import PhiVault


class SemanticMasker:
    """Replaces detected PHI with clinically coherent synthetic values.

    Parameters:
        vault: Optional :class:`~phi_redactor.vault.store.PhiVault` instance
            for persistent mapping storage.  When ``None``, mappings are kept
            only in an in-memory dictionary scoped to the masker instance.
    """

    def __init__(self, vault: PhiVault | None = None) -> None:
        self._faker = Faker("en_US")
        self._faker.add_provider(HealthcareFakerProvider)
        self._vault = vault
        # In-memory fallback when no vault is provided: {session_id: {original: synthetic}}
        self._memory: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mask(
        self,
        text: str,
        detections: list[PHIDetection],
        session_id: str,
    ) -> tuple[str, dict[str, str]]:
        """Replace every detected PHI span with a synthetic value.

        Detections are processed in reverse document order so that earlier
        character offsets remain valid after each replacement.

        Args:
            text: The original source text.
            detections: Ordered list of PHI detections to mask.
            session_id: Logical session identifier for vault consistency.

        Returns:
            A ``(masked_text, mapping)`` tuple where *mapping* is
            ``{original_value: synthetic_value}``.
        """
        if not detections:
            return text, {}

        mapping: dict[str, str] = {}
        # Sort by start position descending so replacements don't shift offsets.
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        masked = text
        for det in sorted_detections:
            original = det.original_text or masked[det.start : det.end]

            # 1. Check for an existing mapping (vault or in-memory).
            synthetic = self._lookup(session_id, original)

            # 2. Generate a new synthetic value if not yet mapped.
            if synthetic is None:
                synthetic = self._generate_synthetic(det, session_id)
                self._store(session_id, original, synthetic, det.category)

            mapping[original] = synthetic
            masked = masked[: det.start] + synthetic + masked[det.end :]

        return masked, mapping

    def rehydrate(self, text: str, session_id: str) -> str:
        """Reverse-map all synthetic tokens back to their original PHI values.

        Replacements are applied longest-first to avoid partial-match
        collisions (e.g., replacing ``"Dr. A"`` inside ``"Dr. Adams"``).

        Args:
            text: Text containing synthetic values.
            session_id: Session whose vault mappings should be consulted.

        Returns:
            The text with synthetic tokens replaced by originals.
        """
        reverse_map = self._get_reverse_map(session_id)
        if not reverse_map:
            return text

        # Sort by synthetic value length descending to prevent partial matches.
        sorted_pairs = sorted(reverse_map.items(), key=lambda kv: len(kv[0]), reverse=True)

        result = text
        for synthetic, original in sorted_pairs:
            result = result.replace(synthetic, original)
        return result

    # ------------------------------------------------------------------
    # Synthetic value generation
    # ------------------------------------------------------------------

    def _generate_synthetic(self, detection: PHIDetection, session_id: str) -> str:
        """Produce a category-appropriate fake value.

        A deterministic seed derived from *session_id* and the original text
        ensures that repeated calls for the same input yield the same output
        even before the mapping is persisted to the vault.
        """
        original = detection.original_text
        self._seed_faker(session_id, original)

        category = detection.category

        generators: dict[PHICategory, Callable[[], str]] = {
            PHICategory.PERSON_NAME: self._faker.name,
            PHICategory.SSN: self._faker.ssn,
            PHICategory.PHONE_NUMBER: self._faker.phone_number,
            PHICategory.EMAIL_ADDRESS: self._faker.email,
            PHICategory.DATE: lambda: self._shift_date(original, session_id),
            PHICategory.GEOGRAPHIC_DATA: lambda: f"{self._faker.city()}, {self._faker.state_abbr()}",
            PHICategory.MRN: self._faker.mrn,
            PHICategory.WEB_URL: self._faker.url,
            PHICategory.IP_ADDRESS: self._faker.ipv4,
            PHICategory.ACCOUNT_NUMBER: lambda: f"ACC-{self._faker.numerify('########')}",
            PHICategory.FAX_NUMBER: self._faker.phone_number,
            PHICategory.HEALTH_PLAN_ID: self._faker.health_plan_id,
            PHICategory.LICENSE_NUMBER: lambda: self._faker.numerify("DL-########"),
            PHICategory.VEHICLE_ID: lambda: self._faker.numerify("VIN-#################"),
            PHICategory.DEVICE_ID: self._faker.device_udi,
            PHICategory.BIOMETRIC_ID: lambda: f"BIO-{self._faker.uuid4()[:8]}",
            PHICategory.PHOTO: lambda: "[REDACTED_PHOTO]",
            PHICategory.OTHER_UNIQUE_ID: lambda: f"ID-{self._faker.numerify('########')}",
        }

        generator = generators.get(category)
        if generator is not None:
            return generator()

        # Ultimate fallback for any future categories.
        return f"[REDACTED_{category.value}]"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _seed_faker(self, session_id: str, original_text: str) -> None:
        """Set a deterministic Faker seed from session + original text."""
        digest = hashlib.sha256(f"{session_id}:{original_text}".encode()).hexdigest()
        seed = int(digest[:16], 16)
        self._faker.seed_instance(seed)
        random.seed(seed)

    @staticmethod
    def _shift_date(original_text: str, session_id: str) -> str:
        """Shift a date string by a session-deterministic offset.

        Attempts to parse common date formats.  Falls back to returning a
        Faker-generated date if parsing fails.
        """
        from datetime import datetime

        digest = hashlib.sha256(f"date_shift:{session_id}".encode()).hexdigest()
        shift_days = (int(digest[:8], 16) % 730) - 365  # range [-365, 364]

        formats = [
            "%m/%d/%Y",
            "%Y-%m-%d",
            "%B %d, %Y",
            "%b %d, %Y",
            "%d-%m-%Y",
            "%m-%d-%Y",
        ]
        for fmt in formats:
            try:
                parsed = datetime.strptime(original_text.strip(), fmt)
                shifted = parsed + timedelta(days=shift_days)
                return shifted.strftime(fmt)
            except ValueError:
                continue

        # Could not parse -- return a plausible fake date in the original style.
        fake = Faker("en_US")
        fake.seed_instance(int(digest[:16], 16))
        return fake.date(pattern="%m/%d/%Y")

    def _lookup(self, session_id: str, original: str) -> str | None:
        """Look up an existing mapping for *original* in the given session."""
        if self._vault is not None:
            result = self._vault.lookup_by_original(session_id, original)
            if result is not None:
                return result
        return self._memory.get(session_id, {}).get(original)

    def _store(
        self,
        session_id: str,
        original: str,
        synthetic: str,
        category: PHICategory,
    ) -> None:
        """Persist a mapping to the vault (if available) and in-memory cache."""
        if self._vault is not None:
            self._vault.store_mapping(
                session_id=session_id,
                original=original,
                synthetic=synthetic,
                category=category.value,
            )
        self._memory.setdefault(session_id, {})[original] = synthetic

    def _get_reverse_map(self, session_id: str) -> dict[str, str]:
        """Return ``{synthetic: original}`` for every mapping in the session."""
        reverse: dict[str, str] = {}

        if self._vault is not None:
            vault_map = self._vault.get_reverse_map(session_id)
            if vault_map:
                reverse.update(vault_map)

        # Overlay in-memory mappings (which may be more current).
        for original, synthetic in self._memory.get(session_id, {}).items():
            reverse[synthetic] = original

        return reverse

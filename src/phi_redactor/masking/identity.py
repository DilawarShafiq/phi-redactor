"""Synthetic identity factory for clinically coherent PHI replacement.

Generates complete synthetic identity packages that maintain internal
consistency -- a single patient cluster gets one name, one DOB, one SSN,
etc., ensuring the masked clinical note reads naturally.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from faker import Faker

from phi_redactor.masking.providers import HealthcareFakerProvider
from phi_redactor.models import PHICategory, PHIDetection


@dataclass(frozen=True)
class SyntheticIdentity:
    """A complete synthetic identity for replacing a patient's PHI."""

    name: str
    first_name: str
    last_name: str
    ssn: str
    date_of_birth: str
    phone: str
    fax: str
    email: str
    address: str
    city: str
    state: str
    zip_code: str
    mrn: str
    health_plan_id: str
    account_number: str
    license_number: str
    biometric_id: str


class SyntheticIdentityFactory:
    """Creates deterministic synthetic identities for identity clusters.

    Each ``(session_id, cluster_id)`` pair produces the same identity,
    ensuring consistency across multiple calls within the same session.

    Parameters:
        locale: Faker locale for generating synthetic data.
    """

    def __init__(self, locale: str = "en_US") -> None:
        self._locale = locale
        self._cache: dict[str, SyntheticIdentity] = {}

    def create_identity(
        self, cluster_id: str, session_id: str
    ) -> SyntheticIdentity:
        """Create or retrieve a synthetic identity for a cluster.

        Args:
            cluster_id: Identifier for the identity cluster.
            session_id: Session identifier for deterministic seeding.

        Returns:
            A fully populated :class:`SyntheticIdentity`.
        """
        cache_key = f"{session_id}:{cluster_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        faker = Faker(self._locale)
        faker.add_provider(HealthcareFakerProvider)

        # Deterministic seed from session + cluster
        digest = hashlib.sha256(cache_key.encode()).hexdigest()
        seed = int(digest[:16], 16)
        faker.seed_instance(seed)

        first = faker.first_name()
        last = faker.last_name()

        identity = SyntheticIdentity(
            name=f"{first} {last}",
            first_name=first,
            last_name=last,
            ssn=faker.ssn(),
            date_of_birth=faker.date_of_birth(minimum_age=18, maximum_age=90).strftime("%m/%d/%Y"),
            phone=faker.phone_number(),
            fax=faker.phone_number(),
            email=f"{first.lower()}.{last.lower()}@{faker.free_email_domain()}",
            address=faker.street_address(),
            city=faker.city(),
            state=faker.state_abbr(),
            zip_code=faker.zipcode(),
            mrn=faker.mrn(),
            health_plan_id=faker.health_plan_id(),
            account_number=f"ACC-{faker.numerify('########')}",
            license_number=faker.numerify("DL-########"),
            biometric_id=f"BIO-{faker.uuid4()[:8]}",
        )

        self._cache[cache_key] = identity
        return identity

    def get_replacement(
        self, detection: PHIDetection, identity: SyntheticIdentity
    ) -> str:
        """Get the appropriate replacement value from a synthetic identity.

        Args:
            detection: The detected PHI entity.
            identity: The synthetic identity to draw from.

        Returns:
            The replacement string for the detected entity.
        """
        category = detection.category

        replacements: dict[PHICategory, str] = {
            PHICategory.PERSON_NAME: identity.name,
            PHICategory.SSN: identity.ssn,
            PHICategory.DATE: identity.date_of_birth,
            PHICategory.PHONE_NUMBER: identity.phone,
            PHICategory.FAX_NUMBER: identity.fax,
            PHICategory.EMAIL_ADDRESS: identity.email,
            PHICategory.GEOGRAPHIC_DATA: f"{identity.city}, {identity.state}",
            PHICategory.MRN: identity.mrn,
            PHICategory.HEALTH_PLAN_ID: identity.health_plan_id,
            PHICategory.ACCOUNT_NUMBER: identity.account_number,
            PHICategory.LICENSE_NUMBER: identity.license_number,
            PHICategory.BIOMETRIC_ID: identity.biometric_id,
        }

        return replacements.get(category, f"[REDACTED_{category.value}]")

    def clear_cache(self) -> None:
        """Clear the identity cache."""
        self._cache.clear()

"""phi-redactor: HIPAA-native PHI redaction proxy for AI/LLM interactions."""

from __future__ import annotations

__version__ = "0.1.1"

from phi_redactor.detection.engine import PhiDetectionEngine
from phi_redactor.masking.semantic import SemanticMasker
from phi_redactor.vault.store import PhiVault

__all__ = [
    "PhiDetectionEngine",
    "PhiRedactor",
    "PhiVault",
    "SemanticMasker",
    "__version__",
]


class PhiRedactor:
    """High-level facade for PHI detection, masking, and re-hydration.

    Usage::

        redactor = PhiRedactor()
        result = redactor.redact("Patient John Smith, SSN 123-45-6789...")
        print(result.redacted_text)
        original = redactor.rehydrate(result.redacted_text, result.session_id)
    """

    def __init__(
        self,
        sensitivity: float = 0.5,
        vault_path: str | None = None,
    ) -> None:
        from phi_redactor.config import PhiRedactorConfig

        self._config = PhiRedactorConfig(
            sensitivity=sensitivity,
            **({"vault_path": vault_path} if vault_path else {}),
        )
        self._engine = PhiDetectionEngine(sensitivity=self._config.sensitivity)
        self._vault = PhiVault(db_path=str(self._config.vault_path))
        self._masker = SemanticMasker(vault=self._vault)

    def redact(self, text: str, session_id: str | None = None) -> RedactionResult:
        """Detect and redact PHI from text, returning masked text and metadata."""
        import uuid

        if session_id is None:
            session_id = str(uuid.uuid4())

        detections = self._engine.detect(text, self._config.sensitivity)
        masked_text, mappings = self._masker.mask(text, detections, session_id)

        from phi_redactor.models import RedactionResult

        return RedactionResult(
            redacted_text=masked_text,
            detections=detections,
            session_id=session_id,
            processing_time_ms=0.0,
        )

    def rehydrate(self, text: str, session_id: str) -> str:
        """Replace synthetic tokens back with original PHI values."""
        return self._masker.rehydrate(text, session_id)


# Lazy import to avoid circular dependency
from phi_redactor.models import RedactionResult as RedactionResult

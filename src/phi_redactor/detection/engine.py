"""Core PHI detection engine wrapping Microsoft Presidio.

Provides a high-level ``PhiDetectionEngine`` that initializes Presidio with
spaCy NER and all HIPAA-relevant recognizers, runs analysis on arbitrary text,
and returns results as ``PHIDetection`` model instances.

Usage::

    engine = PhiDetectionEngine(sensitivity=0.5)
    detections = engine.detect("Patient John Smith, SSN 123-45-6789")
    for d in detections:
        print(f"{d.category}: {d.original_text} (confidence={d.confidence:.2f})")
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import TYPE_CHECKING

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from phi_redactor.detection.registry import (
    PRESIDIO_TO_PHI_CATEGORY,
    HIPAARecognizerRegistry,
)
from phi_redactor.models import DetectionMethod, PHIDetection

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult

logger = logging.getLogger(__name__)

_SPACY_MODEL = os.environ.get("PHI_REDACTOR_SPACY_MODEL", "en_core_web_lg")


class PhiDetectionEngine:
    """PHI detection engine wrapping Microsoft Presidio with healthcare-specific recognizers.

    The engine initializes a Presidio ``AnalyzerEngine`` backed by spaCy's
    ``en_core_web_lg`` model for named-entity recognition, plus all built-in
    Presidio pattern recognizers registered via ``HIPAARecognizerRegistry``.

    Args:
        sensitivity: Default detection sensitivity in ``[0.0, 1.0]``.
            Lower values are *more* aggressive (higher confidence threshold).
            A sensitivity of 0.0 requires maximum confidence; 1.0 accepts
            everything.  Default is 0.5.
    """

    def __init__(self, sensitivity: float = 0.5) -> None:
        if not 0.0 <= sensitivity <= 1.0:
            raise ValueError(f"sensitivity must be between 0.0 and 1.0, got {sensitivity}")
        self._sensitivity = sensitivity

        # Ensure spaCy model is available
        self._ensure_spacy_model()

        # Build NLP engine configuration for Presidio
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": _SPACY_MODEL}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

        # Build recognizer registry with all HIPAA-relevant recognizers
        self._hipaa_registry = HIPAARecognizerRegistry()

        # Initialize the Presidio analyzer with our NLP engine and registry
        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=self._hipaa_registry.registry,
        )

        logger.info(
            "PhiDetectionEngine initialized with sensitivity=%.2f, supported categories=%s",
            self._sensitivity,
            [c.value for c in self._hipaa_registry.get_supported_categories()],
        )

    @property
    def sensitivity(self) -> float:
        """Current default sensitivity threshold."""
        return self._sensitivity

    def detect(self, text: str, sensitivity: float | None = None) -> list[PHIDetection]:
        """Run PHI detection on the given text.

        Args:
            text: The input text to analyze for PHI.
            sensitivity: Override the engine's default sensitivity for this call.
                If ``None``, uses the engine's default sensitivity.

        Returns:
            List of ``PHIDetection`` instances sorted by start position, then
            by descending confidence.  Only detections meeting the confidence
            threshold (derived from sensitivity) are returned.
        """
        if not text or not text.strip():
            return []

        effective_sensitivity = sensitivity if sensitivity is not None else self._sensitivity
        if not 0.0 <= effective_sensitivity <= 1.0:
            raise ValueError(
                f"sensitivity must be between 0.0 and 1.0, got {effective_sensitivity}"
            )

        # Confidence threshold: lower sensitivity => higher threshold => fewer detections
        threshold = 1.0 - effective_sensitivity

        # Run Presidio analysis on all supported entity types
        results: list[RecognizerResult] = self._analyzer.analyze(
            text=text,
            language="en",
        )

        # Map to our PHIDetection model and filter by threshold
        detections: list[PHIDetection] = []
        for result in results:
            if result.score < threshold:
                continue
            detection = self._map_presidio_to_phi(result, text)
            if detection is not None:
                detections.append(detection)

        # Sort by position (start asc), then confidence (desc) for stable ordering
        detections.sort(key=lambda d: (d.start, -d.confidence))

        logger.debug(
            "Detected %d PHI entities in %d chars (sensitivity=%.2f, threshold=%.2f)",
            len(detections),
            len(text),
            effective_sensitivity,
            threshold,
        )

        return detections

    def _ensure_spacy_model(self) -> None:
        """Download the spaCy model if it is not already installed.

        Attempts to import the model; if it fails with an ``OSError`` (model
        not found), downloads it via ``spacy download``.
        """
        try:
            import spacy

            spacy.load(_SPACY_MODEL)
            logger.debug("spaCy model '%s' already available", _SPACY_MODEL)
        except OSError:
            logger.info("spaCy model '%s' not found, downloading...", _SPACY_MODEL)
            subprocess.check_call(
                [sys.executable, "-m", "spacy", "download", _SPACY_MODEL],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("spaCy model '%s' downloaded successfully", _SPACY_MODEL)

    def _map_presidio_to_phi(self, result: RecognizerResult, text: str) -> PHIDetection | None:
        """Map a Presidio RecognizerResult to our PHIDetection model.

        Args:
            result: A single Presidio recognizer result.
            text: The original input text (used to extract the matched substring).

        Returns:
            A ``PHIDetection`` instance, or ``None`` if the Presidio entity type
            cannot be mapped to any HIPAA category.
        """
        category = PRESIDIO_TO_PHI_CATEGORY.get(result.entity_type)
        if category is None:
            logger.warning(
                "Unmapped Presidio entity type '%s' at [%d:%d], skipping",
                result.entity_type,
                result.start,
                result.end,
            )
            return None

        # Determine detection method based on recognizer name
        recognizer_name = (
            result.recognition_metadata.get("recognizer_name", "")
            if result.recognition_metadata
            else ""
        )
        method = self._infer_detection_method(recognizer_name)

        original_text = text[result.start : result.end]

        return PHIDetection(
            category=category,
            start=result.start,
            end=result.end,
            confidence=result.score,
            method=method,
            recognizer_name=recognizer_name,
            original_text=original_text,
        )

    @staticmethod
    def _infer_detection_method(recognizer_name: str) -> DetectionMethod:
        """Infer the detection method from the Presidio recognizer name.

        Args:
            recognizer_name: The name of the Presidio recognizer.

        Returns:
            The corresponding ``DetectionMethod`` enum value.
        """
        name_lower = recognizer_name.lower()
        if "spacy" in name_lower or "stanza" in name_lower or "transformers" in name_lower:
            return DetectionMethod.NER
        if "pattern" in name_lower:
            return DetectionMethod.REGEX
        # Default to regex for built-in Presidio recognizers that are pattern-based
        # but may not have "pattern" in their name
        return DetectionMethod.REGEX

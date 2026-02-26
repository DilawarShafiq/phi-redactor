"""Identity clustering for semantically coherent PHI masking.

Groups detected PHI tokens that likely belong to the same individual
using proximity analysis and entity co-reference heuristics, so that
a single synthetic identity can be applied consistently.
"""

from __future__ import annotations

import re
from collections import defaultdict

from phi_redactor.models import PHICategory, PHIDetection

# Categories that are identity-linked (belong to a specific person)
_IDENTITY_CATEGORIES = {
    PHICategory.PERSON_NAME,
    PHICategory.SSN,
    PHICategory.DATE,
    PHICategory.PHONE_NUMBER,
    PHICategory.FAX_NUMBER,
    PHICategory.EMAIL_ADDRESS,
    PHICategory.MRN,
    PHICategory.HEALTH_PLAN_ID,
    PHICategory.ACCOUNT_NUMBER,
    PHICategory.LICENSE_NUMBER,
    PHICategory.BIOMETRIC_ID,
}

# Max character distance to consider two detections part of the same cluster
_PROXIMITY_THRESHOLD = 500

# Sentence boundary pattern
_SENTENCE_BOUNDARY = re.compile(r"[.!?]\s+(?=[A-Z])")


class IdentityClusterer:
    """Groups related PHI detections into identity clusters.

    Tokens within the same sentence or paragraph that include a PERSON_NAME
    anchor are clustered together, assuming they refer to the same individual.
    Detections without a nearby name anchor form singleton clusters.
    """

    def cluster(
        self, detections: list[PHIDetection], text: str
    ) -> dict[str, list[PHIDetection]]:
        """Group detections into identity clusters.

        Args:
            detections: All PHI detections from a single text.
            text: The original source text.

        Returns:
            Dict mapping cluster_id to list of detections in that cluster.
            Cluster IDs are deterministic based on the anchor entity.
        """
        if not detections:
            return {}

        # Split text into sentence spans for proximity grouping
        sentence_spans = self._get_sentence_spans(text)

        # Find name anchors (PERSON_NAME detections)
        name_anchors = [
            d for d in detections if d.category == PHICategory.PERSON_NAME
        ]

        clusters: dict[str, list[PHIDetection]] = {}
        assigned: set[int] = set()  # Track assigned detection indices by (start, end)

        # Build clusters around each name anchor
        for anchor in name_anchors:
            cluster_id = f"identity_{anchor.original_text.lower().replace(' ', '_')}"
            cluster: list[PHIDetection] = [anchor]
            assigned.add(id(anchor))

            anchor_sentence = self._find_sentence(anchor.start, sentence_spans)

            for det in detections:
                if id(det) in assigned:
                    continue
                if det.category not in _IDENTITY_CATEGORIES:
                    continue

                # Same sentence = same cluster
                det_sentence = self._find_sentence(det.start, sentence_spans)
                if det_sentence == anchor_sentence:
                    cluster.append(det)
                    assigned.add(id(det))
                    continue

                # Within proximity threshold
                distance = min(
                    abs(det.start - anchor.end),
                    abs(anchor.start - det.end),
                )
                if distance <= _PROXIMITY_THRESHOLD:
                    cluster.append(det)
                    assigned.add(id(det))

            clusters[cluster_id] = cluster

        # Assign remaining detections to singleton clusters
        for i, det in enumerate(detections):
            if id(det) not in assigned:
                cluster_id = f"singleton_{i}_{det.category.value}"
                clusters[cluster_id] = [det]

        return clusters

    @staticmethod
    def _get_sentence_spans(text: str) -> list[tuple[int, int]]:
        """Split text into (start, end) spans for each sentence."""
        spans: list[tuple[int, int]] = []
        prev_end = 0

        for match in _SENTENCE_BOUNDARY.finditer(text):
            boundary = match.start() + 1  # After the punctuation
            spans.append((prev_end, boundary))
            prev_end = boundary

        # Last sentence
        if prev_end < len(text):
            spans.append((prev_end, len(text)))

        return spans if spans else [(0, len(text))]

    @staticmethod
    def _find_sentence(offset: int, spans: list[tuple[int, int]]) -> int:
        """Return the index of the sentence containing the given offset."""
        for i, (start, end) in enumerate(spans):
            if start <= offset < end:
                return i
        return len(spans) - 1

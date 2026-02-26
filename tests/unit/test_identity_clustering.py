"""Unit tests for IdentityClusterer.

Verifies grouping behaviour under:
- Empty input
- Single name anchor
- Same-sentence co-location
- Multi-patient disambiguation
- Non-identity singleton fallback
- Proximity threshold enforcement
"""

from __future__ import annotations

import pytest

from phi_redactor.masking.clustering import IdentityClusterer, _PROXIMITY_THRESHOLD
from phi_redactor.models import DetectionMethod, PHICategory, PHIDetection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(
    category: PHICategory,
    start: int,
    end: int,
    original_text: str = "",
    confidence: float = 0.9,
) -> PHIDetection:
    """Construct a PHIDetection for testing with sensible defaults."""
    return PHIDetection(
        category=category,
        start=start,
        end=end,
        confidence=confidence,
        method=DetectionMethod.REGEX,
        recognizer_name="test_recognizer",
        original_text=original_text,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clusterer() -> IdentityClusterer:
    return IdentityClusterer()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEmptyInput:
    def test_empty_detections_returns_empty_dict(self, clusterer: IdentityClusterer) -> None:
        """No detections should produce an empty cluster map."""
        result = clusterer.cluster([], "some text")
        assert result == {}


class TestSingleNameAnchor:
    def test_single_name_anchor_creates_one_cluster(
        self, clusterer: IdentityClusterer
    ) -> None:
        """A single PERSON_NAME detection should create exactly one cluster."""
        text = "Patient John Smith was admitted."
        name_det = _make_detection(
            PHICategory.PERSON_NAME, start=8, end=18, original_text="John Smith"
        )

        result = clusterer.cluster([name_det], text)

        assert len(result) == 1
        cluster_id = next(iter(result))
        assert cluster_id.startswith("identity_")
        assert name_det in result[cluster_id]


class TestSameSentenceGrouping:
    def test_same_sentence_groups_together(self, clusterer: IdentityClusterer) -> None:
        """PERSON_NAME and SSN in the same sentence should land in one cluster."""
        text = "Patient John Smith has SSN 456-78-9012 on file."
        name_det = _make_detection(
            PHICategory.PERSON_NAME, start=8, end=18, original_text="John Smith"
        )
        ssn_det = _make_detection(
            PHICategory.SSN, start=27, end=38, original_text="456-78-9012"
        )

        result = clusterer.cluster([name_det, ssn_det], text)

        # Both detections must be in a single cluster.
        assert len(result) == 1
        sole_cluster = next(iter(result.values()))
        assert name_det in sole_cluster
        assert ssn_det in sole_cluster


class TestDifferentPatientsDistinctClusters:
    def test_different_patients_different_clusters(
        self, clusterer: IdentityClusterer
    ) -> None:
        """Two patients separated by well over the proximity threshold get distinct clusters."""
        padding = "x" * ((_PROXIMITY_THRESHOLD * 2) + 100)
        text = f"Patient Alice Brown visited. {padding} Patient Bob Jones visited."

        # Alice at the beginning
        alice_det = _make_detection(
            PHICategory.PERSON_NAME, start=8, end=19, original_text="Alice Brown"
        )
        # Bob far into the text
        bob_start = len("Patient Alice Brown visited. ") + len(padding) + len("Patient ")
        bob_end = bob_start + len("Bob Jones")
        bob_det = _make_detection(
            PHICategory.PERSON_NAME,
            start=bob_start,
            end=bob_end,
            original_text="Bob Jones",
        )

        result = clusterer.cluster([alice_det, bob_det], text)

        # Expect two separate identity clusters.
        assert len(result) == 2
        cluster_ids = list(result.keys())
        assert all(cid.startswith("identity_") for cid in cluster_ids)

        # Each cluster should contain exactly one name.
        all_detections = [det for cluster in result.values() for det in cluster]
        assert alice_det in all_detections
        assert bob_det in all_detections


class TestNonIdentityCategoriesSingletons:
    def test_non_identity_categories_become_singletons(
        self, clusterer: IdentityClusterer
    ) -> None:
        """WEB_URL and IP_ADDRESS are not identity categories; each becomes a singleton."""
        text = "Visit https://example.com from 192.168.1.1."
        url_det = _make_detection(
            PHICategory.WEB_URL, start=6, end=25, original_text="https://example.com"
        )
        ip_det = _make_detection(
            PHICategory.IP_ADDRESS, start=31, end=42, original_text="192.168.1.1"
        )

        result = clusterer.cluster([url_det, ip_det], text)

        # Neither should be absorbed into an identity cluster (no name anchor present).
        singleton_ids = [cid for cid in result if cid.startswith("singleton_")]
        assert len(singleton_ids) == 2

        all_detections = [det for cluster in result.values() for det in cluster]
        assert url_det in all_detections
        assert ip_det in all_detections

    def test_non_identity_not_merged_with_name_anchor(
        self, clusterer: IdentityClusterer
    ) -> None:
        """WEB_URL near a name anchor should NOT be merged into the identity cluster."""
        text = "John Smith uses https://example.com often."
        name_det = _make_detection(
            PHICategory.PERSON_NAME, start=0, end=10, original_text="John Smith"
        )
        url_det = _make_detection(
            PHICategory.WEB_URL, start=17, end=36, original_text="https://example.com"
        )

        result = clusterer.cluster([name_det, url_det], text)

        identity_clusters = {k: v for k, v in result.items() if k.startswith("identity_")}
        # The identity cluster should only contain the name.
        assert len(identity_clusters) == 1
        identity_dets = next(iter(identity_clusters.values()))
        assert url_det not in identity_dets

        # WEB_URL must be a singleton.
        singleton_clusters = {k: v for k, v in result.items() if k.startswith("singleton_")}
        singleton_dets = [det for cluster in singleton_clusters.values() for det in cluster]
        assert url_det in singleton_dets


class TestProximityThreshold:
    def test_proximity_within_threshold_clusters_together(
        self, clusterer: IdentityClusterer
    ) -> None:
        """An identity-category detection within 500 chars of a name anchor is grouped in."""
        # Craft text where name and phone are separated by fewer than _PROXIMITY_THRESHOLD chars,
        # but NOT in the same sentence (so proximity logic applies, not same-sentence logic).
        name_text = "Dr. Carol Reed"
        separator = ". " + ("a" * 100) + ". "  # two sentence boundaries + padding
        phone_text = "(555) 987-6543"
        text = name_text + separator + phone_text

        name_det = _make_detection(
            PHICategory.PERSON_NAME, start=4, end=4 + len("Carol Reed"), original_text="Carol Reed"
        )
        phone_start = len(name_text + separator)
        phone_end = phone_start + len(phone_text)
        phone_det = _make_detection(
            PHICategory.PHONE_NUMBER,
            start=phone_start,
            end=phone_end,
            original_text=phone_text,
        )

        result = clusterer.cluster([name_det, phone_det], text)

        identity_clusters = {k: v for k, v in result.items() if k.startswith("identity_")}
        assert len(identity_clusters) == 1
        identity_dets = next(iter(identity_clusters.values()))
        assert phone_det in identity_dets

    def test_proximity_beyond_threshold_stays_singleton(
        self, clusterer: IdentityClusterer
    ) -> None:
        """A detection placed more than _PROXIMITY_THRESHOLD chars away is NOT clustered."""
        name_text = "Patient Eve Morris"
        # Separate the name from the phone by more than the threshold.
        gap = ". " + ("B" + "b" * 99) * ((_PROXIMITY_THRESHOLD + 200) // 100)
        phone_text = "(555) 111-2222"
        text = name_text + gap + phone_text

        name_det = _make_detection(
            PHICategory.PERSON_NAME, start=8, end=8 + len("Eve Morris"), original_text="Eve Morris"
        )
        phone_start = len(name_text + gap)
        phone_end = phone_start + len(phone_text)
        phone_det = _make_detection(
            PHICategory.PHONE_NUMBER,
            start=phone_start,
            end=phone_end,
            original_text=phone_text,
        )

        result = clusterer.cluster([name_det, phone_det], text)

        identity_clusters = {k: v for k, v in result.items() if k.startswith("identity_")}
        assert len(identity_clusters) == 1
        identity_dets = next(iter(identity_clusters.values()))
        # The phone should NOT be in the identity cluster.
        assert phone_det not in identity_dets

        singleton_clusters = {k: v for k, v in result.items() if k.startswith("singleton_")}
        singleton_dets = [det for cluster in singleton_clusters.values() for det in cluster]
        assert phone_det in singleton_dets

"""Unit tests for the SSE streaming rehydrator.

Tests the StreamRehydrator's ability to buffer and correctly rehydrate
synthetic tokens that may be split across SSE stream chunks.
"""

from __future__ import annotations

import pytest

from phi_redactor.masking.semantic import SemanticMasker
from phi_redactor.models import DetectionMethod, PHICategory, PHIDetection
from phi_redactor.proxy.streaming import StreamRehydrator


@pytest.fixture
def masker():
    """Create a masker without vault for unit testing."""
    return SemanticMasker(vault=None)


@pytest.fixture
def session_id():
    return "test-session-streaming"


@pytest.fixture
def seeded_masker(masker, session_id):
    """Masker pre-seeded with known mappings via a mask() call."""
    text = "Patient John Smith has SSN 123-45-6789"
    detections = [
        PHIDetection(
            category=PHICategory.PERSON_NAME,
            start=8,
            end=18,
            confidence=0.95,
            method=DetectionMethod.NER,
            recognizer_name="test",
            original_text="John Smith",
        ),
        PHIDetection(
            category=PHICategory.SSN,
            start=27,
            end=38,
            confidence=0.99,
            method=DetectionMethod.REGEX,
            recognizer_name="test",
            original_text="123-45-6789",
        ),
    ]
    masker.mask(text, detections, session_id)
    return masker


class TestStreamRehydratorInit:
    """Test StreamRehydrator initialization."""

    def test_creates_with_masker(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker)
        assert rehydrator._buffer == ""
        assert rehydrator._buffer_size == 50

    def test_custom_buffer_size(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=100)
        assert rehydrator._buffer_size == 100

    def test_minimum_buffer_size_is_1(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=0)
        assert rehydrator._buffer_size == 1


class TestStreamRehydratorBuffering:
    """Test the buffering behavior of process_chunk."""

    def test_small_chunk_buffered(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=50)
        result = rehydrator.process_chunk("Hello")
        # Short text should be buffered, not emitted
        assert result == ""

    def test_large_chunk_emitted(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=10)
        result = rehydrator.process_chunk(
            "This is a sufficiently long piece of text to exceed the buffer."
        )
        # Should emit at least some text
        assert len(result) > 0

    def test_flush_returns_remaining_buffer(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=100)
        rehydrator.process_chunk("Hello world")
        result = rehydrator.flush()
        assert "Hello world" in result

    def test_flush_empty_buffer_returns_empty(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker)
        assert rehydrator.flush() == ""

    def test_multiple_chunks_accumulate(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=100)
        rehydrator.process_chunk("Hello ")
        rehydrator.process_chunk("world ")
        rehydrator.process_chunk("foo")
        result = rehydrator.flush()
        assert "Hello" in result
        assert "world" in result


class TestStreamRehydratorWithMappings:
    """Test rehydration with pre-seeded mappings."""

    def test_rehydrates_known_tokens(self, seeded_masker, session_id):
        # Get the synthetic values that were generated
        reverse_map = seeded_masker._get_reverse_map(session_id)
        if not reverse_map:
            pytest.skip("No mappings created")

        rehydrator = StreamRehydrator(
            session_id=session_id,
            masker=seeded_masker,
            buffer_size=5,
        )

        # Feed synthetic tokens one piece at a time
        synthetic_values = list(reverse_map.keys())
        full_text = f"The patient {synthetic_values[0]} was seen."

        # Process in chunks
        output_parts = []
        for i in range(0, len(full_text), 10):
            chunk = full_text[i : i + 10]
            result = rehydrator.process_chunk(chunk)
            if result:
                output_parts.append(result)

        # Flush remaining
        remaining = rehydrator.flush()
        if remaining:
            output_parts.append(remaining)

        full_output = "".join(output_parts)
        # The original value should appear in the rehydrated output
        original_values = list(reverse_map.values())
        assert original_values[0] in full_output


class TestStreamRehydratorEdgeCases:
    """Test edge cases in streaming rehydration."""

    def test_empty_chunks_handled(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker)
        result = rehydrator.process_chunk("")
        assert result == ""

    def test_no_synthetic_tokens_pass_through(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker, buffer_size=5)
        # Plain text with no synthetic tokens
        output = []
        for word in ["This ", "is ", "plain ", "text ", "with ", "no ", "PHI."]:
            result = rehydrator.process_chunk(word)
            if result:
                output.append(result)
        remaining = rehydrator.flush()
        if remaining:
            output.append(remaining)

        full_output = "".join(output)
        assert "This" in full_output
        assert "plain" in full_output
        assert "PHI" in full_output

    def test_flush_clears_buffer(self, masker, session_id):
        rehydrator = StreamRehydrator(session_id=session_id, masker=masker)
        rehydrator.process_chunk("test")
        rehydrator.flush()
        # Second flush should return empty
        assert rehydrator.flush() == ""

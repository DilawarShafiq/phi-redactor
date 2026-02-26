"""SSE streaming re-hydration for proxy responses.

When the upstream LLM returns a Server-Sent Events stream, synthetic tokens
in the response must be replaced with original PHI values before the chunks
reach the caller.  This is non-trivial because a synthetic token can be
split across multiple SSE chunks.

:class:`StreamRehydrator` buffers incoming text and performs rehydration
only when it is safe to emit a prefix that cannot be part of an incomplete
synthetic entity.
"""

from __future__ import annotations

import logging

from phi_redactor.masking.semantic import SemanticMasker

logger = logging.getLogger(__name__)


class StreamRehydrator:
    """Buffers SSE stream chunks and rehydrates synthetic tokens.

    The rehydrator maintains an internal buffer and emits text only when it
    can guarantee that no synthetic token straddles the emit boundary.  The
    strategy is conservative: text is held until the buffer exceeds
    *buffer_size* characters, then the longest safe prefix is emitted.

    Parameters
    ----------
    session_id:
        Session whose vault mappings are used for rehydration.
    masker:
        The :class:`SemanticMasker` instance that performs reverse lookup.
    buffer_size:
        Minimum buffer length before attempting to emit a safe prefix.
        Defaults to 50 characters.
    """

    def __init__(
        self,
        session_id: str,
        masker: SemanticMasker,
        buffer_size: int = 50,
    ) -> None:
        self._session_id = session_id
        self._masker = masker
        self._buffer_size = max(buffer_size, 1)
        self._buffer = ""

        # Build a set of known synthetic values so we can detect partial
        # matches at the buffer boundary.
        self._synthetic_values: list[str] = self._load_synthetic_values()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_chunk(self, text: str) -> str:
        """Append *text* to the buffer and return any safely-emittable output.

        "Safely emittable" means the returned prefix cannot be the start of
        an incomplete synthetic token.

        Args:
            text: New chunk of text from the SSE stream.

        Returns:
            Text that is safe to forward to the caller.  May be empty if
            the buffer has not accumulated enough to determine a safe boundary.
        """
        self._buffer += text

        if len(self._buffer) < self._buffer_size:
            return ""

        # Rehydrate the full buffer.
        rehydrated = self._masker.rehydrate(self._buffer, self._session_id)

        # Determine the safe prefix: we keep a tail of max-synthetic-length
        # characters in case a token is split at the end.
        max_token_len = self._max_synthetic_length()
        if max_token_len == 0:
            # No synthetic tokens -- everything is safe.
            self._buffer = ""
            return rehydrated

        # The tail that might contain an incomplete token.
        keep_len = min(max_token_len, len(rehydrated))
        safe_prefix = rehydrated[: len(rehydrated) - keep_len]
        remainder = rehydrated[len(rehydrated) - keep_len :]

        # The remainder becomes the new buffer (in *original* space so
        # we can re-rehydrate next time).  Since rehydration is idempotent
        # on already-original text this is safe.
        self._buffer = remainder
        return safe_prefix

    def flush(self) -> str:
        """Rehydrate and emit the entire remaining buffer.

        Call this when the stream ends to ensure no text is left behind.

        Returns:
            Any remaining text after rehydration.
        """
        if not self._buffer:
            return ""

        rehydrated = self._masker.rehydrate(self._buffer, self._session_id)
        self._buffer = ""
        return rehydrated

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_synthetic_values(self) -> list[str]:
        """Load the set of synthetic values for this session from the masker."""
        try:
            reverse_map = self._masker._get_reverse_map(self._session_id)
            return list(reverse_map.keys())
        except Exception:
            logger.debug(
                "Could not load synthetic values for session %s",
                self._session_id,
            )
            return []

    def _max_synthetic_length(self) -> int:
        """Return the length of the longest known synthetic value."""
        if not self._synthetic_values:
            return 0
        return max(len(v) for v in self._synthetic_values)

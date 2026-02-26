"""OpenAI API format adapter.

Handles translation between OpenAI's Chat Completions and Embeddings API
wire formats and the internal PHI detection/masking pipeline.

Supports both non-streaming and SSE streaming response formats.
"""

from __future__ import annotations

import copy
import json
import logging

from phi_redactor.proxy.adapters.base import BaseProviderAdapter

logger = logging.getLogger(__name__)

_DEFAULT_OPENAI_BASE_URL = "https://api.openai.com"


class OpenAIAdapter(BaseProviderAdapter):
    """Adapter for the OpenAI Chat Completions / Embeddings API format.

    Handles the ``messages[]`` array in chat completion requests and the
    ``choices[].message.content`` path in responses, including SSE streaming
    with ``choices[].delta.content``.
    """

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def extract_messages(self, body: dict) -> list[str]:
        """Extract text content from ``messages[].content``.

        Handles both simple string content and the multimodal array format
        (``[{"type": "text", "text": "..."}]``).

        Returns:
            Flat list of text strings in document order.
        """
        texts: list[str] = []
        messages = body.get("messages", [])
        for msg in messages:
            content = msg.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                # Multimodal format: [{"type": "text", "text": "..."}, ...]
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_val = part.get("text", "")
                        if text_val:
                            texts.append(text_val)
        return texts

    def inject_messages(self, body: dict, masked: list[str]) -> dict:
        """Replace text in ``messages[].content`` with masked versions.

        Args:
            body: Original request body.
            masked: Masked texts, positionally aligned with :meth:`extract_messages`.

        Returns:
            Deep copy of *body* with text replaced.
        """
        result = copy.deepcopy(body)
        idx = 0
        for msg in result.get("messages", []):
            content = msg.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                if idx < len(masked):
                    msg["content"] = masked[idx]
                    idx += 1
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_val = part.get("text", "")
                        if text_val and idx < len(masked):
                            part["text"] = masked[idx]
                            idx += 1
        return result

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------

    def parse_response_content(self, body: dict) -> str:
        """Extract ``choices[0].message.content`` from a chat completion response.

        Returns an empty string if the path is missing or null.
        """
        try:
            choices = body.get("choices", [])
            if not choices:
                return ""
            message = choices[0].get("message", {})
            content = message.get("content")
            return content if isinstance(content, str) else ""
        except (IndexError, KeyError, TypeError):
            logger.debug("Could not parse response content from body")
            return ""

    def inject_response_content(self, body: dict, text: str) -> dict:
        """Replace ``choices[0].message.content`` with *text*.

        Returns:
            Deep copy of *body* with content replaced.
        """
        result = copy.deepcopy(body)
        try:
            choices = result.get("choices", [])
            if choices:
                message = choices[0].setdefault("message", {})
                message["content"] = text
        except (IndexError, KeyError, TypeError):
            logger.warning("Could not inject response content into body")
        return result

    # ------------------------------------------------------------------
    # Upstream URL and auth
    # ------------------------------------------------------------------

    def get_upstream_url(self, base_url: str, path: str) -> str:
        """Build the upstream OpenAI URL.

        Args:
            base_url: Override base URL, or empty string for default.
            path: The API path (e.g. ``"/v1/chat/completions"``).

        Returns:
            Fully-qualified URL such as
            ``"https://api.openai.com/v1/chat/completions"``.
        """
        effective_base = base_url.rstrip("/") if base_url else _DEFAULT_OPENAI_BASE_URL
        # Ensure path starts with /v1
        if not path.startswith("/v1"):
            path = "/v1" + path
        return f"{effective_base}{path}"

    def get_auth_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        """Forward the ``Authorization`` header to the upstream provider.

        Also forwards ``OpenAI-Organization`` if present.
        """
        headers: dict[str, str] = {}
        auth = request_headers.get("authorization") or request_headers.get("Authorization")
        if auth:
            headers["Authorization"] = auth
        org = (
            request_headers.get("openai-organization")
            or request_headers.get("OpenAI-Organization")
        )
        if org:
            headers["OpenAI-Organization"] = org
        return headers

    # ------------------------------------------------------------------
    # SSE streaming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_stream_chunk(line: str) -> str | None:
        """Parse an SSE ``data:`` line and extract ``choices[0].delta.content``.

        Args:
            line: A single line from the SSE stream (e.g. ``"data: {...}"``).

        Returns:
            The delta content string, or ``None`` if the line is not a
            content-bearing data event.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return None

        payload = stripped[6:]  # Remove "data: " prefix

        if payload == "[DONE]":
            return None

        try:
            data = json.loads(payload)
            choices = data.get("choices", [])
            if not choices:
                return None
            delta = choices[0].get("delta", {})
            content = delta.get("content")
            return content if isinstance(content, str) else None
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            return None

    @staticmethod
    def is_stream_done(line: str) -> bool:
        """Check whether an SSE line signals end-of-stream.

        Args:
            line: A single SSE line.

        Returns:
            ``True`` if the line is ``"data: [DONE]"``.
        """
        return line.strip() == "data: [DONE]"

    @staticmethod
    def inject_stream_chunk(line: str, new_content: str) -> str:
        """Replace ``choices[0].delta.content`` in a streaming SSE data line.

        If the line is not a parseable data event the original line is returned
        unchanged.

        Args:
            line: The original SSE data line.
            new_content: Replacement content string.

        Returns:
            The modified SSE line.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return line

        payload = stripped[6:]
        if payload == "[DONE]":
            return line

        try:
            data = json.loads(payload)
            choices = data.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                if "content" in delta:
                    delta["content"] = new_content
            return f"data: {json.dumps(data)}"
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            return line

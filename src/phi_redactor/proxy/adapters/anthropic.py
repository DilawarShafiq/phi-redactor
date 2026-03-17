"""Anthropic (Claude) API format adapter.

Handles translation between Anthropic's Messages API wire format and the
internal PHI detection/masking pipeline.  Supports both non-streaming and
SSE streaming response formats.

Anthropic API reference: https://docs.anthropic.com/en/api/messages
"""

from __future__ import annotations

import copy
import json
import logging

from phi_redactor.proxy.adapters.base import BaseProviderAdapter

logger = logging.getLogger(__name__)

_DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"


class AnthropicAdapter(BaseProviderAdapter):
    """Adapter for the Anthropic Messages API format.

    Handles the ``messages[]`` array in requests (with ``content`` being
    either a string or a list of content blocks) and the
    ``content[].text`` path in responses.
    """

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def extract_messages(self, body: dict) -> list[str]:
        """Extract text content from Anthropic ``messages[].content``.

        Handles:
        - Simple string content: ``{"role": "user", "content": "Hello"}``
        - Content block arrays: ``{"role": "user", "content": [{"type": "text", "text": "Hello"}]}``
        - System prompt (top-level ``system`` field)

        Returns:
            Flat list of text strings in document order.
        """
        texts: list[str] = []

        # System prompt (Anthropic puts it at the top level, not in messages)
        system = body.get("system")
        if isinstance(system, str) and system:
            texts.append(system)
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_val = block.get("text", "")
                    if text_val:
                        texts.append(text_val)

        # Messages
        for msg in body.get("messages", []):
            content = msg.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_val = block.get("text", "")
                        if text_val:
                            texts.append(text_val)
        return texts

    def inject_messages(self, body: dict, masked: list[str]) -> dict:
        """Replace text in Anthropic request body with masked versions.

        Args:
            body: Original request body.
            masked: Masked texts, positionally aligned with :meth:`extract_messages`.

        Returns:
            Deep copy of *body* with text replaced.
        """
        result = copy.deepcopy(body)
        idx = 0

        # System prompt
        system = result.get("system")
        if isinstance(system, str) and system:
            if idx < len(masked):
                result["system"] = masked[idx]
                idx += 1
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_val = block.get("text", "")
                    if text_val and idx < len(masked):
                        block["text"] = masked[idx]
                        idx += 1

        # Messages
        for msg in result.get("messages", []):
            content = msg.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                if idx < len(masked):
                    msg["content"] = masked[idx]
                    idx += 1
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_val = block.get("text", "")
                        if text_val and idx < len(masked):
                            block["text"] = masked[idx]
                            idx += 1
        return result

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------

    def parse_response_content(self, body: dict) -> str:
        """Extract text from Anthropic response ``content[]`` blocks.

        Anthropic responses contain a ``content`` array of blocks:
        ``[{"type": "text", "text": "..."}]``

        Returns concatenated text from all text blocks.
        """
        try:
            content_blocks = body.get("content", [])
            texts = []
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if text:
                        texts.append(text)
            return "\n".join(texts) if texts else ""
        except (KeyError, TypeError):
            logger.debug("Could not parse Anthropic response content")
            return ""

    def inject_response_content(self, body: dict, text: str) -> dict:
        """Replace text in Anthropic response ``content[]`` blocks.

        Returns:
            Deep copy of *body* with the first text block replaced.
        """
        result = copy.deepcopy(body)
        try:
            content_blocks = result.get("content", [])
            # Replace all text blocks with the rehydrated content
            text_parts = text.split("\n") if "\n" in text else [text]
            part_idx = 0
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    if part_idx < len(text_parts):
                        block["text"] = text_parts[part_idx]
                        part_idx += 1
                    elif part_idx == 0:
                        block["text"] = text
        except (KeyError, TypeError):
            logger.warning("Could not inject Anthropic response content")
        return result

    # ------------------------------------------------------------------
    # Upstream URL and auth
    # ------------------------------------------------------------------

    def get_upstream_url(self, base_url: str, path: str) -> str:
        """Build the upstream Anthropic URL.

        Args:
            base_url: Override base URL, or empty for default.
            path: The API path (e.g. ``"/v1/messages"``).

        Returns:
            Fully-qualified URL such as
            ``"https://api.anthropic.com/v1/messages"``.
        """
        effective_base = base_url.rstrip("/") if base_url else _DEFAULT_ANTHROPIC_BASE_URL
        if not path.startswith("/v1"):
            path = "/v1" + path
        return f"{effective_base}{path}"

    def get_auth_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        """Extract Anthropic authentication headers.

        Anthropic uses ``x-api-key`` for authentication and requires
        ``anthropic-version`` header.
        """
        headers: dict[str, str] = {}

        # API key
        api_key = (
            request_headers.get("x-api-key")
            or request_headers.get("X-Api-Key")
            or request_headers.get("authorization")
            or request_headers.get("Authorization")
        )
        if api_key:
            # Support both x-api-key and Bearer token formats
            if api_key.lower().startswith("bearer "):
                headers["x-api-key"] = api_key[7:]
            else:
                headers["x-api-key"] = api_key

        # Anthropic version
        version = request_headers.get("anthropic-version") or request_headers.get(
            "Anthropic-Version"
        )
        headers["anthropic-version"] = version or "2023-06-01"

        return headers

    # ------------------------------------------------------------------
    # SSE streaming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_stream_chunk(line: str) -> str | None:
        """Parse an Anthropic SSE event and extract text delta.

        Anthropic streaming uses ``content_block_delta`` events:
        ``data: {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "..."}}``

        Returns:
            The delta text string, or ``None`` if not a text event.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return None

        payload = stripped[6:]
        if payload in ("[DONE]", ""):
            return None

        try:
            data = json.loads(payload)
            event_type = data.get("type", "")

            if event_type == "content_block_delta":
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta":
                    return delta.get("text")

            return None
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    @staticmethod
    def is_stream_done(line: str) -> bool:
        """Check whether an SSE line signals end-of-stream.

        Anthropic signals stream end with a ``message_stop`` event.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return False

        payload = stripped[6:]
        if payload == "[DONE]":
            return True

        try:
            data = json.loads(payload)
            return data.get("type") == "message_stop"
        except (json.JSONDecodeError, KeyError, TypeError):
            return False

    @staticmethod
    def inject_stream_chunk(line: str, new_content: str) -> str:
        """Replace text in an Anthropic streaming ``content_block_delta`` event.

        If the line is not a text delta event, returns it unchanged.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return line

        payload = stripped[6:]
        try:
            data = json.loads(payload)
            if data.get("type") == "content_block_delta":
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta":
                    delta["text"] = new_content
            return f"data: {json.dumps(data)}"
        except (json.JSONDecodeError, KeyError, TypeError):
            return line

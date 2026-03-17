"""Google Generative AI (Gemini) adapter.

Translates between Google's Generative AI API wire format and the internal
PHI detection/masking pipeline.  Targets the ``generateContent`` endpoint of
the Google Generative Language API.

Request format::

    {
        "contents": [
            {"role": "user", "parts": [{"text": "Hello"}]},
            {"role": "model", "parts": [{"text": "Hi there"}]}
        ],
        "systemInstruction": {"parts": [{"text": "You are a helpful assistant"}]}
    }

Response format::

    {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "The answer is ..."}],
                    "role": "model"
                }
            }
        ]
    }

Streaming uses Server-Sent Events where each ``data:`` chunk contains a
partial ``generateContent`` response.

Authentication uses the ``x-goog-api-key`` header.
"""

from __future__ import annotations

import copy
import json
import logging

from phi_redactor.proxy.adapters.base import BaseProviderAdapter

logger = logging.getLogger(__name__)

_DEFAULT_GOOGLE_BASE_URL = "https://generativelanguage.googleapis.com"
_DEFAULT_API_VERSION = "v1beta"


class GoogleAdapter(BaseProviderAdapter):
    """Adapter for the Google Generative AI (Gemini) API.

    Handles ``contents[].parts[].text`` in requests and
    ``candidates[0].content.parts[].text`` in responses.
    Also handles the top-level ``systemInstruction`` field.
    """

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def extract_messages(self, body: dict) -> list[str]:
        """Extract text content from ``contents[].parts[].text``.

        Also extracts ``systemInstruction.parts[].text`` if present.

        Returns:
            Flat list of text strings in document order.
        """
        texts: list[str] = []

        # System instruction (top-level field)
        system = body.get("systemInstruction") or body.get("system_instruction")
        if isinstance(system, dict):
            for part in system.get("parts", []):
                if isinstance(part, dict):
                    text_val = part.get("text", "")
                    if text_val:
                        texts.append(text_val)

        # Contents array
        for turn in body.get("contents", []):
            if not isinstance(turn, dict):
                continue
            for part in turn.get("parts", []):
                if isinstance(part, dict):
                    text_val = part.get("text", "")
                    if text_val:
                        texts.append(text_val)

        return texts

    def inject_messages(self, body: dict, masked: list[str]) -> dict:
        """Replace text in ``contents[].parts[].text`` with masked versions.

        Args:
            body: Original request body.
            masked: Masked texts, positionally aligned with :meth:`extract_messages`.

        Returns:
            Deep copy of *body* with text replaced.
        """
        result = copy.deepcopy(body)
        idx = 0

        # System instruction
        system = result.get("systemInstruction") or result.get("system_instruction")
        if isinstance(system, dict):
            for part in system.get("parts", []):
                if isinstance(part, dict) and part.get("text") and idx < len(masked):
                    part["text"] = masked[idx]
                    idx += 1

        # Contents
        for turn in result.get("contents", []):
            if not isinstance(turn, dict):
                continue
            for part in turn.get("parts", []):
                if isinstance(part, dict) and part.get("text") and idx < len(masked):
                    part["text"] = masked[idx]
                    idx += 1

        return result

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------

    def parse_response_content(self, body: dict) -> str:
        """Extract text from ``candidates[0].content.parts[].text``.

        Returns concatenated text from all text parts of the first candidate.
        """
        try:
            candidates = body.get("candidates", [])
            if not candidates:
                return ""
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text")]
            return "\n".join(texts) if texts else ""
        except (IndexError, KeyError, TypeError):
            logger.debug("Could not parse Google response content")
            return ""

    def inject_response_content(self, body: dict, text: str) -> dict:
        """Replace text in ``candidates[0].content.parts[]``.

        Returns:
            Deep copy of *body* with text replaced.
        """
        result = copy.deepcopy(body)
        try:
            candidates = result.get("candidates", [])
            if not candidates:
                return result
            content = candidates[0].setdefault("content", {})
            parts = content.get("parts", [])
            if parts:
                # Replace first text part
                for part in parts:
                    if isinstance(part, dict) and "text" in part:
                        part["text"] = text
                        break
            else:
                content["parts"] = [{"text": text}]
        except (IndexError, KeyError, TypeError):
            logger.warning("Could not inject Google response content")
        return result

    # ------------------------------------------------------------------
    # Upstream URL and auth
    # ------------------------------------------------------------------

    def get_upstream_url(self, base_url: str, path: str) -> str:
        """Build the upstream Google Generative AI URL.

        Google uses the pattern::

            https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent

        The *path* should already contain the model segment, e.g.
        ``"/models/gemini-1.5-pro:generateContent"``.

        Args:
            base_url: Override base URL, or empty for default.
            path: The API path (already includes model and method).

        Returns:
            Fully-qualified Google API URL.
        """
        effective_base = base_url.rstrip("/") if base_url else _DEFAULT_GOOGLE_BASE_URL
        # Strip any /google prefix added by the router
        if path.startswith("/google"):
            path = path[7:]
        # Ensure versioned path
        if not path.startswith(f"/{_DEFAULT_API_VERSION}"):
            path = f"/{_DEFAULT_API_VERSION}{path}"
        return f"{effective_base}{path}"

    def get_auth_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        """Extract Google authentication headers.

        Google Generative AI uses ``x-goog-api-key`` header.
        Also accepts ``Authorization: Bearer`` for compatibility.
        """
        headers: dict[str, str] = {}

        api_key = (
            request_headers.get("x-goog-api-key")
            or request_headers.get("authorization")
            or request_headers.get("Authorization")
        )
        if api_key:
            if api_key.lower().startswith("bearer "):
                api_key = api_key[7:]
            headers["x-goog-api-key"] = api_key

        return headers

    # ------------------------------------------------------------------
    # SSE streaming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_stream_chunk(line: str) -> str | None:
        """Parse a Google SSE chunk and extract text content.

        Google streaming responses send partial ``generateContent`` responses::

            data: {"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}

        Returns:
            The text string, or ``None`` if not a text-bearing chunk.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return None

        payload = stripped[6:]
        if payload in ("[DONE]", ""):
            return None

        try:
            data = json.loads(payload)
            candidates = data.get("candidates", [])
            if not candidates:
                return None
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            texts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text")]
            return "".join(texts) if texts else None
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            return None

    @staticmethod
    def is_stream_done(line: str) -> bool:
        """Check whether a Google SSE line signals end-of-stream."""
        stripped = line.strip()
        if stripped == "data: [DONE]":
            return True
        # Google may signal finish via finishReason
        if not stripped.startswith("data: "):
            return False
        try:
            data = json.loads(stripped[6:])
            candidates = data.get("candidates", [])
            if candidates:
                return bool(candidates[0].get("finishReason"))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        return False

    @staticmethod
    def inject_stream_chunk(line: str, new_content: str) -> str:
        """Replace text in a Google streaming SSE data line.

        If the line is not parseable it is returned unchanged.
        """
        stripped = line.strip()
        if not stripped.startswith("data: "):
            return line

        payload = stripped[6:]
        try:
            data = json.loads(payload)
            candidates = data.get("candidates", [])
            if candidates:
                content = candidates[0].setdefault("content", {})
                parts = content.get("parts", [])
                if parts:
                    for part in parts:
                        if isinstance(part, dict) and "text" in part:
                            part["text"] = new_content
                            break
                else:
                    content["parts"] = [{"text": new_content}]
            return f"data: {json.dumps(data)}"
        except (json.JSONDecodeError, KeyError, TypeError):
            return line

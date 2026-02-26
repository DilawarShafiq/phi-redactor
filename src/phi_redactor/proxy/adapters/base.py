"""Base adapter for LLM provider API format translation.

Each supported LLM provider (OpenAI, Anthropic, etc.) must implement this
interface so the proxy can translate between the provider's wire format and
the internal PHI detection/masking pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseProviderAdapter(ABC):
    """Abstract base class for LLM provider request/response translation.

    Subclasses teach the proxy how to:
    * extract user-supplied text from an inbound request body,
    * inject masked text back into the request before forwarding,
    * parse the upstream LLM's response text, and
    * inject rehydrated text into the response before returning to the caller.
    """

    @abstractmethod
    def extract_messages(self, body: dict) -> list[str]:
        """Extract all user-visible text content from the request body.

        Args:
            body: The parsed JSON request body.

        Returns:
            A flat list of text strings that should be scanned for PHI.
        """
        ...

    @abstractmethod
    def inject_messages(self, body: dict, masked: list[str]) -> dict:
        """Replace user-visible text in the request body with masked versions.

        The *masked* list is positionally aligned with the output of
        :meth:`extract_messages`.

        Args:
            body: The original parsed JSON request body.
            masked: Masked text strings (same order as ``extract_messages``).

        Returns:
            A **new** request body dict with text replaced.
        """
        ...

    @abstractmethod
    def parse_response_content(self, body: dict) -> str:
        """Extract the assistant/model text from an upstream response body.

        Args:
            body: The parsed JSON response body.

        Returns:
            The model-generated text content.
        """
        ...

    @abstractmethod
    def inject_response_content(self, body: dict, text: str) -> dict:
        """Replace the assistant/model text in a response body.

        Args:
            body: The original parsed JSON response body.
            text: The replacement text (e.g., rehydrated content).

        Returns:
            A **new** response body dict with text replaced.
        """
        ...

    @abstractmethod
    def get_upstream_url(self, base_url: str, path: str) -> str:
        """Compute the full upstream URL for a given request path.

        Args:
            base_url: The provider's base URL (e.g. ``"https://api.openai.com"``).
            path: The request path relative to the proxy prefix
                  (e.g. ``"/chat/completions"``).

        Returns:
            The fully-qualified upstream URL.
        """
        ...

    @abstractmethod
    def get_auth_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        """Extract and return authentication headers to forward upstream.

        Args:
            request_headers: All headers from the inbound proxy request.

        Returns:
            A dict of headers to include in the upstream request.
        """
        ...

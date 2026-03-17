"""Azure OpenAI Service adapter.

Azure OpenAI exposes an OpenAI-compatible wire format but requires different
URL construction (resource endpoint + deployment name) and authentication
(``api-key`` header instead of ``Authorization: Bearer``).

Configuration is supplied via environment variables or proxy config:

``AZURE_OPENAI_ENDPOINT``
    The resource endpoint, e.g.
    ``https://my-resource.openai.azure.com``.

``AZURE_OPENAI_API_VERSION``
    The API version, e.g. ``2024-02-01``.  Defaults to ``2024-02-01``.

Clients point their OpenAI SDK at the proxy's ``/azure/v1`` prefix and
include the deployment name in the ``model`` field of the request body,
which the adapter uses to build the upstream URL.
"""

from __future__ import annotations

import logging

from phi_redactor.proxy.adapters.openai import OpenAIAdapter

logger = logging.getLogger(__name__)

_DEFAULT_API_VERSION = "2024-02-01"


class AzureOpenAIAdapter(OpenAIAdapter):
    """Adapter for the Azure OpenAI Service.

    Inherits all request/response parsing from :class:`OpenAIAdapter` since
    Azure OpenAI uses the identical wire format.  Only URL construction and
    authentication differ.

    Args:
        endpoint: Azure resource endpoint, e.g.
            ``"https://my-resource.openai.azure.com"``.  Can also be supplied
            at call time via ``base_url`` in :meth:`get_upstream_url`.
        api_version: Azure REST API version string.  Defaults to
            ``"2024-02-01"``.
    """

    def __init__(
        self,
        endpoint: str = "",
        api_version: str = _DEFAULT_API_VERSION,
    ) -> None:
        self._endpoint = endpoint.rstrip("/") if endpoint else ""
        self._api_version = api_version or _DEFAULT_API_VERSION

    def get_upstream_url(self, base_url: str, path: str) -> str:
        """Build the Azure OpenAI upstream URL for a given deployment.

        Azure OpenAI URLs follow the pattern::

            https://{resource}.openai.azure.com/openai/deployments/{deployment}/{path}?api-version={version}

        The deployment name is expected to be encoded in *path* as the
        ``model`` fragment, e.g. ``"/deployments/gpt-4/chat/completions"``.
        Callers should pass a *path* of the form
        ``"/deployments/{deployment}/chat/completions"`` directly, **or** a
        plain OpenAI-style path (``"/v1/chat/completions"``), in which case
        the deployment is omitted and must be set upstream via the client.

        Args:
            base_url: Azure resource endpoint override.  Falls back to the
                endpoint supplied at construction time.
            path: API path relative to the proxy prefix.

        Returns:
            Fully-qualified Azure OpenAI URL with ``api-version`` query param.
        """
        effective_base = base_url.rstrip("/") if base_url else self._endpoint
        if not effective_base:
            logger.warning(
                "Azure OpenAI endpoint not configured — "
                "set AZURE_OPENAI_ENDPOINT or pass --azure-endpoint"
            )
            effective_base = "https://UNCONFIGURED.openai.azure.com"

        # Normalise path: strip /v1 prefix, then prepend /openai
        normalised = path
        if normalised.startswith("/v1"):
            normalised = normalised[3:]
        if not normalised.startswith("/openai"):
            normalised = "/openai" + normalised

        return f"{effective_base}{normalised}?api-version={self._api_version}"

    def get_auth_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        """Extract Azure OpenAI authentication headers.

        Azure OpenAI accepts the API key via the ``api-key`` header.  This
        method also accepts ``Authorization: Bearer <key>`` and ``x-api-key``
        for compatibility with clients configured for other providers.
        """
        headers: dict[str, str] = {}

        api_key = (
            request_headers.get("api-key")
            or request_headers.get("x-api-key")
            or request_headers.get("authorization")
            or request_headers.get("Authorization")
        )
        if api_key:
            # Normalise Bearer token to raw key
            if api_key.lower().startswith("bearer "):
                api_key = api_key[7:]
            headers["api-key"] = api_key

        return headers

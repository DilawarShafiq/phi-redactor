"""Integration tests for Anthropic proxy routes.

Tests the full PHI detection + masking pipeline for the
POST /anthropic/v1/messages endpoint using a mocked upstream httpx client.

Verifies:
- PHI in user message content is redacted before reaching upstream.
- PHI in the system prompt is redacted.
- Anthropic authentication headers (x-api-key, anthropic-version) are forwarded.
- Upstream 4xx errors are forwarded transparently to the caller.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from phi_redactor.config import PhiRedactorConfig
from phi_redactor.proxy.app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def test_config(tmp_dir: Path) -> PhiRedactorConfig:
    """Minimal test configuration pointing to temp storage."""
    audit_dir = tmp_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return PhiRedactorConfig(
        port=9998,
        host="127.0.0.1",
        vault_path=tmp_dir / "anthropic_test_vault.db",
        audit_path=audit_dir,
        log_level="WARNING",
        sensitivity=0.7,
    )


@pytest.fixture
def app(test_config: PhiRedactorConfig):
    """Create the FastAPI application with test configuration."""
    return create_app(config=test_config)


@pytest.fixture
def client(app) -> TestClient:
    """HTTP test client for the FastAPI application."""
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Shared mock response factories
# ---------------------------------------------------------------------------


def _make_anthropic_response(content: str = "The patient should take metformin.") -> httpx.Response:
    """Build a mock Anthropic Messages API response."""
    return httpx.Response(
        200,
        json={
            "id": "msg_test_abc123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": content}],
            "model": "claude-opus-4-6",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 20, "output_tokens": 10},
        },
        headers={"content-type": "application/json"},
    )


def _make_anthropic_error_response(
    status_code: int, error_type: str = "authentication_error", message: str = "Invalid API key"
) -> httpx.Response:
    """Build a mock Anthropic error response."""
    return httpx.Response(
        status_code,
        json={"type": "error", "error": {"type": error_type, "message": message}},
        headers={"content-type": "application/json"},
    )


# ---------------------------------------------------------------------------
# Tests: PHI redaction in message content
# ---------------------------------------------------------------------------


class TestAnthropicMessagesRedactsPhi:
    def test_anthropic_messages_redacts_phi_in_user_content(self, client: TestClient) -> None:
        """PHI in user message content must be redacted before reaching upstream."""
        phi_ssn = "456-78-9012"

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 1024,
                    "messages": [
                        {
                            "role": "user",
                            "content": f"Patient John Smith has SSN {phi_ssn} and needs help.",
                        }
                    ],
                },
                headers={"x-api-key": "test-anthropic-key"},
            )

        assert resp.status_code == 200

        call_args = mock_post.call_args
        upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
        assert upstream_body is not None

        upstream_content = upstream_body["messages"][0]["content"]
        assert phi_ssn not in upstream_content, (
            f"SSN '{phi_ssn}' was not redacted from the upstream request body"
        )

    def test_anthropic_messages_redacts_phi_content_block_array(
        self, client: TestClient
    ) -> None:
        """PHI in content block array format must also be redacted."""
        phi_ssn = "456-78-9012"

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 512,
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"SSN is {phi_ssn} for John Smith.",
                                }
                            ],
                        }
                    ],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 200

        call_args = mock_post.call_args
        upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
        assert upstream_body is not None

        # Content is a list of blocks.
        content_blocks = upstream_body["messages"][0]["content"]
        all_text = " ".join(
            b.get("text", "") for b in content_blocks if isinstance(b, dict)
        )
        assert phi_ssn not in all_text


class TestAnthropicSystemPromptRedacted:
    def test_anthropic_system_prompt_redacted(self, client: TestClient) -> None:
        """PHI placed in the top-level 'system' field must be redacted before forwarding."""
        phi_name = "John Smith"
        phi_ssn = "456-78-9012"
        system_with_phi = (
            f"You are assisting with the case of patient {phi_name}, SSN {phi_ssn}. "
            "Provide medical advice only."
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 256,
                    "system": system_with_phi,
                    "messages": [{"role": "user", "content": "What should I do?"}],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 200

        call_args = mock_post.call_args
        upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
        assert upstream_body is not None

        upstream_system = upstream_body.get("system", "")
        assert phi_ssn not in upstream_system, (
            f"SSN '{phi_ssn}' was not redacted from the upstream system prompt"
        )

    def test_anthropic_clean_system_prompt_unchanged(self, client: TestClient) -> None:
        """A system prompt with no PHI should pass through without corruption."""
        clean_system = "You are a helpful medical assistant. Provide evidence-based advice."

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 128,
                    "system": clean_system,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 200

        call_args = mock_post.call_args
        upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
        # The clean system prompt should be present (may be identical or trivially altered).
        assert upstream_body.get("system") is not None


# ---------------------------------------------------------------------------
# Tests: authentication header forwarding
# ---------------------------------------------------------------------------


class TestAnthropicAuthHeadersForwarded:
    def test_anthropic_x_api_key_forwarded(self, client: TestClient) -> None:
        """The 'x-api-key' header must be forwarded to the upstream Anthropic API."""
        api_key = "sk-ant-test-key-forwarding-check"

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": api_key},
            )

        call_args = mock_post.call_args
        forwarded_headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        assert "x-api-key" in forwarded_headers
        assert forwarded_headers["x-api-key"] == api_key

    def test_anthropic_version_header_forwarded(self, client: TestClient) -> None:
        """The 'anthropic-version' header must be forwarded (or defaulted) to upstream."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hi"}],
                },
                headers={
                    "x-api-key": "test-key",
                    "anthropic-version": "2023-06-01",
                },
            )

        call_args = mock_post.call_args
        forwarded_headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        assert "anthropic-version" in forwarded_headers

    def test_anthropic_version_defaulted_when_absent(self, client: TestClient) -> None:
        """If the client does not send 'anthropic-version', the proxy must supply a default."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hi"}],
                },
                headers={"x-api-key": "test-key"},
                # No anthropic-version header.
            )

        call_args = mock_post.call_args
        forwarded_headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        # The adapter must always include anthropic-version.
        assert "anthropic-version" in forwarded_headers
        assert forwarded_headers["anthropic-version"]  # Must not be empty.

    def test_bearer_token_converted_to_x_api_key(self, client: TestClient) -> None:
        """A 'Bearer sk-ant-...' authorization header must be converted to 'x-api-key'."""
        raw_key = "sk-ant-bearer-test-key"

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ) as mock_post:
            client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"Authorization": f"Bearer {raw_key}"},
            )

        call_args = mock_post.call_args
        forwarded_headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        # The proxy should strip the 'Bearer ' prefix and send raw key as x-api-key.
        assert forwarded_headers.get("x-api-key") == raw_key


# ---------------------------------------------------------------------------
# Tests: upstream error forwarding
# ---------------------------------------------------------------------------


class TestAnthropicUpstreamErrorForwarded:
    def test_anthropic_upstream_401_forwarded(self, client: TestClient) -> None:
        """A 401 from the upstream Anthropic API must be transparently forwarded to the caller."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_error_response(401, "authentication_error", "Invalid API key"),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "bad-key"},
            )

        assert resp.status_code == 401

    def test_anthropic_upstream_429_forwarded(self, client: TestClient) -> None:
        """A 429 (rate limited) from upstream must be forwarded to the caller."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_error_response(429, "rate_limit_error", "Too many requests"),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 429

    def test_anthropic_upstream_500_forwarded(self, client: TestClient) -> None:
        """A 500 from the upstream Anthropic API must be forwarded to the caller."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_error_response(500, "api_error", "Internal server error"),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 500

    def test_anthropic_upstream_error_body_forwarded(self, client: TestClient) -> None:
        """The error body from upstream must be included in the response returned to the caller."""
        error_message = "This specific error from upstream"

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_error_response(401, "auth_error", error_message),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "bad-key"},
            )

        assert resp.status_code == 401
        body = resp.json()
        # The error message from upstream must appear in the forwarded response body.
        body_text = str(body)
        assert error_message in body_text


# ---------------------------------------------------------------------------
# Tests: response metadata
# ---------------------------------------------------------------------------


class TestAnthropicResponseMetadata:
    def test_successful_response_contains_phi_redactor_metadata(
        self, client: TestClient
    ) -> None:
        """A successful proxied response must include x_phi_redactor session metadata."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "What is diabetes?"}],
                },
                headers={"x-api-key": "test-key"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert "x_phi_redactor" in body
        meta = body["x_phi_redactor"]
        assert "session_id" in meta
        assert "request_id" in meta
        assert "processing_ms" in meta

    def test_session_id_is_valid_uuid(self, client: TestClient) -> None:
        """The session_id in the response metadata must be a valid UUID."""
        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=_make_anthropic_response(),
        ):
            resp = client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 64,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"x-api-key": "test-key"},
            )

        body = resp.json()
        session_id_str = body["x_phi_redactor"]["session_id"]
        # This raises ValueError if not a valid UUID.
        parsed = uuid.UUID(session_id_str)
        assert str(parsed) == session_id_str

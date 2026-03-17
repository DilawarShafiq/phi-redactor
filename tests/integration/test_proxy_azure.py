"""Integration tests for the Azure OpenAI proxy round-trip flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from phi_redactor.config import PhiRedactorConfig
from phi_redactor.proxy.app import create_app


@pytest.fixture
def test_config(tmp_dir):
    return PhiRedactorConfig(
        port=9998,
        host="127.0.0.1",
        vault_path=tmp_dir / "vault.db",
        audit_path=tmp_dir / "audit",
        log_level="WARNING",
        sensitivity=0.7,
    )


@pytest.fixture
def app(test_config):
    return create_app(config=test_config)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


class TestAzureAdapter:
    """Unit tests for AzureOpenAIAdapter."""

    def test_get_auth_headers_api_key(self):
        from phi_redactor.proxy.adapters.azure import AzureOpenAIAdapter

        adapter = AzureOpenAIAdapter()
        headers = adapter.get_auth_headers({"api-key": "my-azure-key"})
        assert headers["api-key"] == "my-azure-key"

    def test_get_auth_headers_bearer(self):
        from phi_redactor.proxy.adapters.azure import AzureOpenAIAdapter

        adapter = AzureOpenAIAdapter()
        headers = adapter.get_auth_headers({"authorization": "Bearer my-key"})
        assert headers["api-key"] == "my-key"

    def test_get_upstream_url_with_deployment(self):
        from phi_redactor.proxy.adapters.azure import AzureOpenAIAdapter

        adapter = AzureOpenAIAdapter(
            endpoint="https://my-resource.openai.azure.com",
            api_version="2024-02-01",
        )
        url = adapter.get_upstream_url("", "/v1/chat/completions")
        assert "my-resource.openai.azure.com" in url
        assert "api-version=2024-02-01" in url
        assert "openai" in url

    def test_extract_and_inject_messages(self):
        from phi_redactor.proxy.adapters.azure import AzureOpenAIAdapter

        adapter = AzureOpenAIAdapter()
        body = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Patient John Smith SSN 123-45-6789"}],
        }
        texts = adapter.extract_messages(body)
        assert len(texts) == 1
        assert "John Smith" in texts[0]

        masked_body = adapter.inject_messages(body, ["Patient [NAME] SSN [SSN]"])
        assert masked_body["messages"][0]["content"] == "Patient [NAME] SSN [SSN]"


class TestAzureProxyRoute:
    """Test the Azure proxy endpoint with mocked upstream."""

    def test_azure_chat_redacts_phi(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "id": "chatcmpl-azure-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Understood."},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            resp = client.post(
                "/azure/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Patient Jane Doe SSN 987-65-4321."}],
                },
                headers={"api-key": "test-azure-key"},
            )

            assert resp.status_code == 200

            call_args = mock_post.call_args
            upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
            if upstream_body:
                upstream_content = upstream_body["messages"][0]["content"]
                assert "987-65-4321" not in upstream_content

    def test_azure_chat_metadata(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello!"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            resp = client.post(
                "/azure/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"api-key": "test-key"},
            )

            body = resp.json()
            assert "x_phi_redactor" in body
            assert body["x_phi_redactor"]["provider"] == "azure"

    def test_azure_upstream_error_forwarded(self, client):
        mock_response = httpx.Response(
            401,
            json={"error": {"message": "Invalid API key"}},
            headers={"content-type": "application/json"},
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            resp = client.post(
                "/azure/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"api-key": "bad-key"},
            )
            assert resp.status_code == 401

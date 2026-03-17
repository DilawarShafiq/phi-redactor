"""Integration tests for the Google Gemini proxy round-trip flow."""

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
        port=9997,
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


class TestGoogleAdapter:
    """Unit tests for GoogleAdapter."""

    def test_extract_messages_contents(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": "Patient John Smith SSN 123-45-6789"}]}
            ]
        }
        texts = adapter.extract_messages(body)
        assert len(texts) == 1
        assert "John Smith" in texts[0]

    def test_extract_messages_system_instruction(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        body = {
            "systemInstruction": {"parts": [{"text": "You are a helpful medical assistant."}]},
            "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
        }
        texts = adapter.extract_messages(body)
        assert len(texts) == 2
        assert "medical assistant" in texts[0]

    def test_inject_messages(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        body = {
            "contents": [{"role": "user", "parts": [{"text": "Patient Jane Doe DOB 01/01/1980"}]}]
        }
        masked = adapter.inject_messages(body, ["Patient [NAME] DOB [DATE]"])
        assert masked["contents"][0]["parts"][0]["text"] == "Patient [NAME] DOB [DATE]"

    def test_parse_response_content(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        body = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "The patient should take metformin."}],
                        "role": "model",
                    }
                }
            ]
        }
        text = adapter.parse_response_content(body)
        assert "metformin" in text

    def test_inject_response_content(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        body = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "Original [NAME]"}],
                        "role": "model",
                    }
                }
            ]
        }
        result = adapter.inject_response_content(body, "Restored John Smith")
        assert result["candidates"][0]["content"]["parts"][0]["text"] == "Restored John Smith"

    def test_get_auth_headers(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        headers = adapter.get_auth_headers({"x-goog-api-key": "my-google-key"})
        assert headers["x-goog-api-key"] == "my-google-key"

    def test_get_auth_headers_bearer(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        adapter = GoogleAdapter()
        headers = adapter.get_auth_headers({"authorization": "Bearer my-key"})
        assert headers["x-goog-api-key"] == "my-key"

    def test_parse_stream_chunk(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        line = (
            'data: {"candidates": [{"content": {"parts": [{"text": "Hello"}], "role": "model"}}]}'
        )
        result = GoogleAdapter.parse_stream_chunk(line)
        assert result == "Hello"

    def test_inject_stream_chunk(self):
        from phi_redactor.proxy.adapters.google import GoogleAdapter

        line = (
            'data: {"candidates": [{"content": {"parts": [{"text": "[NAME]"}], "role": "model"}}]}'
        )
        result = GoogleAdapter.inject_stream_chunk(line, "John Smith")
        assert "John Smith" in result


class TestGoogleProxyRoute:
    """Test the Google proxy endpoint with mocked upstream."""

    def test_google_generate_content_redacts_phi(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": "I understand."}],
                            "role": "model",
                        },
                        "finishReason": "STOP",
                    }
                ]
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            resp = client.post(
                "/google/v1beta/models/gemini-1.5-pro:generateContent",
                json={
                    "contents": [
                        {
                            "role": "user",
                            "parts": [{"text": "Patient Jane Doe SSN 987-65-4321 was admitted."}],
                        }
                    ]
                },
                headers={"x-goog-api-key": "test-google-key"},
            )

            assert resp.status_code == 200

            call_args = mock_post.call_args
            upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
            if upstream_body:
                upstream_text = upstream_body["contents"][0]["parts"][0]["text"]
                assert "987-65-4321" not in upstream_text

    def test_google_response_metadata(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": "Hello!"}], "role": "model"},
                        "finishReason": "STOP",
                    }
                ]
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            resp = client.post(
                "/google/v1beta/models/gemini-1.5-pro:generateContent",
                json={"contents": [{"role": "user", "parts": [{"text": "Hello"}]}]},
                headers={"x-goog-api-key": "test-key"},
            )

            body = resp.json()
            assert "x_phi_redactor" in body
            assert body["x_phi_redactor"]["provider"] == "google"

    def test_google_upstream_error_forwarded(self, client):
        mock_response = httpx.Response(
            403,
            json={"error": {"message": "API key not valid"}},
            headers={"content-type": "application/json"},
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            resp = client.post(
                "/google/v1beta/models/gemini-1.5-pro:generateContent",
                json={"contents": [{"role": "user", "parts": [{"text": "Hello"}]}]},
                headers={"x-goog-api-key": "bad-key"},
            )
            assert resp.status_code == 403

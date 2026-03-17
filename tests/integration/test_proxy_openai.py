"""Integration tests for the OpenAI proxy round-trip flow.

Tests the full redact -> forward -> rehydrate pipeline using a mocked
upstream OpenAI API.  Validates that PHI is stripped from outbound requests
and restored in inbound responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from phi_redactor.config import PhiRedactorConfig
from phi_redactor.proxy.app import create_app


@pytest.fixture
def test_config(tmp_dir):
    """Create a test configuration with temporary paths."""
    return PhiRedactorConfig(
        port=9999,
        host="127.0.0.1",
        vault_path=tmp_dir / "vault.db",
        audit_path=tmp_dir / "audit",
        log_level="WARNING",
        sensitivity=0.7,
    )


@pytest.fixture
def app(test_config):
    """Create the FastAPI app with test config."""
    application = create_app(config=test_config)
    return application


@pytest.fixture
def client(app):
    """Create a test client."""
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    """Verify the management health endpoint works through the full app."""

    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body
        assert "uptime_seconds" in body

    def test_health_shows_providers(self, client):
        resp = client.get("/api/v1/health")
        body = resp.json()
        assert "openai" in body["providers"]


class TestLibraryRedactEndpoint:
    """Test the /api/v1/redact library endpoint through the full app stack."""

    def test_redact_detects_phi(self, client):
        resp = client.post(
            "/api/v1/redact",
            json={"text": "Patient John Smith SSN 456-78-9012 was admitted."},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "redacted_text" in body
        assert "session_id" in body
        # The original SSN should not appear in the redacted text
        assert "456-78-9012" not in body["redacted_text"]
        assert len(body["detections"]) > 0

    def test_redact_preserves_non_phi(self, client):
        resp = client.post(
            "/api/v1/redact",
            json={
                "text": "Metformin 1000mg BID for Type 2 Diabetes Mellitus.",
                "sensitivity": 0.5,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        # Clinical terms should not be redacted
        assert "Metformin" in body["redacted_text"] or "metformin" in body["redacted_text"].lower()

    def test_redact_session_consistency(self, client):
        """Same PHI in same session should produce the same synthetic value."""
        text = "Dr. John Smith prescribed medication."
        resp1 = client.post("/api/v1/redact", json={"text": text})
        session_id = resp1.json()["session_id"]

        resp2 = client.post(
            "/api/v1/redact",
            json={"text": text, "session_id": session_id},
        )
        # Same session -> same redacted output
        assert resp1.json()["redacted_text"] == resp2.json()["redacted_text"]


class TestLibraryRehydrateEndpoint:
    """Test the /api/v1/rehydrate endpoint round-trip."""

    def test_redact_then_rehydrate(self, client):
        original = "Patient Jane Doe SSN 987-65-4321 seen on 01/15/2026."
        # Step 1: Redact
        redact_resp = client.post("/api/v1/redact", json={"text": original})
        assert redact_resp.status_code == 200
        redacted = redact_resp.json()
        session_id = redacted["session_id"]
        redacted_text = redacted["redacted_text"]

        # Verify PHI is gone
        assert "Jane Doe" not in redacted_text
        assert "987-65-4321" not in redacted_text

        # Step 2: Rehydrate
        rehydrate_resp = client.post(
            "/api/v1/rehydrate",
            json={"text": redacted_text, "session_id": session_id},
        )
        assert rehydrate_resp.status_code == 200
        restored = rehydrate_resp.json()["text"]

        # Original PHI should be restored
        assert "Jane Doe" in restored or "987-65-4321" in restored


class TestProxyChatCompletions:
    """Test the OpenAI proxy chat completions endpoint with mocked upstream."""

    def test_non_streaming_chat_redacts_phi(self, client):
        """Verify PHI is redacted before reaching upstream."""
        mock_response = httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "The patient should take metformin.",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            resp = client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "user",
                            "content": "Patient John Smith SSN 456-78-9012 has diabetes.",
                        }
                    ],
                },
                headers={"Authorization": "Bearer test-key"},
            )

            assert resp.status_code == 200

            # Check that the upstream request had PHI redacted
            call_args = mock_post.call_args
            upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
            if upstream_body:
                upstream_content = upstream_body["messages"][0]["content"]
                assert "456-78-9012" not in upstream_content

    def test_chat_returns_session_metadata(self, client):
        """Verify proxy metadata is included in the response."""
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
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"Authorization": "Bearer test-key"},
            )

            body = resp.json()
            assert "x_phi_redactor" in body
            assert "session_id" in body["x_phi_redactor"]
            assert "request_id" in body["x_phi_redactor"]
            assert "processing_ms" in body["x_phi_redactor"]

    def test_chat_upstream_error_forwarded(self, client):
        """Verify upstream errors are forwarded to the caller."""
        mock_response = httpx.Response(
            401,
            json={"error": {"message": "Invalid API key", "type": "invalid_request_error"}},
            headers={"content-type": "application/json"},
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            resp = client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
                headers={"Authorization": "Bearer bad-key"},
            )

            assert resp.status_code == 401


class TestProxyEmbeddings:
    """Test the embeddings endpoint."""

    def test_embeddings_redacts_phi(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
                "usage": {"prompt_tokens": 5, "total_tokens": 5},
            },
        )

        with patch.object(
            client.app.state.http_client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            resp = client.post(
                "/v1/embeddings",
                json={
                    "model": "text-embedding-3-small",
                    "input": "Patient John Smith SSN 456-78-9012",
                },
                headers={"Authorization": "Bearer test-key"},
            )

            assert resp.status_code == 200

            call_args = mock_post.call_args
            upstream_body = call_args.kwargs.get("json") or call_args[1].get("json")
            if upstream_body:
                assert "456-78-9012" not in upstream_body["input"]


class TestSessionManagement:
    """Test session lifecycle through the management API."""

    def test_list_sessions_empty(self, client):
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200
        body = resp.json()
        assert "count" in body
        assert "sessions" in body

    def test_session_created_on_redact(self, client):
        client.post("/api/v1/redact", json={"text": "John Smith called at 555-123-4567."})
        resp = client.get("/api/v1/sessions")
        body = resp.json()
        assert body["count"] >= 1

    def test_close_session(self, client):
        # Create a session via redaction
        redact_resp = client.post("/api/v1/redact", json={"text": "SSN 456-78-9012"})
        session_id = redact_resp.json()["session_id"]

        # Close it
        close_resp = client.delete(f"/api/v1/sessions/{session_id}")
        assert close_resp.status_code == 200
        assert close_resp.json()["status"] == "closed"


class TestAuditTrailEndpoint:
    """Test the audit query endpoint."""

    def test_audit_trail_populated_after_redaction(self, client):
        client.post("/api/v1/redact", json={"text": "Patient John Smith SSN 456-78-9012."})
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] > 0
        assert len(body["events"]) > 0

    def test_audit_filter_by_session(self, client):
        redact_resp = client.post("/api/v1/redact", json={"text": "SSN 456-78-9012"})
        session_id = redact_resp.json()["session_id"]

        resp = client.get(f"/api/v1/audit?session_id={session_id}")
        assert resp.status_code == 200
        body = resp.json()
        for event in body["events"]:
            assert event["session_id"] == session_id

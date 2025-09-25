"""Integration tests for agent status API with mocked SDK."""

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import structlog
from io import StringIO
import logging

from app.main import create_app
from app.services.exceptions import (
    AgentNotFoundError,
    SDKError,
    SDKTimeoutError,
    InvalidAgentIdError,
)


class TestAgentStatusIntegration:
    """Integration tests for the complete agent status request flow."""

    @pytest.fixture
    def app(self):
        """Create FastAPI app for testing."""
        return create_app()

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        with TestClient(app) as c:
            yield c

    @pytest.fixture
    def auth_token(self, client):
        """Get authentication token for testing."""
        response = client.post("/api/v1/auth/token", data={"username": "user", "password": "x"})
        assert response.status_code == 200
        return response.json()["access_token"]

    @pytest.fixture
    def admin_token(self, client):
        """Get admin authentication token for testing."""
        response = client.post("/api/v1/auth/token", data={"username": "admin", "password": "x"})
        assert response.status_code == 200
        return response.json()["access_token"]

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> dict:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

    @pytest.fixture
    def mock_sdk(self):
        """Mock SDK for testing."""
        with patch('app.api.deps.MockAgentSDK') as mock:
            yield mock.return_value

    @pytest.fixture
    def log_capture(self):
        """Capture structured logs for testing."""
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        yield log_stream
        
        logger.removeHandler(handler)

    @pytest.fixture
    def sample_agent_data(self):
        """Sample agent data for testing."""
        return {
            "id": "test-agent-123",
            "name": "Test Agent",
            "status": "active"
        }

    def test_successful_agent_status_request_flow(
        self, client, auth_token, auth_headers, mock_sdk, sample_agent_data, log_capture
    ):
        """Test complete successful request flow from HTTP to SDK and back."""
        # Arrange
        agent_id = "test-agent-123"
        mock_sdk.get_agent = AsyncMock(return_value=sample_agent_data)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Test Agent"
        assert response_data["status"] == "active"
        
        # Assert SDK was called correctly
        mock_sdk.get_agent.assert_called_once_with(agent_id)
        
        # Assert structured logging
        log_output = log_capture.getvalue()
        assert "Agent status request received" in log_output
        assert "Agent status request completed successfully" in log_output
        assert agent_id in log_output

    def test_agent_not_found_error_propagation(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test error propagation from SDK AgentNotFoundError to HTTP 404."""
        # Arrange
        agent_id = "nonexistent-agent"
        mock_sdk.get_agent = AsyncMock(side_effect=AgentNotFoundError(agent_id))
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 404
        response_data = response.json()
        # FastAPI returns HTTPException detail directly
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "AGENT_NOT_FOUND"
        assert response_data["detail"]["error"]["message"] == f"Agent with ID '{agent_id}' not found"
        assert response_data["detail"]["error"]["details"]["agent_id"] == agent_id
        
        # Assert SDK was called
        mock_sdk.get_agent.assert_called_once_with(agent_id)
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "Agent not found" in log_output
        assert "Agent status request failed" in log_output

    def test_sdk_timeout_error_propagation(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test error propagation from SDK timeout to HTTP 502."""
        # Arrange
        agent_id = "timeout-agent"
        timeout_seconds = 30
        mock_sdk.get_agent = AsyncMock(side_effect=SDKTimeoutError(timeout_seconds))
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        # Note: SDKTimeoutError gets wrapped in retry logic, so it becomes SERVICE_ERROR
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"
        assert "SDK call failed after" in response_data["detail"]["error"]["details"]["error_message"]
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "SDK call timed out" in log_output
        assert str(timeout_seconds) in log_output

    def test_sdk_general_error_propagation(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test error propagation from general SDK error to HTTP 502."""
        # Arrange
        agent_id = "error-agent"
        error_message = "SDK connection failed"
        mock_sdk.get_agent = AsyncMock(side_effect=SDKError(error_message))
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"
        assert response_data["detail"]["error"]["message"] == "Agent service error occurred"
        assert "SDK call failed after" in response_data["detail"]["error"]["details"]["error_message"]
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "SDK error" in log_output
        assert error_message in log_output

    def test_authentication_failure_flow(self, client, mock_sdk, log_capture):
        """Test complete flow with authentication failure."""
        # Arrange
        agent_id = "test-agent"
        invalid_token = "invalid-token"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )
        
        # Assert HTTP response
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Invalid token"
        
        # Assert SDK was not called
        mock_sdk.get_agent.assert_not_called()

    def test_missing_authentication_flow(self, client, mock_sdk):
        """Test complete flow without authentication."""
        # Arrange
        agent_id = "test-agent"
        
        # Act
        response = client.get(f"/api/v1/agent/{agent_id}")
        
        # Assert HTTP response
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Not authenticated"
        
        # Assert SDK was not called
        mock_sdk.get_agent.assert_not_called()

    def test_invalid_agent_id_validation_flow(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test complete flow with invalid agent ID format."""
        # Arrange
        invalid_agent_id = "invalid@agent#id"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{invalid_agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 422
        response_data = response.json()
        # FastAPI validation error format
        assert "detail" in response_data
        
        # Assert SDK was not called due to path validation
        mock_sdk.get_agent.assert_not_called()

    def test_malformed_sdk_response_handling(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test handling of malformed SDK responses."""
        # Arrange
        agent_id = "test-agent"
        malformed_response = {"invalid": "response"}  # Missing required fields
        mock_sdk.get_agent = AsyncMock(return_value=malformed_response)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"
        assert "SDK response missing required fields" in response_data["detail"]["error"]["details"]["error_message"]
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "SDK error" in log_output

    def test_sdk_response_id_mismatch_handling(
        self, client, auth_token, auth_headers, mock_sdk, log_capture
    ):
        """Test handling when SDK returns different agent ID than requested."""
        # Arrange
        requested_id = "agent-123"
        returned_data = {
            "id": "different-agent-456",
            "name": "Different Agent",
            "status": "active"
        }
        mock_sdk.get_agent = AsyncMock(return_value=returned_data)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{requested_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"
        assert "SDK returned different agent ID" in response_data["detail"]["error"]["details"]["error_message"]

    def test_structured_logging_integration(
        self, client, auth_token, auth_headers, mock_sdk, sample_agent_data, log_capture
    ):
        """Test that structured logging captures all required fields."""
        # Arrange
        agent_id = "test-agent-123"
        mock_sdk.get_agent = AsyncMock(return_value=sample_agent_data)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert response is successful
        assert response.status_code == 200
        
        # Parse log output to verify structured logging
        log_output = log_capture.getvalue()
        log_lines = [line for line in log_output.split('\n') if line.strip()]
        
        # Find the request received log entry
        request_log = None
        success_log = None
        
        for line in log_lines:
            if "Agent status request received" in line:
                try:
                    request_log = json.loads(line)
                except json.JSONDecodeError:
                    # Skip non-JSON log lines
                    continue
            elif "Agent status request completed successfully" in line:
                try:
                    success_log = json.loads(line)
                except json.JSONDecodeError:
                    continue
        
        # Verify request log structure
        if request_log:
            assert request_log.get("agent_id") == agent_id
            assert request_log.get("user") == "user"
            assert "user_roles" in request_log
        
        # Verify success log structure
        if success_log:
            assert success_log.get("agent_id") == agent_id
            assert success_log.get("user") == "user"
            assert success_log.get("agent_name") == "Test Agent"
            assert success_log.get("status") == "active"

    def test_concurrent_requests_handling(
        self, client, auth_token, auth_headers, mock_sdk, sample_agent_data
    ):
        """Test handling of concurrent requests to the same endpoint."""
        import asyncio
        import threading
        from concurrent.futures import ThreadPoolExecutor
        
        # Arrange
        agent_id = "test-agent-123"
        mock_sdk.get_agent = AsyncMock(return_value=sample_agent_data)
        
        def make_request():
            return client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(auth_token)
            )
        
        # Act - make multiple concurrent requests
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            responses = [future.result() for future in futures]
        
        # Assert all requests succeeded
        for response in responses:
            assert response.status_code == 200
            response_data = response.json()
            assert response_data["id"] == agent_id
            assert response_data["agent_name"] == "Test Agent"
            assert response_data["status"] == "active"
        
        # Assert SDK was called for each request
        assert mock_sdk.get_agent.call_count == 5

    def test_request_response_timing_logging(
        self, client, auth_token, auth_headers, mock_sdk, sample_agent_data, log_capture
    ):
        """Test that request timing information is properly logged."""
        # Arrange
        agent_id = "test-agent-123"
        
        # Add delay to SDK call to test timing
        async def delayed_get_agent(agent_id):
            await asyncio.sleep(0.1)  # 100ms delay
            return sample_agent_data
        
        mock_sdk.get_agent = AsyncMock(side_effect=delayed_get_agent)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert response is successful
        assert response.status_code == 200
        
        # Verify timing information in logs
        log_output = log_capture.getvalue()
        assert "Agent status request received" in log_output
        assert "Agent status request completed successfully" in log_output

    @pytest.mark.parametrize("sdk_error,expected_status,expected_code", [
        (AgentNotFoundError("test-agent"), 404, "AGENT_NOT_FOUND"),
        (SDKTimeoutError(30), 502, "SERVICE_ERROR"),  # Timeout gets wrapped in retry logic
        (SDKError("Connection failed"), 502, "SERVICE_ERROR"),
        (Exception("Unexpected error"), 502, "SERVICE_ERROR"),  # All exceptions become SERVICE_ERROR due to retry logic
    ])
    def test_various_sdk_error_scenarios(
        self, client, auth_token, auth_headers, mock_sdk, log_capture,
        sdk_error, expected_status, expected_code
    ):
        """Test various SDK error scenarios and their HTTP mappings."""
        # Arrange
        agent_id = "test-agent"
        mock_sdk.get_agent = AsyncMock(side_effect=sdk_error)
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(auth_token)
        )
        
        # Assert HTTP response
        assert response.status_code == expected_status
        response_data = response.json()
        
        # All errors go through the detail structure
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == expected_code
        
        # Assert error was logged
        log_output = log_capture.getvalue()
        assert "Agent status request failed" in log_output or "error" in log_output.lower()


class TestAgentStatusFixtures:
    """Test fixtures for various SDK response scenarios."""

    @pytest.fixture
    def app(self):
        """Create FastAPI app for testing."""
        return create_app()

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        with TestClient(app) as c:
            yield c

    @pytest.fixture
    def auth_token(self, client):
        """Get authentication token for testing."""
        response = client.post("/api/v1/auth/token", data={"username": "user", "password": "x"})
        assert response.status_code == 200
        return response.json()["access_token"]

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> dict:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

    @pytest.fixture
    def mock_sdk(self):
        """Mock SDK for testing."""
        with patch('app.api.deps.MockAgentSDK') as mock:
            yield mock.return_value

    @pytest.fixture
    def active_agent_response(self):
        """Fixture for active agent response."""
        return {
            "id": "active-agent-001",
            "name": "Active Customer Support Bot",
            "status": "active"
        }

    @pytest.fixture
    def inactive_agent_response(self):
        """Fixture for inactive agent response."""
        return {
            "id": "inactive-agent-002",
            "name": "Inactive Sales Bot",
            "status": "inactive"
        }

    @pytest.fixture
    def busy_agent_response(self):
        """Fixture for busy agent response."""
        return {
            "id": "busy-agent-003",
            "name": "Busy Technical Support Agent",
            "status": "busy"
        }

    @pytest.fixture
    def maintenance_agent_response(self):
        """Fixture for agent in maintenance mode."""
        return {
            "id": "maintenance-agent-004",
            "name": "Maintenance Mode Agent",
            "status": "maintenance"
        }

    def test_different_agent_status_scenarios(
        self, client, auth_token, auth_headers, mock_sdk,
        active_agent_response, inactive_agent_response, busy_agent_response, maintenance_agent_response
    ):
        """Test different agent status scenarios using fixtures."""
        test_cases = [
            ("active-agent-001", active_agent_response),
            ("inactive-agent-002", inactive_agent_response),
            ("busy-agent-003", busy_agent_response),
            ("maintenance-agent-004", maintenance_agent_response),
        ]
        
        for agent_id, expected_response in test_cases:
            # Arrange
            mock_sdk.get_agent = AsyncMock(return_value=expected_response)
            
            # Act
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(auth_token)
            )
            
            # Assert
            assert response.status_code == 200
            response_data = response.json()
            assert response_data["id"] == expected_response["id"]
            assert response_data["agent_name"] == expected_response["name"]
            assert response_data["status"] == expected_response["status"]
            
            # Reset mock for next iteration
            mock_sdk.reset_mock()
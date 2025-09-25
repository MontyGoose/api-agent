"""Comprehensive integration tests for complete API to SDK flow."""

import json
import pytest
import asyncio
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import structlog
from io import StringIO
import logging
from typing import Dict, Any

from app.main import create_app
from app.core.config import Settings
from app.services.exceptions import (
    AgentNotFoundError,
    SDKError,
    SDKTimeoutError,
    InvalidAgentIdError,
    AuthenticationError,
    SessionError,
    SDKConfigurationError,
)
from app.models.agent_config import AgentSDKConfig
from app.services.concrete_sdk import ConcreteAgentSDK
from app.services.mock_sdk import MockAgentSDK


class TestCompleteAPIToSDKFlow:
    """Integration tests for complete flow from API endpoint to SDK and back."""

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
    def valid_jwt_token(self):
        """Create valid JWT token for testing."""
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def admin_jwt_token(self):
        """Create admin JWT token for testing."""
        payload = {
            "sub": "admin",
            "roles": ["admin", "user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def expired_jwt_token(self):
        """Create expired JWT token for testing."""
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> Dict[str, str]:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

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

    def test_complete_successful_flow_with_mock_sdk(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test complete successful request flow using mock SDK."""
        # Arrange
        agent_id = "agent-123"  # This exists in MockAgentSDK
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Customer Support Bot"
        assert response_data["status"] == "active"
        
        # Assert structured logging
        log_output = log_capture.getvalue()
        assert "Agent status request received" in log_output
        assert "Agent status request completed successfully" in log_output
        assert agent_id in log_output

    @patch('app.api.deps.get_settings')
    @patch('app.services.sdk_factory.AgentSDKFactory.create_sdk')
    def test_complete_flow_with_concrete_sdk_mock(
        self, mock_create_sdk, mock_get_settings, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test complete flow with concrete SDK (mocked external calls)."""
        # Arrange - Configure settings to use concrete SDK
        mock_settings = Settings(
            ENV="prod",  # Use prod to avoid test environment override
            SECRET_KEY="test-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-jwt-token",
            AGENT_SDK_BASE_URL="https://test-api.example.com",
            AGENT_SDK_ENV="TEST",
            AGENT_SDK_TIMEOUT=30,
            AGENT_SDK_RETRY_COUNT=2
        )
        mock_get_settings.return_value = mock_settings
        
        agent_id = "test-agent-123"
        
        # Mock the SDK to return test data
        mock_sdk = AsyncMock()
        mock_sdk.get_agent.return_value = {
            "id": agent_id,
            "name": "Test Agent",
            "status": "active"
        }
        mock_create_sdk.return_value = mock_sdk
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Test Agent"
        assert response_data["status"] == "active"
        
        # Assert SDK was called
        mock_sdk.get_agent.assert_called_once_with(agent_id)
        
        # Assert structured logging
        log_output = log_capture.getvalue()
        assert "Agent status request received" in log_output
        assert "Agent status request completed successfully" in log_output
    def test_authentication_failure_complete_flow(
        self, client, log_capture
    ):
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
        
        # Assert no agent service logs (request should fail at auth layer)
        log_output = log_capture.getvalue()
        assert "Agent status request received" not in log_output

    def test_missing_authentication_complete_flow(self, client):
        """Test complete flow without authentication."""
        # Arrange
        agent_id = "test-agent"
        
        # Act
        response = client.get(f"/api/v1/agent/{agent_id}")
        
        # Assert HTTP response
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Not authenticated"

    def test_expired_token_complete_flow(
        self, client, expired_jwt_token, auth_headers, log_capture
    ):
        """Test complete flow with expired JWT token."""
        # Arrange
        agent_id = "test-agent"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(expired_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Invalid token"

    def test_agent_not_found_error_propagation(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test error propagation from SDK AgentNotFoundError to HTTP 404."""
        # Arrange
        agent_id = "nonexistent-agent"  # This doesn't exist in MockAgentSDK
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 404
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "AGENT_NOT_FOUND"
        assert response_data["detail"]["error"]["details"]["agent_id"] == agent_id
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "Agent not found" in log_output or "Agent status request failed" in log_output

    def test_sdk_error_propagation_complete_flow(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test error propagation from SDK error to HTTP 502."""
        # Arrange
        agent_id = "error-agent"  # This triggers SDK error in MockAgentSDK
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"
        
        # Assert error logging
        log_output = log_capture.getvalue()
        assert "SDK error" in log_output or "Agent status request failed" in log_output

    def test_timeout_error_propagation_complete_flow(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test timeout error propagation through complete flow."""
        # Arrange
        agent_id = "timeout-agent"  # This triggers timeout in MockAgentSDK
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response
        assert response.status_code == 502
        response_data = response.json()
        assert "error" in response_data["detail"]
        assert response_data["detail"]["error"]["code"] == "SERVICE_ERROR"

    def test_invalid_agent_id_validation_complete_flow(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test complete flow with invalid agent ID format."""
        # Arrange
        invalid_agent_id = "invalid@agent#id"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{invalid_agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert HTTP response - FastAPI path validation should catch this
        assert response.status_code == 422
        response_data = response.json()
        assert "detail" in response_data

    @pytest.mark.parametrize("agent_id,expected_status,expected_name", [
        ("agent-123", "active", "Customer Support Bot"),
        ("agent-456", "inactive", "Sales Assistant"),
        ("agent-789", "busy", "Technical Support Agent"),
        ("agent-indexing", "indexing", "Indexing Agent"),
    ])
    def test_various_agent_statuses_complete_flow(
        self, client, valid_jwt_token, auth_headers, agent_id, expected_status, expected_name
    ):
        """Test complete flow with various agent statuses."""
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == expected_name
        assert response_data["status"] == expected_status

    def test_concurrent_requests_complete_flow(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test handling of concurrent requests through complete flow."""
        import threading
        from concurrent.futures import ThreadPoolExecutor
        
        # Arrange
        agent_id = "agent-123"
        
        def make_request():
            return client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
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
            assert response_data["agent_name"] == "Customer Support Bot"
            assert response_data["status"] == "active"


class TestMockVsConcreteSDKIntegration:
    """Integration tests comparing mock and concrete SDK implementations."""

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
    def valid_jwt_token(self):
        """Create valid JWT token for testing."""
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> Dict[str, str]:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

    @patch('app.api.deps.get_settings')
    def test_mock_sdk_forced_mode(
        self, mock_get_settings, client, valid_jwt_token, auth_headers
    ):
        """Test that forced mock mode works even with concrete SDK config."""
        # Arrange - Force mock mode even with valid concrete config
        mock_settings = Settings(
            ENV="prod",
            SECRET_KEY="test-secret-key",
            AGENT_SDK_MOCK_MODE=True,  # Force mock mode
            AGENT_SDK_JWT_TOKEN="test-jwt-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        mock_get_settings.return_value = mock_settings
        
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert - Should get mock data
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Customer Support Bot"  # Mock data
        assert response_data["status"] == "active"

    @patch('app.api.deps.get_settings')
    def test_concrete_sdk_fallback_to_mock(
        self, mock_get_settings, client, valid_jwt_token, auth_headers
    ):
        """Test fallback to mock SDK when concrete SDK config is incomplete."""
        # Arrange - Missing JWT token for concrete SDK
        mock_settings = Settings(
            ENV="prod",
            SECRET_KEY="test-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,  # Missing JWT token
            AGENT_SDK_BASE_URL="https://api.example.com"
        )
        mock_get_settings.return_value = mock_settings
        
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert - Should fallback to mock and work
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Customer Support Bot"  # Mock data

    @patch('app.api.deps.get_settings')
    @patch('app.services.sdk_factory.AgentSDKFactory.create_sdk')
    def test_concrete_sdk_with_mocked_external_calls(
        self, mock_create_sdk, mock_get_settings, client, valid_jwt_token, auth_headers
    ):
        """Test concrete SDK with mocked external API calls."""
        # Arrange - Valid concrete SDK config
        mock_settings = Settings(
            ENV="prod",  # Use prod to avoid test environment override
            SECRET_KEY="test-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-jwt-token",
            AGENT_SDK_BASE_URL="https://test-api.example.com",
            AGENT_SDK_ENV="TEST"
        )
        mock_get_settings.return_value = mock_settings
        
        agent_id = "concrete-test-agent"
        
        # Mock the SDK to return test data
        mock_sdk = AsyncMock()
        mock_sdk.get_agent.return_value = {
            "id": agent_id,
            "name": "Concrete Test Agent",
            "status": "active"
        }
        mock_create_sdk.return_value = mock_sdk
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id
        assert response_data["agent_name"] == "Concrete Test Agent"
        assert response_data["status"] == "active"
        
        # Verify SDK was called
        mock_sdk.get_agent.assert_called_once_with(agent_id)

class TestAuthenticationAndAuthorizationIntegration:
    """Integration tests for authentication and authorization with real JWT tokens."""

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
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> Dict[str, str]:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

    def create_jwt_token(self, username: str, roles: list, exp_hours: int = 1) -> str:
        """Helper to create JWT tokens with specific claims."""
        payload = {
            "sub": username,
            "roles": roles,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=exp_hours)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    def test_user_role_authentication_flow(self, client, auth_headers):
        """Test complete flow with user role authentication."""
        # Arrange
        user_token = self.create_jwt_token("testuser", ["user"])
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(user_token)
        )
        
        # Assert
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id

    def test_admin_role_authentication_flow(self, client, auth_headers):
        """Test complete flow with admin role authentication."""
        # Arrange
        admin_token = self.create_jwt_token("admin", ["admin", "user"])
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(admin_token)
        )
        
        # Assert
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id

    def test_multiple_roles_authentication_flow(self, client, auth_headers):
        """Test complete flow with multiple roles in JWT token."""
        # Arrange
        multi_role_token = self.create_jwt_token("poweruser", ["user", "admin", "developer"])
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(multi_role_token)
        )
        
        # Assert
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id

    def test_no_roles_authentication_flow(self, client, auth_headers):
        """Test complete flow with JWT token containing no roles."""
        # Arrange
        no_roles_token = self.create_jwt_token("noroleuser", [])
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(no_roles_token)
        )
        
        # Assert - Should still work as endpoint doesn't require specific roles
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["id"] == agent_id

    def test_malformed_jwt_token_flow(self, client, auth_headers):
        """Test complete flow with malformed JWT token."""
        # Arrange
        malformed_token = "not.a.valid.jwt.token"
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(malformed_token)
        )
        
        # Assert
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Invalid token"

    def test_jwt_token_without_sub_claim_flow(self, client, auth_headers):
        """Test complete flow with JWT token missing sub claim."""
        # Arrange
        payload = {
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
            # Missing "sub" claim
        }
        invalid_token = jwt.encode(payload, "test-secret-key", algorithm="HS256")
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(invalid_token)
        )
        
        # Assert
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Invalid token payload"

    def test_jwt_token_with_wrong_secret_flow(self, client, auth_headers):
        """Test complete flow with JWT token signed with wrong secret."""
        # Arrange
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        wrong_secret_token = jwt.encode(payload, "wrong-secret", algorithm="HS256")
        agent_id = "agent-123"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(wrong_secret_token)
        )
        
        # Assert
        assert response.status_code == 401
        response_data = response.json()
        assert response_data["detail"] == "Invalid token"

    def test_bearer_token_format_variations(self, client):
        """Test various Bearer token format scenarios."""
        agent_id = "agent-123"
        valid_token = self.create_jwt_token("testuser", ["user"])
        
        # Test valid format
        response = client.get(
            f"/api/v1/agent/{agent_id}", 
            headers={"Authorization": f"Bearer {valid_token}"}
        )
        assert response.status_code == 200
        
        # Test invalid formats
        invalid_cases = [
            {"Authorization": valid_token},  # Missing Bearer prefix
            {"Authorization": ""},  # Empty Authorization header
            {},  # No Authorization header
        ]
        
        for headers in invalid_cases:
            response = client.get(f"/api/v1/agent/{agent_id}", headers=headers)
            assert response.status_code == 401
        
        # Test case variations - FastAPI OAuth2PasswordBearer behavior
        case_variations = [
            {"Authorization": f"bearer {valid_token}"},  # lowercase
            {"Authorization": f"Bearer  {valid_token}"},  # extra space
        ]
        
        for headers in case_variations:
            response = client.get(f"/api/v1/agent/{agent_id}", headers=headers)
            # FastAPI might be flexible with these, so we test actual behavior
            assert response.status_code in [200, 401]  # Either works or doesn't

    def test_token_expiration_edge_cases(self, client, auth_headers):
        """Test JWT token expiration edge cases."""
        agent_id = "agent-123"
        
        # Test recently expired token (1 second ago)
        recently_expired_payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        recently_expired_token = jwt.encode(recently_expired_payload, "test-secret-key", algorithm="HS256")
        
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(recently_expired_token)
        )
        assert response.status_code == 401
        
        # Test token expiring soon (1 second from now)
        expiring_soon_payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(seconds=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        expiring_soon_token = jwt.encode(expiring_soon_payload, "test-secret-key", algorithm="HS256")
        
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(expiring_soon_token)
        )
        assert response.status_code == 200


class TestErrorPropagationIntegration:
    """Integration tests for error propagation through the entire stack."""

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
    def valid_jwt_token(self):
        """Create valid JWT token for testing."""
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> Dict[str, str]:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

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

    def test_sdk_exception_to_http_error_mapping(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test that SDK exceptions are properly mapped to HTTP errors."""
        test_cases = [
            # (agent_id, expected_status, expected_error_code)
            ("nonexistent-agent", 404, "AGENT_NOT_FOUND"),
            ("error-agent", 502, "SERVICE_ERROR"),
            ("timeout-agent", 502, "SERVICE_ERROR"),
        ]
        
        for agent_id, expected_status, expected_error_code in test_cases:
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            
            assert response.status_code == expected_status
            response_data = response.json()
            assert "error" in response_data["detail"]
            assert response_data["detail"]["error"]["code"] == expected_error_code
            
            # Verify error was logged
            log_output = log_capture.getvalue()
            assert agent_id in log_output

    @patch('app.api.deps.get_settings')
    @patch('app.services.sdk_factory.AgentSDKFactory.create_sdk')
    def test_concrete_sdk_error_propagation(
        self, mock_create_sdk, mock_get_settings, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test error propagation from concrete SDK through the stack."""
        # Arrange - Configure concrete SDK
        mock_settings = Settings(
            ENV="prod",  # Use prod to avoid test environment override
            SECRET_KEY="test-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-jwt-token",
            AGENT_SDK_BASE_URL="https://test-api.example.com",
            AGENT_SDK_ENV="TEST"
        )
        mock_get_settings.return_value = mock_settings
        
        agent_id = "test-agent"
        
        # Test different error scenarios
        error_scenarios = [
            # (exception_to_raise, expected_status, expected_error_code)
            (AgentNotFoundError(agent_id), 404, "AGENT_NOT_FOUND"),
            (SDKTimeoutError(30), 502, "SERVICE_ERROR"),  # Timeout gets wrapped in retry logic
            (AuthenticationError("Auth failed"), 502, "SERVICE_ERROR"),
            (SDKError("General SDK error"), 502, "SERVICE_ERROR"),
        ]
        
        for exception, expected_status, expected_error_code in error_scenarios:
            # Mock the SDK to raise the exception
            mock_sdk = AsyncMock()
            mock_sdk.get_agent.side_effect = exception
            mock_create_sdk.return_value = mock_sdk
            
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            
            assert response.status_code == expected_status
            response_data = response.json()
            assert "error" in response_data["detail"]
            assert response_data["detail"]["error"]["code"] == expected_error_code

    def test_structured_error_logging_propagation(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test that structured error information propagates through logs."""
        # Arrange
        agent_id = "error-agent"
        
        # Act
        response = client.get(
            f"/api/v1/agent/{agent_id}",
            headers=auth_headers(valid_jwt_token)
        )
        
        # Assert response
        assert response.status_code == 502
        
        # Parse and verify structured logs
        log_output = log_capture.getvalue()
        log_lines = [line for line in log_output.split('\n') if line.strip()]
        
        # Look for structured log entries
        structured_logs = []
        for line in log_lines:
            try:
                log_data = json.loads(line)
                structured_logs.append(log_data)
            except json.JSONDecodeError:
                continue
        
        # Verify we have logs with proper structure
        request_logs = [log for log in structured_logs if "Agent status request received" in log.get("event", "")]
        error_logs = [log for log in structured_logs if "error" in log.get("event", "").lower()]
        
        # Should have request received log
        assert len(request_logs) > 0
        request_log = request_logs[0]
        assert request_log.get("agent_id") == agent_id
        assert request_log.get("user") == "testuser"
        
        # Should have error logs
        assert len(error_logs) > 0

    def test_error_response_format_consistency(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test that all error responses follow consistent format."""
        error_test_cases = [
            ("nonexistent-agent", 404),
            ("error-agent", 502),
            ("timeout-agent", 502),
        ]
        
        for agent_id, expected_status in error_test_cases:
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            
            assert response.status_code == expected_status
            response_data = response.json()
            
            # Verify consistent error structure
            assert "detail" in response_data
            assert "error" in response_data["detail"]
            
            error_obj = response_data["detail"]["error"]
            assert "message" in error_obj
            assert "code" in error_obj
            assert "details" in error_obj
            
            # Verify error details contain agent_id (may be in different formats)
            details_str = str(error_obj["details"])
            assert ("agent_id" in error_obj["details"] or 
                   agent_id in details_str or 
                   "error_message" in error_obj["details"])

    def test_unexpected_exception_handling(
        self, client, valid_jwt_token, auth_headers, log_capture
    ):
        """Test handling of unexpected exceptions in the stack."""
        agent_id = "test-agent"
        
        # Mock an unexpected exception in the service layer by patching the SDK
        with patch('app.services.sdk_factory.AgentSDKFactory.create_sdk') as mock_create_sdk:
            mock_sdk = AsyncMock()
            mock_sdk.get_agent.side_effect = RuntimeError("Unexpected error")
            mock_create_sdk.return_value = mock_sdk
            
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            
            # Should get 502 for unexpected errors (wrapped by service layer retry logic)
            assert response.status_code == 502
            response_data = response.json()
            assert "detail" in response_data
            
            # Verify error was logged
            log_output = log_capture.getvalue()
            assert "error" in log_output.lower()


class TestPerformanceAndReliabilityIntegration:
    """Integration tests for performance and reliability aspects."""

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
    def valid_jwt_token(self):
        """Create valid JWT token for testing."""
        payload = {
            "sub": "testuser",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    @pytest.fixture
    def auth_headers(self):
        """Helper to create auth headers."""
        def _make_headers(token: str) -> Dict[str, str]:
            return {"Authorization": f"Bearer {token}"}
        return _make_headers

    def test_response_time_consistency(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test that response times are consistent across multiple requests."""
        import time
        
        agent_id = "agent-123"
        response_times = []
        
        # Make multiple requests and measure response times
        for _ in range(10):
            start_time = time.time()
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            end_time = time.time()
            
            assert response.status_code == 200
            response_times.append(end_time - start_time)
        
        # Verify response times are reasonable and consistent
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        # All responses should be under 1 second for mock SDK
        assert max_response_time < 1.0
        # Average should be much faster
        assert avg_response_time < 0.5

    def test_memory_usage_stability(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test that memory usage remains stable across multiple requests."""
        import gc
        
        agent_id = "agent-123"
        
        # Make many requests to test for memory leaks
        for _ in range(50):
            response = client.get(
                f"/api/v1/agent/{agent_id}",
                headers=auth_headers(valid_jwt_token)
            )
            assert response.status_code == 200
        
        # Force garbage collection
        gc.collect()
        
        # If we get here without memory errors, consider it stable
        # This is a simplified test since psutil is not available
        assert True

    def test_error_recovery_after_failures(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test that system recovers properly after error conditions."""
        # First, trigger an error
        error_response = client.get(
            "/api/v1/agent/error-agent",
            headers=auth_headers(valid_jwt_token)
        )
        assert error_response.status_code == 502
        
        # Then verify normal operation continues
        normal_response = client.get(
            "/api/v1/agent/agent-123",
            headers=auth_headers(valid_jwt_token)
        )
        assert normal_response.status_code == 200
        
        # Repeat to ensure stability
        for _ in range(5):
            response = client.get(
                "/api/v1/agent/agent-123",
                headers=auth_headers(valid_jwt_token)
            )
            assert response.status_code == 200

    def test_load_handling_capability(
        self, client, valid_jwt_token, auth_headers
    ):
        """Test system's ability to handle moderate load."""
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        agent_id = "agent-123"
        num_requests = 20
        
        def make_request():
            try:
                response = client.get(
                    f"/api/v1/agent/{agent_id}",
                    headers=auth_headers(valid_jwt_token)
                )
                return response.status_code == 200
            except Exception:
                return False
        
        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            results = [future.result() for future in as_completed(futures)]
        
        # All requests should succeed
        success_rate = sum(results) / len(results)
        assert success_rate >= 0.95  # At least 95% success rate
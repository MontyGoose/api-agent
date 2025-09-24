"""Unit tests for agent status router endpoints."""

import pytest
from unittest.mock import AsyncMock
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from app.main import create_app
from app.api.deps import get_agent_service
from app.models.schemas import AgentStatusResponse


@pytest.fixture
def mock_agent_service():
    """Mock agent service for testing."""
    return AsyncMock()


@pytest.fixture
def client_with_mock(mock_agent_service):
    """Test client with mocked agent service."""
    app = create_app()
    app.dependency_overrides[get_agent_service] = lambda: mock_agent_service
    with TestClient(app) as client:
        yield client, mock_agent_service


@pytest.fixture
def sample_agent_response():
    """Sample agent response for successful tests."""
    return AgentStatusResponse(
        id="test-agent-123",
        agent_name="Test Agent",
        status="active"
    )


def test_get_agent_status_success(client_with_mock, user_token, auth_header, sample_agent_response):
    """Test successful agent status retrieval with valid authentication."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.return_value = sample_agent_response
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "test-agent-123"
    assert data["agent_name"] == "Test Agent"
    assert data["status"] == "active"
    
    # Verify service was called with correct parameters
    mock_agent_service.get_agent_status.assert_called_once_with("test-agent-123")


def test_get_agent_status_no_auth_token(client_with_mock):
    """Test authentication failure when no token is provided (401)."""
    # Arrange
    client, _ = client_with_mock
    
    # Act
    response = client.get("/api/v1/agent/test-agent-123")
    
    # Assert
    assert response.status_code == 401


def test_get_agent_status_invalid_token(client_with_mock):
    """Test authentication failure with invalid token (401)."""
    # Arrange
    client, _ = client_with_mock
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers={"Authorization": "Bearer invalid-token"}
    )
    
    # Assert
    assert response.status_code == 401


def test_get_agent_status_expired_token(client_with_mock):
    """Test authentication failure with expired token (401)."""
    # Arrange
    client, _ = client_with_mock
    # Use a clearly expired/malformed token
    expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxfQ.invalid"
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    
    # Assert
    assert response.status_code == 401


@pytest.mark.parametrize("invalid_agent_id", [
    "agent@123",  # Invalid character (@)
    "agent 123",  # Invalid character (space)
    "agent.123",  # Invalid character (.)
])
def test_get_agent_status_invalid_agent_id_format(client_with_mock, user_token, auth_header, invalid_agent_id):
    """Test validation failure for invalid agent ID formats (422)."""
    # Arrange
    client, _ = client_with_mock
    
    # Act
    response = client.get(
        f"/api/v1/agent/{invalid_agent_id}",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data


def test_get_agent_status_agent_not_found(client_with_mock, user_token, auth_header):
    """Test agent not found scenario (404)."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.side_effect = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": {
                "message": "Agent with ID 'nonexistent-agent' not found",
                "code": "AGENT_NOT_FOUND",
                "details": {"agent_id": "nonexistent-agent"}
            }
        }
    )
    
    # Act
    response = client.get(
        "/api/v1/agent/nonexistent-agent",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 404
    data = response.json()
    assert data["detail"]["error"]["code"] == "AGENT_NOT_FOUND"
    assert data["detail"]["error"]["details"]["agent_id"] == "nonexistent-agent"


def test_get_agent_status_service_error(client_with_mock, user_token, auth_header):
    """Test service error scenario (502)."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.side_effect = HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail={
            "error": {
                "message": "Agent service error occurred",
                "code": "SERVICE_ERROR",
                "details": {"error_message": "SDK connection failed"}
            }
        }
    )
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 502
    data = response.json()
    assert data["detail"]["error"]["code"] == "SERVICE_ERROR"


def test_get_agent_status_service_timeout(client_with_mock, user_token, auth_header):
    """Test service timeout scenario (502)."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.side_effect = HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail={
            "error": {
                "message": "Agent service is currently unavailable",
                "code": "SERVICE_TIMEOUT",
                "details": {"timeout_seconds": 30}
            }
        }
    )
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 502
    data = response.json()
    assert data["detail"]["error"]["code"] == "SERVICE_TIMEOUT"
    assert data["detail"]["error"]["details"]["timeout_seconds"] == 30


def test_get_agent_status_internal_server_error(client_with_mock, user_token, auth_header):
    """Test internal server error scenario (500)."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.side_effect = HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error": {
                "message": "Internal server error occurred",
                "code": "INTERNAL_ERROR",
                "details": {"agent_id": "test-agent-123"}
            }
        }
    )
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 500
    data = response.json()
    assert data["detail"]["error"]["code"] == "INTERNAL_ERROR"


@pytest.mark.parametrize("valid_agent_id", [
    "agent-123",
    "agent_456", 
    "AGENT-789",
    "a",  # Minimum length
    "agent-123_test-456",
])
def test_get_agent_status_valid_agent_ids(client_with_mock, user_token, auth_header, valid_agent_id):
    """Test that valid agent ID formats are accepted."""
    # Arrange
    client, mock_agent_service = client_with_mock
    sample_response = AgentStatusResponse(
        id=valid_agent_id,
        agent_name="Test Agent",
        status="active"
    )
    mock_agent_service.get_agent_status.return_value = sample_response
    
    # Act
    response = client.get(
        f"/api/v1/agent/{valid_agent_id}",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == valid_agent_id


def test_get_agent_status_response_format(client_with_mock, user_token, auth_header, sample_agent_response):
    """Test that response format matches the expected schema."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.return_value = sample_agent_response
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    
    # Verify all required fields are present
    required_fields = ["id", "agent_name", "status"]
    for field in required_fields:
        assert field in data
        assert isinstance(data[field], str)
        assert len(data[field]) > 0


def test_get_agent_status_with_admin_token(client_with_mock, admin_token, auth_header, sample_agent_response):
    """Test that admin users can access the endpoint."""
    # Arrange
    client, mock_agent_service = client_with_mock
    mock_agent_service.get_agent_status.return_value = sample_agent_response
    
    # Act
    response = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(admin_token)
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "test-agent-123"


def test_get_agent_status_case_sensitive_agent_id(client_with_mock, user_token, auth_header):
    """Test that agent IDs are case-sensitive."""
    # Arrange
    client, mock_agent_service = client_with_mock
    agent_response_lower = AgentStatusResponse(
        id="test-agent-123",
        agent_name="Lower Case Agent",
        status="active"
    )
    agent_response_upper = AgentStatusResponse(
        id="TEST-AGENT-123",
        agent_name="Upper Case Agent", 
        status="active"
    )
    
    # Configure mock to return different responses for different cases
    def mock_get_agent_status(agent_id):
        if agent_id == "test-agent-123":
            return agent_response_lower
        elif agent_id == "TEST-AGENT-123":
            return agent_response_upper
        else:
            raise HTTPException(status_code=404, detail="Not found")
    
    mock_agent_service.get_agent_status.side_effect = mock_get_agent_status
    
    # Act & Assert - lowercase
    response_lower = client.get(
        "/api/v1/agent/test-agent-123",
        headers=auth_header(user_token)
    )
    assert response_lower.status_code == 200
    assert response_lower.json()["agent_name"] == "Lower Case Agent"
    
    # Act & Assert - uppercase
    response_upper = client.get(
        "/api/v1/agent/TEST-AGENT-123",
        headers=auth_header(user_token)
    )
    assert response_upper.status_code == 200
    assert response_upper.json()["agent_name"] == "Upper Case Agent"


def test_get_agent_status_special_characters_in_path(client_with_mock, user_token, auth_header):
    """Test handling of URL-encoded special characters in agent ID."""
    # Arrange
    client, _ = client_with_mock
    # Test with URL-encoded characters that should be rejected
    encoded_agent_id = "agent%40123"  # agent@123 URL encoded
    
    # Act
    response = client.get(
        f"/api/v1/agent/{encoded_agent_id}",
        headers=auth_header(user_token)
    )
    
    # Assert - should be rejected due to invalid characters
    assert response.status_code == 422
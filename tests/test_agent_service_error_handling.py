"""Tests for AgentService error handling and HTTP exception mapping."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import HTTPException, status

from src.app.services.agent_service import AgentService
from src.app.services.interfaces import AgentSDKInterface
from src.app.services.exceptions import (
    SDKError,
    AgentNotFoundError,
    SDKTimeoutError,
    InvalidAgentIdError,
    AuthenticationError,
    SessionError,
    AgentAccessError,
    SDKConnectionError,
    SDKConfigurationError,
    SDKResponseError
)


class TestAgentServiceErrorHandling:
    """Test error handling in AgentService."""
    
    @pytest.fixture
    def mock_sdk(self):
        """Create a mock SDK for testing."""
        return Mock(spec=AgentSDKInterface)
    
    @pytest.fixture
    def agent_service(self, mock_sdk):
        """Create AgentService instance for testing."""
        return AgentService(mock_sdk, timeout_seconds=30, retry_count=3)
    
    @pytest.mark.asyncio
    async def test_get_agent_status_invalid_agent_id_empty(self, agent_service):
        """Test get_agent_status with empty agent ID."""
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status("")
        
        assert exc_info.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert exc_info.value.detail["error"]["code"] == "INVALID_AGENT_ID"
        assert "Agent ID cannot be empty" in exc_info.value.detail["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_get_agent_status_invalid_agent_id_format(self, agent_service):
        """Test get_agent_status with invalid agent ID format."""
        invalid_agent_id = "invalid@agent#id"
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(invalid_agent_id)
        
        assert exc_info.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert exc_info.value.detail["error"]["code"] == "INVALID_AGENT_ID"
        assert invalid_agent_id in exc_info.value.detail["error"]["details"]["agent_id"]
    
    @pytest.mark.asyncio
    async def test_get_agent_status_agent_not_found(self, agent_service, mock_sdk):
        """Test get_agent_status when agent is not found."""
        agent_id = "nonexistent-agent"
        mock_sdk.get_agent.side_effect = AgentNotFoundError(agent_id)
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail["error"]["code"] == "AGENT_NOT_FOUND"
        assert agent_id in exc_info.value.detail["error"]["message"]
        assert exc_info.value.detail["error"]["details"]["agent_id"] == agent_id
    
    @pytest.mark.asyncio
    async def test_get_agent_status_sdk_timeout(self, agent_service, mock_sdk):
        """Test get_agent_status when SDK times out."""
        agent_id = "timeout-agent"
        timeout_seconds = 30
        mock_sdk.get_agent.side_effect = SDKTimeoutError(timeout_seconds, "get_agent")
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_TIMEOUT"
        assert "Agent service is currently unavailable" in exc_info.value.detail["error"]["message"]
        assert exc_info.value.detail["error"]["details"]["timeout_seconds"] == timeout_seconds
    
    @pytest.mark.asyncio
    async def test_get_agent_status_authentication_error(self, agent_service, mock_sdk):
        """Test get_agent_status when authentication fails."""
        agent_id = "auth-agent"
        mock_sdk.get_agent.side_effect = AuthenticationError("JWT token expired")
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
        assert "Agent service error occurred" in exc_info.value.detail["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_get_agent_status_session_error(self, agent_service, mock_sdk):
        """Test get_agent_status when session management fails."""
        agent_id = "session-agent"
        mock_sdk.get_agent.side_effect = SessionError("Session expired")
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
    
    @pytest.mark.asyncio
    async def test_get_agent_status_agent_access_error(self, agent_service, mock_sdk):
        """Test get_agent_status when agent access is denied."""
        agent_id = "restricted-agent"
        mock_sdk.get_agent.side_effect = AgentAccessError(agent_id)
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
    
    @pytest.mark.asyncio
    async def test_get_agent_status_sdk_connection_error(self, agent_service, mock_sdk):
        """Test get_agent_status when SDK connection fails."""
        agent_id = "connection-agent"
        mock_sdk.get_agent.side_effect = SDKConnectionError(
            "Failed to connect to agent service",
            "https://api.example.com"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
    
    @pytest.mark.asyncio
    async def test_get_agent_status_sdk_configuration_error(self, agent_service, mock_sdk):
        """Test get_agent_status when SDK configuration is invalid."""
        agent_id = "config-agent"
        mock_sdk.get_agent.side_effect = SDKConfigurationError(
            "Missing JWT token",
            missing_fields=["jwt_token"]
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
    
    @pytest.mark.asyncio
    async def test_get_agent_status_sdk_response_error(self, agent_service, mock_sdk):
        """Test get_agent_status when SDK response is invalid."""
        agent_id = "response-agent"
        mock_sdk.get_agent.side_effect = SDKResponseError(
            "Invalid response format",
            {"invalid": "data"},
            "AgentDetailsResponse"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
    
    @pytest.mark.asyncio
    async def test_get_agent_status_generic_sdk_error(self, agent_service, mock_sdk):
        """Test get_agent_status with generic SDK error."""
        agent_id = "error-agent"
        original_error = ValueError("Some validation error")
        mock_sdk.get_agent.side_effect = SDKError("SDK operation failed", original_error)
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_502_BAD_GATEWAY
        assert exc_info.value.detail["error"]["code"] == "SERVICE_ERROR"
        assert "Agent service error occurred" in exc_info.value.detail["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_get_agent_status_unexpected_error(self, agent_service, mock_sdk):
        """Test get_agent_status with unexpected error."""
        agent_id = "unexpected-agent"
        mock_sdk.get_agent.side_effect = RuntimeError("Unexpected runtime error")
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.get_agent_status(agent_id)
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail["error"]["code"] == "INTERNAL_ERROR"
        assert "Internal server error occurred" in exc_info.value.detail["error"]["message"]
        assert exc_info.value.detail["error"]["details"]["agent_id"] == agent_id
    
    @pytest.mark.asyncio
    async def test_get_agent_status_success(self, agent_service, mock_sdk):
        """Test successful get_agent_status call."""
        agent_id = "success-agent"
        mock_agent_data = {
            "id": agent_id,
            "name": "Test Agent",
            "status": "active"
        }
        mock_sdk.get_agent.return_value = mock_agent_data
        
        result = await agent_service.get_agent_status(agent_id)
        
        assert result.id == agent_id
        assert result.agent_name == "Test Agent"
        assert result.status == "active"
    
    @pytest.mark.asyncio
    @patch('src.app.services.agent_service.logger')
    async def test_get_agent_status_logging_success(self, mock_logger, agent_service, mock_sdk):
        """Test that successful operations are logged properly."""
        agent_id = "logging-agent"
        mock_agent_data = {
            "id": agent_id,
            "name": "Test Agent",
            "status": "active"
        }
        mock_sdk.get_agent.return_value = mock_agent_data
        
        result = await agent_service.get_agent_status(agent_id)
        
        # Verify info logging calls
        info_calls = [call for call in mock_logger.info.call_args_list]
        assert len(info_calls) >= 2  # Should have start and success logs
        
        # Check that agent_id is in the log calls
        log_messages = [str(call) for call in info_calls]
        assert any(agent_id in msg for msg in log_messages)
    
    @pytest.mark.asyncio
    @patch('src.app.services.agent_service.logger')
    async def test_get_agent_status_logging_errors(self, mock_logger, agent_service, mock_sdk):
        """Test that errors are logged with structured information."""
        agent_id = "error-logging-agent"
        mock_sdk.get_agent.side_effect = AgentNotFoundError(agent_id)
        
        with pytest.raises(HTTPException):
            await agent_service.get_agent_status(agent_id)
        
        # Verify warning logging for AgentNotFoundError
        mock_logger.warning.assert_called()
        warning_call = mock_logger.warning.call_args
        assert agent_id in str(warning_call)
    
    @pytest.mark.asyncio
    @patch('src.app.services.agent_service.logger')
    async def test_get_agent_status_logging_sdk_errors(self, mock_logger, agent_service, mock_sdk):
        """Test that SDK errors are logged with enhanced information."""
        agent_id = "sdk-error-logging-agent"
        original_error = ConnectionError("Network failed")
        sdk_error = SDKError("SDK failed", original_error)
        mock_sdk.get_agent.side_effect = sdk_error
        
        with pytest.raises(HTTPException):
            await agent_service.get_agent_status(agent_id)
        
        # Verify error logging for SDKError
        mock_logger.error.assert_called()
        error_call = mock_logger.error.call_args
        
        # Check that structured logging includes relevant information
        assert agent_id in str(error_call)
        assert "SDK error" in str(error_call)


class TestAgentServiceErrorHandlerMethods:
    """Test individual error handler methods in AgentService."""
    
    @pytest.fixture
    def agent_service(self):
        """Create AgentService instance for testing."""
        mock_sdk = Mock(spec=AgentSDKInterface)
        return AgentService(mock_sdk)
    
    def test_handle_validation_error(self, agent_service):
        """Test _handle_validation_error method."""
        error = InvalidAgentIdError("invalid@id", "Contains invalid characters")
        
        http_exception = agent_service._handle_validation_error(error)
        
        assert isinstance(http_exception, HTTPException)
        assert http_exception.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert http_exception.detail["error"]["code"] == "INVALID_AGENT_ID"
        assert http_exception.detail["error"]["details"]["agent_id"] == "invalid@id"
        assert http_exception.detail["error"]["details"]["reason"] == "Contains invalid characters"
    
    def test_handle_not_found_error(self, agent_service):
        """Test _handle_not_found_error method."""
        error = AgentNotFoundError("missing-agent", "Agent does not exist")
        
        http_exception = agent_service._handle_not_found_error(error)
        
        assert isinstance(http_exception, HTTPException)
        assert http_exception.status_code == status.HTTP_404_NOT_FOUND
        assert http_exception.detail["error"]["code"] == "AGENT_NOT_FOUND"
        assert http_exception.detail["error"]["details"]["agent_id"] == "missing-agent"
    
    def test_handle_timeout_error(self, agent_service):
        """Test _handle_timeout_error method."""
        error = SDKTimeoutError(45, "get_agent_details")
        
        http_exception = agent_service._handle_timeout_error(error)
        
        assert isinstance(http_exception, HTTPException)
        assert http_exception.status_code == status.HTTP_502_BAD_GATEWAY
        assert http_exception.detail["error"]["code"] == "SERVICE_TIMEOUT"
        assert http_exception.detail["error"]["details"]["timeout_seconds"] == 45
        assert "Agent service is currently unavailable" in http_exception.detail["error"]["message"]
    
    def test_handle_sdk_error(self, agent_service):
        """Test _handle_sdk_error method."""
        original_error = ValueError("Validation failed")
        error = SDKError("SDK operation failed", original_error, "CUSTOM_SDK_ERROR")
        
        http_exception = agent_service._handle_sdk_error(error)
        
        assert isinstance(http_exception, HTTPException)
        assert http_exception.status_code == status.HTTP_502_BAD_GATEWAY
        assert http_exception.detail["error"]["code"] == "SERVICE_ERROR"
        assert "Agent service error occurred" in http_exception.detail["error"]["message"]
        assert "SDK operation failed" in http_exception.detail["error"]["details"]["error_message"]


class TestAgentServiceRetryLogic:
    """Test retry logic in AgentService._call_sdk_with_retry method."""
    
    @pytest.fixture
    def agent_service(self):
        """Create AgentService instance with specific retry configuration."""
        mock_sdk = Mock(spec=AgentSDKInterface)
        return AgentService(mock_sdk, timeout_seconds=10, retry_count=2)
    
    @pytest.mark.asyncio
    async def test_call_sdk_with_retry_success_first_attempt(self, agent_service):
        """Test successful SDK call on first attempt."""
        agent_id = "success-agent"
        expected_data = {"id": agent_id, "name": "Test Agent", "status": "active"}
        
        # Mock SDK to return data immediately
        agent_service.sdk.get_agent = AsyncMock(return_value=expected_data)
        
        result = await agent_service._call_sdk_with_retry(agent_id)
        
        assert result == expected_data
        assert agent_service.sdk.get_agent.call_count == 1
    
    @pytest.mark.asyncio
    async def test_call_sdk_with_retry_success_after_retries(self, agent_service):
        """Test successful SDK call after retries."""
        agent_id = "retry-agent"
        expected_data = {"id": agent_id, "name": "Test Agent", "status": "active"}
        
        # Mock SDK to fail twice then succeed
        agent_service.sdk.get_agent = AsyncMock(
            side_effect=[
                Exception("Temporary error 1"),
                Exception("Temporary error 2"),
                expected_data
            ]
        )
        
        result = await agent_service._call_sdk_with_retry(agent_id)
        
        assert result == expected_data
        assert agent_service.sdk.get_agent.call_count == 3
    
    @pytest.mark.asyncio
    async def test_call_sdk_with_retry_timeout(self, agent_service):
        """Test SDK call timeout."""
        agent_id = "timeout-agent"
        
        # Mock SDK to raise TimeoutError
        async def timeout_side_effect(*args, **kwargs):
            raise asyncio.TimeoutError()
        
        agent_service.sdk.get_agent = AsyncMock(side_effect=timeout_side_effect)
        
        with pytest.raises(SDKTimeoutError) as exc_info:
            await agent_service._call_sdk_with_retry(agent_id)
        
        assert exc_info.value.timeout_seconds == agent_service.timeout_seconds
        assert agent_service.sdk.get_agent.call_count == 1  # No retries for timeout
    
    @pytest.mark.asyncio
    async def test_call_sdk_with_retry_agent_not_found_no_retry(self, agent_service):
        """Test that AgentNotFoundError is not retried."""
        agent_id = "missing-agent"
        
        # Mock SDK to raise AgentNotFoundError
        agent_service.sdk.get_agent = AsyncMock(side_effect=AgentNotFoundError(agent_id))
        
        with pytest.raises(AgentNotFoundError):
            await agent_service._call_sdk_with_retry(agent_id)
        
        assert agent_service.sdk.get_agent.call_count == 1  # No retries
    
    @pytest.mark.asyncio
    async def test_call_sdk_with_retry_all_retries_exhausted(self, agent_service):
        """Test when all retries are exhausted."""
        agent_id = "failing-agent"
        
        # Mock SDK to always fail
        agent_service.sdk.get_agent = AsyncMock(side_effect=Exception("Persistent error"))
        
        with pytest.raises(SDKError) as exc_info:
            await agent_service._call_sdk_with_retry(agent_id)
        
        # Should attempt initial call + retry_count retries
        expected_calls = agent_service.retry_count + 1
        assert agent_service.sdk.get_agent.call_count == expected_calls
        assert f"failed after {expected_calls} attempts" in str(exc_info.value)
    
    @pytest.mark.asyncio
    @patch('src.app.services.agent_service.asyncio.sleep')
    async def test_call_sdk_with_retry_exponential_backoff(self, mock_sleep, agent_service):
        """Test exponential backoff in retry logic."""
        agent_id = "backoff-agent"
        
        # Mock SDK to fail then succeed
        agent_service.sdk.get_agent = AsyncMock(
            side_effect=[
                Exception("Error 1"),
                Exception("Error 2"),
                {"id": agent_id, "name": "Test", "status": "active"}
            ]
        )
        
        result = await agent_service._call_sdk_with_retry(agent_id)
        
        # Verify exponential backoff sleep calls
        expected_sleep_calls = [
            ((1,), {}),  # 2^0 = 1 second
            ((2,), {}),  # 2^1 = 2 seconds
        ]
        assert mock_sleep.call_args_list == expected_sleep_calls
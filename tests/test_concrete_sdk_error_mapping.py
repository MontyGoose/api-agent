"""Tests for ConcreteAgentSDK error mapping and handling."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import httpx
import asyncio
from typing import Dict, Any

from src.app.services.concrete_sdk import ConcreteAgentSDK
from src.app.models.agent_config import AgentSDKConfig
from src.app.models.session import SessionManager
from src.app.services.exceptions import (
    SDKError,
    AgentNotFoundError,
    SDKTimeoutError,
    AuthenticationError,
    SessionError,
    AgentAccessError,
    SDKConnectionError,
    SDKConfigurationError,
    SDKResponseError
)


class TestConcreteAgentSDKErrorMapping:
    """Test error mapping in ConcreteAgentSDK."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock AgentSDKConfig for testing."""
        return AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token",
            request_timeout=30,
            retry_count=3
        )
    
    @pytest.fixture
    def mock_session_manager(self):
        """Create a mock SessionManager for testing."""
        session_manager = Mock(spec=SessionManager)
        session_manager.is_authenticated.return_value = True
        return session_manager
    
    @pytest.fixture
    def concrete_sdk(self, mock_config, mock_session_manager):
        """Create ConcreteAgentSDK instance for testing."""
        sdk = ConcreteAgentSDK(mock_config)
        sdk.session_manager = mock_session_manager
        return sdk
    
    def test_map_sdk_exceptions_http_404(self, concrete_sdk):
        """Test mapping HTTP 404 errors to AgentNotFoundError."""
        # Create mock error with HTTP response
        mock_error = Exception("Not found")
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Agent not found"
        mock_error.response = mock_response
        
        mapped_error = concrete_sdk._map_sdk_exceptions(mock_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, AgentNotFoundError)
        assert mapped_error.agent_id == "agent-123"
    
    def test_map_sdk_exceptions_http_403(self, concrete_sdk):
        """Test mapping HTTP 403 errors to AgentAccessError."""
        mock_error = Exception("Forbidden")
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Access denied"
        mock_error.response = mock_response
        
        mapped_error = concrete_sdk._map_sdk_exceptions(mock_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, AgentAccessError)
        assert mapped_error.agent_id == "agent-123"
    
    def test_map_sdk_exceptions_http_401(self, concrete_sdk):
        """Test mapping HTTP 401 errors to AuthenticationError."""
        mock_error = Exception("Unauthorized")
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Invalid token"
        mock_error.response = mock_response
        
        mapped_error = concrete_sdk._map_sdk_exceptions(mock_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, AuthenticationError)
    
    def test_map_sdk_exceptions_connection_error(self, concrete_sdk):
        """Test mapping connection errors to SDKConnectionError."""
        connection_error = ConnectionError("Connection refused")
        
        mapped_error = concrete_sdk._map_sdk_exceptions(connection_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, SDKConnectionError)
        assert mapped_error.base_url == concrete_sdk.config.base_url
        assert mapped_error.original_error == connection_error
    
    def test_map_sdk_exceptions_timeout_error(self, concrete_sdk):
        """Test mapping timeout errors to SDKConnectionError."""
        timeout_error = TimeoutError("Request timed out")
        
        mapped_error = concrete_sdk._map_sdk_exceptions(timeout_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, SDKConnectionError)
    
    def test_map_sdk_exceptions_authentication_keywords(self, concrete_sdk):
        """Test mapping errors with authentication keywords."""
        auth_errors = [
            Exception("Authentication failed"),
            Exception("Unauthorized access"),
            Exception("JWT token invalid"),
            Exception("Token expired"),
            Exception("Auth error occurred")
        ]
        
        for error in auth_errors:
            mapped_error = concrete_sdk._map_sdk_exceptions(error, "agent-123", "login")
            assert isinstance(mapped_error, AuthenticationError)
    
    def test_map_sdk_exceptions_session_keywords(self, concrete_sdk):
        """Test mapping errors with session keywords."""
        session_errors = [
            Exception("Session expired"),
            Exception("Session management failed"),
            # Note: "Session token invalid" contains "token" which maps to AuthenticationError
        ]
        
        for error in session_errors:
            mapped_error = concrete_sdk._map_sdk_exceptions(error, "agent-123", "session_op")
            assert isinstance(mapped_error, SessionError)
        
        # Test that "Session token invalid" maps to AuthenticationError due to "token" keyword
        token_error = Exception("Session token invalid")
        mapped_error = concrete_sdk._map_sdk_exceptions(token_error, "agent-123", "session_op")
        assert isinstance(mapped_error, AuthenticationError)
    
    def test_map_sdk_exceptions_not_found_keywords(self, concrete_sdk):
        """Test mapping errors with 'not found' keywords."""
        not_found_errors = [
            Exception("Agent not found"),
            Exception("Resource not found"),
            Exception("HTTP 404 error")
        ]
        
        for error in not_found_errors:
            mapped_error = concrete_sdk._map_sdk_exceptions(error, "agent-123", "get_agent")
            assert isinstance(mapped_error, AgentNotFoundError)
            assert mapped_error.agent_id == "agent-123"
    
    def test_map_sdk_exceptions_access_denied_keywords(self, concrete_sdk):
        """Test mapping errors with 'access denied' keywords."""
        access_errors = [
            Exception("Access denied"),
            Exception("HTTP 403 forbidden"),
            Exception("Permission denied")
        ]
        
        for error in access_errors:
            mapped_error = concrete_sdk._map_sdk_exceptions(error, "agent-123", "get_agent")
            assert isinstance(mapped_error, AgentAccessError)
            assert mapped_error.agent_id == "agent-123"
    
    def test_map_sdk_exceptions_timeout_keywords(self, concrete_sdk):
        """Test mapping errors with timeout keywords."""
        timeout_errors = [
            Exception("Request timeout"),
            Exception("Operation timed out"),
            Exception("Timeout occurred")
        ]
        
        for error in timeout_errors:
            mapped_error = concrete_sdk._map_sdk_exceptions(error, "agent-123", "get_agent")
            assert isinstance(mapped_error, SDKTimeoutError)
            assert mapped_error.operation == "get_agent"
    
    def test_map_sdk_exceptions_generic_error(self, concrete_sdk):
        """Test mapping generic errors to SDKError."""
        generic_error = ValueError("Some validation error")
        
        mapped_error = concrete_sdk._map_sdk_exceptions(generic_error, "agent-123", "get_agent")
        
        assert isinstance(mapped_error, SDKError)
        assert mapped_error.original_error == generic_error
        assert "agent-123" in str(mapped_error.details.get("agent_id", ""))
        assert "get_agent" in str(mapped_error.details.get("operation", ""))


class TestConcreteAgentSDKGetAgentErrorHandling:
    """Test error handling in ConcreteAgentSDK.get_agent method."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock AgentSDKConfig for testing."""
        return AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token",
            request_timeout=30,
            retry_count=2  # Reduced for faster tests
        )
    
    @pytest.fixture
    def concrete_sdk(self, mock_config):
        """Create ConcreteAgentSDK instance for testing."""
        return ConcreteAgentSDK(mock_config)
    
    @pytest.mark.asyncio
    async def test_get_agent_configuration_error_no_base_url(self):
        """Test get_agent with missing base_url configuration."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="",  # Empty base URL
            jwt_token="mock.jwt.token"
        )
        sdk = ConcreteAgentSDK(config)
        
        with pytest.raises(SDKConfigurationError) as exc_info:
            await sdk.get_agent("agent-123")
        
        assert "Base URL is required" in str(exc_info.value)
        assert "base_url" in exc_info.value.missing_fields
    
    @pytest.mark.asyncio
    async def test_get_agent_configuration_error_no_env(self):
        """Test get_agent with missing environment configuration."""
        # Since AgentSDKConfig validates env at creation, we need to test this differently
        # We'll create a valid config then modify it after creation
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token"
        )
        sdk = ConcreteAgentSDK(config)
        
        # Modify the config after creation to simulate missing env
        sdk.config.env = ""
        
        with pytest.raises(SDKConfigurationError) as exc_info:
            await sdk.get_agent("agent-123")
        
        assert "Environment is required" in str(exc_info.value)
        assert "env" in exc_info.value.missing_fields
    
    @pytest.mark.asyncio
    async def test_get_agent_authentication_error_no_jwt(self):
        """Test get_agent with missing JWT token."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token=None  # No JWT token
        )
        sdk = ConcreteAgentSDK(config)
        
        with pytest.raises(AuthenticationError) as exc_info:
            await sdk.get_agent("agent-123")
        
        assert "No JWT token configured" in str(exc_info.value)
        assert exc_info.value.details["agent_id"] == "agent-123"
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_async_agent_creation_error(self, mock_async_agent, concrete_sdk):
        """Test get_agent when AsyncAgent creation fails."""
        # Mock AsyncAgent constructor to raise an error
        mock_async_agent.side_effect = ValueError("Invalid agent configuration")
        
        with pytest.raises(SDKError) as exc_info:
            await concrete_sdk.get_agent("agent-123")
        
        # Verify the error was mapped appropriately
        assert isinstance(exc_info.value, SDKError)
        assert exc_info.value.original_error is not None
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_view_call_timeout(self, mock_async_agent, concrete_sdk):
        """Test get_agent when AsyncAgent.view() times out."""
        # Setup mock AsyncAgent
        mock_agent_instance = AsyncMock()
        mock_agent_instance.view.side_effect = asyncio.TimeoutError()
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        with pytest.raises(SDKTimeoutError) as exc_info:
            await concrete_sdk.get_agent("agent-123")
        
        assert exc_info.value.timeout_seconds == concrete_sdk.config.request_timeout
        assert exc_info.value.operation == "agent_view"
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_view_call_agent_not_found(self, mock_async_agent, concrete_sdk):
        """Test get_agent when agent is not found."""
        # Setup mock AsyncAgent
        mock_agent_instance = AsyncMock()
        mock_agent_instance.view.side_effect = AgentNotFoundError("agent-123")
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        with pytest.raises(AgentNotFoundError) as exc_info:
            await concrete_sdk.get_agent("agent-123")
        
        assert exc_info.value.agent_id == "agent-123"
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_view_call_authentication_error(self, mock_async_agent, concrete_sdk):
        """Test get_agent when authentication fails."""
        # Setup mock AsyncAgent
        mock_agent_instance = AsyncMock()
        mock_agent_instance.view.side_effect = AuthenticationError("Token expired")
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        with pytest.raises(AuthenticationError) as exc_info:
            await concrete_sdk.get_agent("agent-123")
        
        assert "Token expired" in str(exc_info.value)
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_retry_logic_transient_error(self, mock_async_agent, concrete_sdk):
        """Test get_agent retry logic with transient errors."""
        # Setup mock AsyncAgent that fails twice then succeeds
        mock_agent_instance = AsyncMock()
        
        # First two calls fail with a retryable error, third succeeds
        side_effects = [
            Exception("Temporary network error"),
            Exception("Another temporary error"),
            {
                "agentId": "agent-123",
                "agentName": "Test Agent",
                "orgId": "",
                "tenantId": "DEV",
                "agentConfig": {
                    "version": "3",
                    "ownerId": "owner",
                    "agentType": "BYOD",
                    "group": "Personal",
                    "requestUrl": "https://api.example.com/agent/chat",
                    "rootUrl": "https://api.example.com/agent/",
                    "llmModel": "gpt-4",
                    "status": "ACTIVE",
                    "retrieverStrategy": "NUGGET",
                    "reasoningAlgorithm": "GPT_FUNCTION_REASONING",
                    "welcomeMessage": "Hello!",
                    "controlFlags": [],
                    "uiType": "chat",
                    "id": "agent-123"
                }
            }
        ]
        mock_agent_instance.view.side_effect = side_effects
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        # Should succeed after retries
        result = await concrete_sdk.get_agent("agent-123")
        
        assert result["id"] == "agent-123"
        assert result["name"] == "Test Agent"
        assert result["status"] == "active"
        
        # Verify view was called 3 times (initial + 2 retries)
        assert mock_agent_instance.view.call_count == 3
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_retry_logic_non_retryable_error(self, mock_async_agent, concrete_sdk):
        """Test get_agent doesn't retry non-retryable errors."""
        # Setup mock AsyncAgent that fails with non-retryable error
        mock_agent_instance = AsyncMock()
        mock_agent_instance.view.side_effect = AgentNotFoundError("agent-123")
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        with pytest.raises(AgentNotFoundError):
            await concrete_sdk.get_agent("agent-123")
        
        # Verify view was called only once (no retries for AgentNotFoundError)
        assert mock_agent_instance.view.call_count == 1
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_retry_exhausted(self, mock_async_agent, concrete_sdk):
        """Test get_agent when all retries are exhausted."""
        # Setup mock AsyncAgent that always fails
        mock_agent_instance = AsyncMock()
        mock_agent_instance.view.side_effect = Exception("Persistent error")
        mock_async_agent.return_value = mock_agent_instance
        
        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.is_authenticated.return_value = True
        concrete_sdk.session_manager = mock_session_manager
        
        with pytest.raises(SDKError) as exc_info:
            await concrete_sdk.get_agent("agent-123")
        
        # Verify all retries were attempted
        expected_calls = concrete_sdk.config.retry_count + 1  # Initial + retries
        assert mock_agent_instance.view.call_count == expected_calls
        
        # Verify error message indicates retry exhaustion
        assert "failed after" in str(exc_info.value)
        assert str(expected_calls) in str(exc_info.value)


class TestConcreteAgentSDKResponseParsing:
    """Test response parsing and validation in ConcreteAgentSDK."""
    
    @pytest.fixture
    def concrete_sdk(self):
        """Create ConcreteAgentSDK instance for testing."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token"
        )
        return ConcreteAgentSDK(config)
    
    def test_parse_agent_response_invalid_type(self, concrete_sdk):
        """Test parsing response with invalid type."""
        invalid_responses = [
            "string response",
            123,
            None,
            ["list", "response"]
        ]
        
        for response in invalid_responses:
            with pytest.raises(SDKResponseError) as exc_info:
                concrete_sdk._parse_agent_response(response, "agent-123")
            
            assert "Expected dictionary" in str(exc_info.value)
            assert exc_info.value.response_data == response
    
    def test_parse_agent_response_missing_fields(self, concrete_sdk):
        """Test parsing response with missing required fields."""
        incomplete_response = {
            "agentId": "agent-123",
            # Missing agentName, tenantId, agentConfig
        }
        
        with pytest.raises(SDKResponseError) as exc_info:
            concrete_sdk._parse_agent_response(incomplete_response, "agent-123")
        
        assert "Invalid agent response format" in str(exc_info.value)
        assert exc_info.value.expected_format == "AgentDetailsResponse"
    
    def test_parse_agent_response_id_mismatch(self, concrete_sdk):
        """Test parsing response with mismatched agent ID."""
        response_with_wrong_id = {
            "agentId": "different-agent",
            "agentName": "Test Agent",
            "orgId": "",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner",
                "agentType": "BYOD",
                "group": "Personal",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING",
                "welcomeMessage": "Hello!",
                "controlFlags": [],
                "uiType": "chat",
                "id": "different-agent"
            }
        }
        
        with pytest.raises(SDKResponseError) as exc_info:
            concrete_sdk._parse_agent_response(response_with_wrong_id, "agent-123")
        
        assert "Response agent ID mismatch" in str(exc_info.value)
        assert "expected 'agent-123'" in str(exc_info.value)
        assert "got 'different-agent'" in str(exc_info.value)
    
    def test_parse_agent_response_valid(self, concrete_sdk):
        """Test parsing valid response."""
        valid_response = {
            "agentId": "agent-123",
            "agentName": "Test Agent",
            "orgId": "",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner",
                "agentType": "BYOD",
                "group": "Personal",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING",
                "welcomeMessage": "Hello!",
                "controlFlags": [],
                "uiType": "chat",
                "id": "agent-123"
            }
        }
        
        result = concrete_sdk._parse_agent_response(valid_response, "agent-123")
        
        assert result.agentId == "agent-123"
        assert result.agentName == "Test Agent"
        assert result.agentConfig.status == "ACTIVE"
        
        # Test transformation to simple format
        simple_format = result.to_simple_format()
        assert simple_format["id"] == "agent-123"
        assert simple_format["name"] == "Test Agent"
        assert simple_format["status"] == "active"  # Should be lowercase
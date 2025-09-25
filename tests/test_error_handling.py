"""Comprehensive tests for error handling and exception mapping."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import httpx
import asyncio
from typing import Dict, Any

from src.app.services.exceptions import (
    ServiceError,
    SDKError,
    AgentNotFoundError,
    SDKTimeoutError,
    InvalidAgentIdError,
    AuthenticationError,
    SessionError,
    AgentAccessError,
    SDKConfigurationError,
    SDKResponseError,
    SDKConnectionError,
    SDKErrorMapper
)


class TestServiceError:
    """Test ServiceError base class functionality."""
    
    def test_service_error_basic(self):
        """Test basic ServiceError creation."""
        error = ServiceError("Test error")
        assert str(error) == "Test error"
        assert error.error_code == "SERVICEERROR"
        assert error.details == {}
    
    def test_service_error_with_code_and_details(self):
        """Test ServiceError with custom error code and details."""
        details = {"key": "value", "number": 42}
        error = ServiceError("Test error", "CUSTOM_CODE", details)
        assert str(error) == "Test error"
        assert error.error_code == "CUSTOM_CODE"
        assert error.details == details
    
    @patch('src.app.services.exceptions.logger')
    def test_service_error_logging(self, mock_logger):
        """Test that ServiceError logs structured information."""
        details = {"agent_id": "test-123"}
        error = ServiceError("Test error", "TEST_CODE", details)
        
        mock_logger.error.assert_called_once_with(
            "Service error occurred",
            error_type="ServiceError",
            error_code="TEST_CODE",
            message="Test error",
            details=details
        )


class TestSDKError:
    """Test SDKError functionality."""
    
    def test_sdk_error_basic(self):
        """Test basic SDKError creation."""
        error = SDKError("SDK failed")
        assert str(error) == "SDK failed"
        assert error.error_code == "SDK_ERROR"
        assert error.original_error is None
    
    def test_sdk_error_with_original_error(self):
        """Test SDKError with original error."""
        original = ValueError("Original error")
        error = SDKError("SDK failed", original)
        assert str(error) == "SDK failed"
        assert error.original_error == original
    
    @patch('src.app.services.exceptions.logger')
    def test_sdk_error_logging(self, mock_logger):
        """Test that SDKError logs enhanced information."""
        original = ValueError("Original error")
        details = {"operation": "test"}
        error = SDKError("SDK failed", original, "CUSTOM_SDK_ERROR", details)
        
        mock_logger.error.assert_called_with(
            "SDK error occurred",
            error_type="SDKError",
            error_code="CUSTOM_SDK_ERROR",
            message="SDK failed",
            original_error_type="ValueError",
            original_error_message="Original error",
            details=details
        )


class TestAgentNotFoundError:
    """Test AgentNotFoundError functionality."""
    
    def test_agent_not_found_basic(self):
        """Test basic AgentNotFoundError creation."""
        error = AgentNotFoundError("agent-123")
        assert str(error) == "Agent with ID 'agent-123' not found"
        assert error.agent_id == "agent-123"
        assert error.reason is None
        assert error.error_code == "AGENT_NOT_FOUND"
    
    def test_agent_not_found_with_reason(self):
        """Test AgentNotFoundError with reason."""
        error = AgentNotFoundError("agent-123", "Access denied")
        assert str(error) == "Agent with ID 'agent-123' not found: Access denied"
        assert error.agent_id == "agent-123"
        assert error.reason == "Access denied"
        assert error.details == {"agent_id": "agent-123", "reason": "Access denied"}


class TestSDKTimeoutError:
    """Test SDKTimeoutError functionality."""
    
    def test_timeout_error_basic(self):
        """Test basic SDKTimeoutError creation."""
        error = SDKTimeoutError(30)
        assert str(error) == "SDK call timed out after 30 seconds"
        assert error.timeout_seconds == 30
        assert error.operation is None
        assert error.error_code == "SDK_TIMEOUT"
    
    def test_timeout_error_with_operation(self):
        """Test SDKTimeoutError with operation."""
        error = SDKTimeoutError(30, "agent_view")
        assert str(error) == "SDK call timed out after 30 seconds during agent_view"
        assert error.timeout_seconds == 30
        assert error.operation == "agent_view"
        assert error.details == {"timeout_seconds": 30, "operation": "agent_view"}


class TestInvalidAgentIdError:
    """Test InvalidAgentIdError functionality."""
    
    def test_invalid_agent_id_basic(self):
        """Test basic InvalidAgentIdError creation."""
        error = InvalidAgentIdError("invalid@id")
        assert str(error) == "Invalid agent ID format: 'invalid@id'"
        assert error.agent_id == "invalid@id"
        assert error.reason is None
        assert error.error_code == "INVALID_AGENT_ID"
    
    def test_invalid_agent_id_with_reason(self):
        """Test InvalidAgentIdError with reason."""
        error = InvalidAgentIdError("", "Agent ID cannot be empty")
        assert str(error) == "Invalid agent ID format: '' - Agent ID cannot be empty"
        assert error.agent_id == ""
        assert error.reason == "Agent ID cannot be empty"


class TestAuthenticationError:
    """Test AuthenticationError functionality."""
    
    def test_authentication_error_basic(self):
        """Test basic AuthenticationError creation."""
        error = AuthenticationError()
        assert str(error) == "Authentication failed"
        assert error.error_code == "AUTHENTICATION_ERROR"
        assert error.original_error is None
    
    def test_authentication_error_with_details(self):
        """Test AuthenticationError with custom message and details."""
        original = ValueError("JWT expired")
        details = {"token_type": "JWT", "context": "login"}
        error = AuthenticationError("Token expired", original, details)
        assert str(error) == "Token expired"
        assert error.original_error == original
        assert error.details == details


class TestSessionError:
    """Test SessionError functionality."""
    
    def test_session_error_basic(self):
        """Test basic SessionError creation."""
        error = SessionError()
        assert str(error) == "Session error"
        assert error.error_code == "SESSION_ERROR"
    
    def test_session_error_with_context(self):
        """Test SessionError with context."""
        original = Exception("Session expired")
        details = {"session_id": "sess-123"}
        error = SessionError("Session management failed", original, details)
        assert str(error) == "Session management failed"
        assert error.original_error == original
        assert error.details == details


class TestAgentAccessError:
    """Test AgentAccessError functionality."""
    
    def test_agent_access_error_basic(self):
        """Test basic AgentAccessError creation."""
        error = AgentAccessError("agent-123")
        expected_message = (
            "Access denied for agent 'agent-123'. "
            "Your access scope may be limited to USER level. "
            "You may only be able to access agents you have created."
        )
        assert str(error) == expected_message
        assert error.agent_id == "agent-123"
        assert error.error_code == "AGENT_ACCESS_ERROR"
        assert error.details == {"agent_id": "agent-123", "access_scope": "USER"}
    
    def test_agent_access_error_custom_message(self):
        """Test AgentAccessError with custom message."""
        custom_message = "Custom access denied message"
        error = AgentAccessError("agent-123", custom_message)
        assert str(error) == custom_message
        assert error.agent_id == "agent-123"


class TestSDKConfigurationError:
    """Test SDKConfigurationError functionality."""
    
    def test_configuration_error_basic(self):
        """Test basic SDKConfigurationError creation."""
        error = SDKConfigurationError("Missing configuration")
        assert str(error) == "Missing configuration"
        assert error.error_code == "SDK_CONFIGURATION_ERROR"
        assert error.missing_fields == []
        assert error.invalid_fields == {}
    
    def test_configuration_error_with_fields(self):
        """Test SDKConfigurationError with missing and invalid fields."""
        missing = ["jwt_token", "base_url"]
        invalid = {"timeout": "must be positive", "env": "invalid environment"}
        error = SDKConfigurationError("Configuration invalid", missing, invalid)
        
        assert str(error) == "Configuration invalid"
        assert error.missing_fields == missing
        assert error.invalid_fields == invalid
        assert error.details == {
            "missing_fields": missing,
            "invalid_fields": invalid
        }


class TestSDKResponseError:
    """Test SDKResponseError functionality."""
    
    def test_response_error_basic(self):
        """Test basic SDKResponseError creation."""
        error = SDKResponseError("Invalid response format")
        assert str(error) == "Invalid response format"
        assert error.error_code == "SDK_RESPONSE_ERROR"
        assert error.response_data is None
        assert error.expected_format is None
    
    def test_response_error_with_data(self):
        """Test SDKResponseError with response data."""
        response_data = {"invalid": "format"}
        expected_format = "AgentDetailsResponse"
        original = ValueError("Missing field")
        
        error = SDKResponseError(
            "Response validation failed",
            response_data,
            expected_format,
            original
        )
        
        assert str(error) == "Response validation failed"
        assert error.response_data == response_data
        assert error.expected_format == expected_format
        assert error.original_error == original
        assert error.details["expected_format"] == expected_format
        assert error.details["response_type"] == "dict"
        assert error.details["response_keys"] == ["invalid"]
    
    def test_response_error_with_non_dict_data(self):
        """Test SDKResponseError with non-dictionary response data."""
        response_data = "string response"
        error = SDKResponseError("Expected dict", response_data)
        
        assert error.details["response_type"] == "str"
        assert "response_keys" not in error.details


class TestSDKConnectionError:
    """Test SDKConnectionError functionality."""
    
    def test_connection_error_basic(self):
        """Test basic SDKConnectionError creation."""
        error = SDKConnectionError("Connection failed")
        assert str(error) == "Connection failed"
        assert error.error_code == "SDK_CONNECTION_ERROR"
        assert error.base_url is None
    
    def test_connection_error_with_url(self):
        """Test SDKConnectionError with base URL."""
        base_url = "https://api.example.com"
        original = ConnectionError("Network unreachable")
        
        error = SDKConnectionError("Failed to connect", base_url, original)
        assert str(error) == "Failed to connect"
        assert error.base_url == base_url
        assert error.original_error == original
        assert error.details == {"base_url": base_url}


class TestSDKErrorMapper:
    """Test SDKErrorMapper utility class."""
    
    def test_map_http_status_404(self):
        """Test mapping HTTP 404 to AgentNotFoundError."""
        error = SDKErrorMapper.map_http_status_error(404, "agent-123")
        assert isinstance(error, AgentNotFoundError)
        assert error.agent_id == "agent-123"
        assert "Agent not found (HTTP 404)" in str(error)
    
    def test_map_http_status_403(self):
        """Test mapping HTTP 403 to AgentAccessError."""
        error = SDKErrorMapper.map_http_status_error(403, "agent-123")
        assert isinstance(error, AgentAccessError)
        assert error.agent_id == "agent-123"
    
    def test_map_http_status_401(self):
        """Test mapping HTTP 401 to AuthenticationError."""
        error = SDKErrorMapper.map_http_status_error(401)
        assert isinstance(error, AuthenticationError)
        assert "Authentication failed (HTTP 401)" in str(error)
    
    def test_map_http_status_timeout(self):
        """Test mapping HTTP timeout statuses to SDKTimeoutError."""
        for status_code in [408, 504]:
            error = SDKErrorMapper.map_http_status_error(status_code)
            assert isinstance(error, SDKTimeoutError)
            assert "HTTP request timeout" in str(error)
    
    def test_map_http_status_server_error(self):
        """Test mapping HTTP 5xx to SDKError."""
        error = SDKErrorMapper.map_http_status_error(500, "agent-123", "Internal server error")
        assert isinstance(error, SDKError)
        assert "Server error (HTTP 500)" in str(error)
        assert error.details["status_code"] == 500
        assert error.details["agent_id"] == "agent-123"
        assert "Internal server error" in error.details["response_text"]
    
    def test_map_http_status_client_error(self):
        """Test mapping HTTP 4xx to SDKError."""
        error = SDKErrorMapper.map_http_status_error(422)
        assert isinstance(error, SDKError)
        assert "Client error (HTTP 422)" in str(error)
    
    def test_map_connection_error_timeout(self):
        """Test mapping timeout connection errors."""
        original = Exception("Connection timeout occurred")
        error = SDKErrorMapper.map_connection_error(original, "https://api.example.com")
        
        assert isinstance(error, SDKConnectionError)
        assert "Connection timeout to agent service" in str(error)
        assert error.base_url == "https://api.example.com"
        assert error.original_error == original
    
    def test_map_connection_error_connection_failed(self):
        """Test mapping connection failed errors."""
        original = ConnectionError("Connection refused")
        error = SDKErrorMapper.map_connection_error(original)
        
        assert isinstance(error, SDKConnectionError)
        assert "Failed to connect to agent service" in str(error)
        assert error.original_error == original
    
    def test_map_connection_error_dns(self):
        """Test mapping DNS resolution errors."""
        original = Exception("DNS resolution failed for hostname")
        error = SDKErrorMapper.map_connection_error(original)
        
        assert isinstance(error, SDKConnectionError)
        assert "DNS resolution failed for agent service" in str(error)
    
    def test_map_connection_error_generic(self):
        """Test mapping generic network errors."""
        original = Exception("Unknown network error")
        error = SDKErrorMapper.map_connection_error(original)
        
        assert isinstance(error, SDKConnectionError)
        assert "Network error connecting to agent service" in str(error)
    
    def test_map_authentication_error_expired(self):
        """Test mapping expired token errors."""
        original = Exception("Token has expired")
        error = SDKErrorMapper.map_authentication_error(original, "login")
        
        assert isinstance(error, AuthenticationError)
        assert "JWT token has expired (login)" in str(error)
        assert error.original_error == original
        assert error.details["context"] == "login"
    
    def test_map_authentication_error_invalid(self):
        """Test mapping invalid token errors."""
        original = Exception("Invalid token format")
        error = SDKErrorMapper.map_authentication_error(original)
        
        assert isinstance(error, AuthenticationError)
        assert "JWT token is invalid" in str(error)
    
    def test_map_authentication_error_malformed(self):
        """Test mapping malformed token errors."""
        original = Exception("Malformed JWT token")
        error = SDKErrorMapper.map_authentication_error(original)
        
        assert isinstance(error, AuthenticationError)
        assert "JWT token is malformed" in str(error)
    
    def test_map_authentication_error_signature(self):
        """Test mapping signature verification errors."""
        original = Exception("Signature verification failed")
        error = SDKErrorMapper.map_authentication_error(original)
        
        assert isinstance(error, AuthenticationError)
        assert "JWT token signature verification failed" in str(error)
    
    def test_map_authentication_error_generic(self):
        """Test mapping generic authentication errors."""
        original = Exception("Unknown auth error")
        error = SDKErrorMapper.map_authentication_error(original)
        
        assert isinstance(error, AuthenticationError)
        assert "Authentication failed: Unknown auth error" in str(error)
    
    def test_map_session_error_token(self):
        """Test mapping session token errors."""
        original = Exception("Session token invalid")
        error = SDKErrorMapper.map_session_error(original, "refresh")
        
        assert isinstance(error, SessionError)
        assert "Session token error: Session token invalid during refresh" in str(error)
        assert error.details["operation"] == "refresh"
    
    def test_map_session_error_expired(self):
        """Test mapping session expired errors."""
        original = Exception("Session has expired")
        error = SDKErrorMapper.map_session_error(original)
        
        assert isinstance(error, SessionError)
        assert "Session expired: Session has expired" in str(error)
    
    def test_map_session_error_generic(self):
        """Test mapping generic session errors."""
        original = Exception("Session management failed")
        error = SDKErrorMapper.map_session_error(original)
        
        assert isinstance(error, SessionError)
        assert "Session management error: Session management failed" in str(error)
    
    def test_map_generic_sdk_error(self):
        """Test mapping generic SDK errors."""
        original = ValueError("Validation failed")
        error = SDKErrorMapper.map_generic_sdk_error(original, "get_agent", "agent-123")
        
        assert isinstance(error, SDKError)
        assert "SDK get_agent failed: Validation failed" in str(error)
        assert error.original_error == original
        assert error.error_code == "SDK_OPERATION_ERROR"
        assert error.details["original_error_type"] == "ValueError"
        assert error.details["operation"] == "get_agent"
        assert error.details["agent_id"] == "agent-123"
    
    def test_map_generic_sdk_error_no_operation(self):
        """Test mapping generic SDK errors without operation."""
        original = Exception("Generic error")
        error = SDKErrorMapper.map_generic_sdk_error(original)
        
        assert isinstance(error, SDKError)
        assert "SDK operation failed: Generic error" in str(error)
        assert "operation" not in error.details
        assert "agent_id" not in error.details


class TestErrorMappingIntegration:
    """Integration tests for error mapping in real scenarios."""
    
    def test_http_response_with_status_code(self):
        """Test mapping errors with HTTP response objects."""
        # Mock an HTTP response with status code
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Agent not found"
        
        # Mock an exception with response attribute
        mock_error = Exception("HTTP error")
        mock_error.response = mock_response
        
        # This would be used in the ConcreteAgentSDK._map_sdk_exceptions method
        error = SDKErrorMapper.map_http_status_error(404, "agent-123", "Agent not found")
        
        assert isinstance(error, AgentNotFoundError)
        assert error.agent_id == "agent-123"
    
    def test_chained_error_mapping(self):
        """Test that error mapping preserves original error chain."""
        original_error = ConnectionError("Network unreachable")
        connection_error = SDKErrorMapper.map_connection_error(original_error, "https://api.example.com")
        
        assert isinstance(connection_error, SDKConnectionError)
        assert connection_error.original_error == original_error
        assert connection_error.base_url == "https://api.example.com"
        
        # Verify the error chain is preserved
        assert str(connection_error.original_error) == "Network unreachable"
    
    def test_error_details_serialization(self):
        """Test that error details can be safely serialized."""
        details = {
            "agent_id": "agent-123",
            "timeout": 30,
            "nested": {"key": "value"},
            "list": [1, 2, 3]
        }
        
        error = SDKError("Test error", details=details)
        
        # Verify details are preserved
        assert error.details == details
        
        # Verify error can be converted to string (important for logging)
        error_str = str(error)
        assert "Test error" in error_str
    
    def test_error_logging_integration(self):
        """Test that all error types can be created without issues."""
        # Test different error types to ensure they can be created properly
        errors_to_test = [
            ("ServiceError", ServiceError, ("Service failed", "SERVICE_CODE", {"key": "value"})),
            ("SDKError", SDKError, ("SDK failed", ValueError("Original"), "SDK_CODE", {"operation": "test"})),
            ("AgentNotFoundError", AgentNotFoundError, ("agent-123", "Not found")),
            ("SDKTimeoutError", SDKTimeoutError, (30, "get_agent")),
            ("AuthenticationError", AuthenticationError, ("Auth failed", None, {"context": "login"})),
        ]
        
        for error_name, error_class, args in errors_to_test:
            # Create error instance
            if error_name == "AuthenticationError":
                error = error_class(args[0], details=args[2])
            else:
                error = error_class(*args)
            
            # Verify error was created successfully
            assert isinstance(error, Exception), f"Failed to create {error_name}"
            assert hasattr(error, 'error_code'), f"{error_name} missing error_code attribute"
            assert hasattr(error, 'details'), f"{error_name} missing details attribute"
            
            # Verify error can be converted to string
            error_str = str(error)
            assert len(error_str) > 0, f"{error_name} string representation is empty"
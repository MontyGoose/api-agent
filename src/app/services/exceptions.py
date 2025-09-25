"""Custom exceptions for service layer operations."""

import structlog
from typing import Optional, Dict, Any

logger = structlog.get_logger(__name__)


class ServiceError(Exception):
    """Base exception for service layer errors."""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        super().__init__(message)
        self.error_code = error_code or self.__class__.__name__.upper()
        self.details = details or {}
        
        # Log the error with structured information
        logger.error(
            "Service error occurred",
            error_type=self.__class__.__name__,
            error_code=self.error_code,
            message=message,
            details=self.details
        )


class SDKError(ServiceError):
    """Exception raised when SDK operations fail."""
    
    def __init__(self, message: str, original_error: Exception = None, error_code: str = None, details: Dict[str, Any] = None):
        super().__init__(message, error_code or "SDK_ERROR", details)
        self.original_error = original_error
        
        # Enhanced logging for SDK errors
        logger.error(
            "SDK error occurred",
            error_type=self.__class__.__name__,
            error_code=self.error_code,
            message=message,
            original_error_type=type(original_error).__name__ if original_error else None,
            original_error_message=str(original_error) if original_error else None,
            details=self.details
        )


class AgentNotFoundError(ServiceError):
    """Exception raised when an agent is not found."""
    
    def __init__(self, agent_id: str, reason: str = None):
        message = f"Agent with ID '{agent_id}' not found"
        if reason:
            message += f": {reason}"
        
        details = {"agent_id": agent_id}
        if reason:
            details["reason"] = reason
            
        super().__init__(message, "AGENT_NOT_FOUND", details)
        self.agent_id = agent_id
        self.reason = reason


class SDKTimeoutError(ServiceError):
    """Exception raised when SDK calls timeout."""
    
    def __init__(self, timeout_seconds: int, operation: str = None):
        message = f"SDK call timed out after {timeout_seconds} seconds"
        if operation:
            message += f" during {operation}"
            
        details = {"timeout_seconds": timeout_seconds}
        if operation:
            details["operation"] = operation
            
        super().__init__(message, "SDK_TIMEOUT", details)
        self.timeout_seconds = timeout_seconds
        self.operation = operation


class InvalidAgentIdError(ServiceError):
    """Exception raised when agent ID format is invalid."""
    
    def __init__(self, agent_id: str, reason: str = None):
        message = f"Invalid agent ID format: '{agent_id}'"
        if reason:
            message += f" - {reason}"
            
        details = {"agent_id": agent_id}
        if reason:
            details["reason"] = reason
            
        super().__init__(message, "INVALID_AGENT_ID", details)
        self.agent_id = agent_id
        self.reason = reason


class AuthenticationError(SDKError):
    """Exception raised when JWT authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", original_error: Exception = None, details: Dict[str, Any] = None):
        super().__init__(message, original_error, "AUTHENTICATION_ERROR", details)


class SessionError(SDKError):
    """Exception raised when session management fails."""
    
    def __init__(self, message: str = "Session error", original_error: Exception = None, details: Dict[str, Any] = None):
        super().__init__(message, original_error, "SESSION_ERROR", details)


class AgentAccessError(SDKError):
    """Exception raised when agent access is restricted due to scope limitations."""
    
    def __init__(self, agent_id: str, message: str = None, original_error: Exception = None):
        default_message = (
            f"Access denied for agent '{agent_id}'. "
            "Your access scope may be limited to USER level. "
            "You may only be able to access agents you have created."
        )
        final_message = message or default_message
        
        details = {"agent_id": agent_id, "access_scope": "USER"}
        super().__init__(final_message, original_error, "AGENT_ACCESS_ERROR", details)
        self.agent_id = agent_id


class SDKConfigurationError(SDKError):
    """Exception raised when SDK configuration is invalid or missing."""
    
    def __init__(self, message: str, missing_fields: list = None, invalid_fields: Dict[str, str] = None):
        details = {}
        if missing_fields:
            details["missing_fields"] = missing_fields
        if invalid_fields:
            details["invalid_fields"] = invalid_fields
            
        super().__init__(message, None, "SDK_CONFIGURATION_ERROR", details)
        self.missing_fields = missing_fields or []
        self.invalid_fields = invalid_fields or {}


class SDKResponseError(SDKError):
    """Exception raised when SDK response format is invalid or unexpected."""
    
    def __init__(self, message: str, response_data: Any = None, expected_format: str = None, original_error: Exception = None):
        details = {}
        if expected_format:
            details["expected_format"] = expected_format
        if response_data is not None:
            # Safely serialize response data for logging
            try:
                if isinstance(response_data, dict):
                    details["response_keys"] = list(response_data.keys())
                    details["response_type"] = "dict"
                else:
                    details["response_type"] = type(response_data).__name__
            except Exception:
                details["response_type"] = "unknown"
                
        super().__init__(message, original_error, "SDK_RESPONSE_ERROR", details)
        self.response_data = response_data
        self.expected_format = expected_format


class SDKConnectionError(SDKError):
    """Exception raised when SDK cannot connect to the remote service."""
    
    def __init__(self, message: str, base_url: str = None, original_error: Exception = None):
        details = {}
        if base_url:
            details["base_url"] = base_url
            
        super().__init__(message, original_error, "SDK_CONNECTION_ERROR", details)
        self.base_url = base_url


# Error mapping utilities
class SDKErrorMapper:
    """Utility class for mapping SDK exceptions to appropriate service exceptions."""
    
    @staticmethod
    def map_http_status_error(status_code: int, agent_id: str = None, response_text: str = None) -> ServiceError:
        """
        Map HTTP status codes to appropriate exceptions.
        
        Args:
            status_code: HTTP status code
            agent_id: Agent ID for context
            response_text: Response text for additional context
            
        Returns:
            Appropriate ServiceError subclass
        """
        details = {"status_code": status_code}
        if agent_id:
            details["agent_id"] = agent_id
        if response_text:
            details["response_text"] = response_text[:500]  # Limit response text length
        
        if status_code == 404:
            return AgentNotFoundError(agent_id or "unknown", "Agent not found (HTTP 404)")
        elif status_code == 403:
            return AgentAccessError(agent_id or "unknown", "Access denied (HTTP 403)")
        elif status_code == 401:
            return AuthenticationError("Authentication failed (HTTP 401)", details=details)
        elif status_code == 408 or status_code == 504:
            return SDKTimeoutError(0, "HTTP request timeout")  # Timeout from server side
        elif 500 <= status_code < 600:
            return SDKError(f"Server error (HTTP {status_code})", details=details)
        elif 400 <= status_code < 500:
            return SDKError(f"Client error (HTTP {status_code})", details=details)
        else:
            return SDKError(f"Unexpected HTTP status {status_code}", details=details)
    
    @staticmethod
    def map_connection_error(error: Exception, base_url: str = None) -> SDKConnectionError:
        """
        Map connection-related errors to SDKConnectionError.
        
        Args:
            error: Original connection error
            base_url: Base URL that failed to connect
            
        Returns:
            SDKConnectionError instance
        """
        error_type = type(error).__name__
        
        if "timeout" in str(error).lower() or "TimeoutError" in error_type:
            message = f"Connection timeout to agent service: {str(error)}"
        elif "connection" in str(error).lower() or "ConnectionError" in error_type:
            message = f"Failed to connect to agent service: {str(error)}"
        elif "dns" in str(error).lower() or "resolve" in str(error).lower():
            message = f"DNS resolution failed for agent service: {str(error)}"
        else:
            message = f"Network error connecting to agent service: {str(error)}"
        
        return SDKConnectionError(message, base_url, error)
    
    @staticmethod
    def map_authentication_error(error: Exception, context: str = None) -> AuthenticationError:
        """
        Map authentication-related errors.
        
        Args:
            error: Original authentication error
            context: Additional context about where the error occurred
            
        Returns:
            AuthenticationError instance
        """
        error_message = str(error)
        
        if "expired" in error_message.lower():
            message = "JWT token has expired"
        elif "invalid" in error_message.lower():
            message = "JWT token is invalid"
        elif "malformed" in error_message.lower():
            message = "JWT token is malformed"
        elif "signature" in error_message.lower():
            message = "JWT token signature verification failed"
        else:
            message = f"Authentication failed: {error_message}"
        
        if context:
            message += f" ({context})"
        
        details = {}
        if context:
            details["context"] = context
        
        return AuthenticationError(message, error, details)
    
    @staticmethod
    def map_session_error(error: Exception, operation: str = None) -> SessionError:
        """
        Map session-related errors.
        
        Args:
            error: Original session error
            operation: Operation that was being performed
            
        Returns:
            SessionError instance
        """
        error_message = str(error)
        
        if "token" in error_message.lower():
            message = f"Session token error: {error_message}"
        elif "expired" in error_message.lower():
            message = f"Session expired: {error_message}"
        else:
            message = f"Session management error: {error_message}"
        
        if operation:
            message += f" during {operation}"
        
        details = {}
        if operation:
            details["operation"] = operation
        
        return SessionError(message, error, details)
    
    @staticmethod
    def map_generic_sdk_error(error: Exception, operation: str = None, agent_id: str = None) -> SDKError:
        """
        Map generic SDK errors that don't fit other categories.
        
        Args:
            error: Original error
            operation: Operation that was being performed
            agent_id: Agent ID for context
            
        Returns:
            SDKError instance
        """
        error_type = type(error).__name__
        error_message = str(error)
        
        message = f"SDK operation failed: {error_message}"
        if operation:
            message = f"SDK {operation} failed: {error_message}"
        
        details = {"original_error_type": error_type}
        if operation:
            details["operation"] = operation
        if agent_id:
            details["agent_id"] = agent_id
        
        return SDKError(message, error, "SDK_OPERATION_ERROR", details)
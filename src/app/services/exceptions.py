"""Custom exceptions for service layer operations."""


class ServiceError(Exception):
    """Base exception for service layer errors."""
    pass


class SDKError(ServiceError):
    """Exception raised when SDK operations fail."""
    
    def __init__(self, message: str, original_error: Exception = None):
        super().__init__(message)
        self.original_error = original_error


class AgentNotFoundError(ServiceError):
    """Exception raised when an agent is not found."""
    
    def __init__(self, agent_id: str):
        super().__init__(f"Agent with ID '{agent_id}' not found")
        self.agent_id = agent_id


class SDKTimeoutError(ServiceError):
    """Exception raised when SDK calls timeout."""
    
    def __init__(self, timeout_seconds: int):
        super().__init__(f"SDK call timed out after {timeout_seconds} seconds")
        self.timeout_seconds = timeout_seconds


class InvalidAgentIdError(ServiceError):
    """Exception raised when agent ID format is invalid."""
    
    def __init__(self, agent_id: str, reason: str = None):
        message = f"Invalid agent ID format: '{agent_id}'"
        if reason:
            message += f" - {reason}"
        super().__init__(message)
        self.agent_id = agent_id
        self.reason = reason
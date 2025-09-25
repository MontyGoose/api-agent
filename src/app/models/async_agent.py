"""AsyncAgent implementation based on the Agent SDK documentation."""

import uuid
import random
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
import httpx

from .session import Session, SessionManager


class FileDetail(BaseModel):
    """File detail model for agent file handling."""
    
    filename: str
    content: Optional[str] = None
    file_type: Optional[str] = None


class MemoryConfig(BaseModel):
    """Memory configuration for agent."""
    
    enabled: bool = True
    max_tokens: int = 4000
    
    def dict(self) -> Dict[str, Any]:
        """Return dictionary representation."""
        return {
            "enabled": self.enabled,
            "max_tokens": self.max_tokens
        }


class AsyncAgent(BaseModel):
    """
    AsyncAgent class based on the Agent SDK documentation.
    
    This class represents an agent with all the required fields and functionality
    as specified in the SDK documentation, including session management,
    configuration, and API integration capabilities.
    """
    
    # Core identification fields
    agent_id: Optional[str] = Field(None, description="Agent unique identifier")
    agent_name: Optional[str] = Field(
        default_factory=lambda: f"Agent: {random.randint(1000, 9999)}",
        description="Agent display name"
    )
    
    # Environment and connection settings
    env: Optional[str] = Field(None, description="Environment (DEV, QA, PROD)")
    base_url: Optional[str] = Field(None, description="Base URL for agent API")
    session: Optional[Session] = Field(None, description="Active session object")
    
    # Configuration fields
    request_timeout: Optional[int] = Field(180, description="Request timeout in seconds")
    auth_headers: Optional[Dict[str, str]] = Field(None, description="Authentication headers")
    llm_model: Optional[str] = Field(None, description="LLM model identifier")
    
    # Agent behavior and content
    agent_description: Optional[str] = Field("", description="Agent description")
    prompt: Optional[str] = Field("", description="Agent system prompt")
    role: Optional[str] = Field("", description="Agent role")
    welcome_message: Optional[str] = Field(
        "Hi! How can I assist you today?",
        description="Welcome message for users"
    )
    
    # Advanced configuration
    retriever_strategy: Optional[str] = Field(None, description="Retrieval strategy")
    reasoning_algorithm: Optional[str] = Field(None, description="Reasoning algorithm")
    questions: Optional[List[str]] = Field(default_factory=list, description="Predefined questions")
    file_details: Optional[List[FileDetail]] = Field(None, description="Associated file details")
    
    # API and request configuration
    request_url: Optional[str] = Field(None, description="Request URL for agent")
    root_url: Optional[str] = Field(None, description="Root URL for agent")
    request_id: Optional[str] = Field(None, description="Request identifier")
    app_id: Optional[str] = Field(None, description="Application identifier")
    
    # Additional SDK fields
    commit_id: Optional[str] = Field(None, description="Commit identifier")
    initiative_id: Optional[str] = Field(None, description="Initiative identifier")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    control_flags: List[str] = Field(default_factory=list, description="Control flags")
    memory_config: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: MemoryConfig().dict(),
        description="Memory configuration"
    )
    guardrail_config: Optional[Dict[str, Any]] = Field(None, description="Guardrail configuration")
    agent_type: Optional[str] = Field("BYOD", description="Agent type")
    
    # HTTP client placeholders (will be set during initialization)
    stomp_client: Optional[Any] = Field(None, description="STOMP client for messaging")
    http_client: Optional[Any] = Field(None, description="HTTP client for API calls")
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
    
    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate agent_id format.
        
        Args:
            v: The agent_id value to validate
            
        Returns:
            Validated agent_id or None
            
        Raises:
            ValueError: If agent_id format is invalid
        """
        if v is not None:
            # Basic validation - should be non-empty string
            if not isinstance(v, str) or not v.strip():
                raise ValueError("agent_id must be a non-empty string")
            # Remove any whitespace
            v = v.strip()
        return v
    
    @field_validator("env")
    @classmethod
    def validate_env(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate environment value.
        
        Args:
            v: The environment value to validate
            
        Returns:
            Validated environment in uppercase
        """
        if v is not None:
            valid_envs = {"DEV", "QA", "PROD", "LOCAL", "TEST"}
            v_upper = v.upper()
            if v_upper not in valid_envs:
                raise ValueError(f"env must be one of {valid_envs}, got {v}")
            return v_upper
        return v
    
    @field_validator("request_timeout")
    @classmethod
    def validate_timeout(cls, v: Optional[int]) -> Optional[int]:
        """
        Validate request timeout value.
        
        Args:
            v: The timeout value to validate
            
        Returns:
            Validated timeout value
            
        Raises:
            ValueError: If timeout is not positive
        """
        if v is not None and v <= 0:
            raise ValueError("request_timeout must be positive")
        return v
    
    @model_validator(mode="after")
    def generate_agent_id_if_needed(self) -> "AsyncAgent":
        """
        Generate UUID for agent_id if not provided.
        
        Returns:
            Self with agent_id set if it was None
        """
        if self.agent_id is None:
            self.agent_id = str(uuid.uuid4())
        return self
    
    def __init__(self, **data):
        """
        Initialize AsyncAgent with parameter validation.
        
        Args:
            **data: Agent initialization parameters
        """
        super().__init__(**data)
        
        # Initialize HTTP client placeholder if not provided
        if self.http_client is None:
            # This will be set by the concrete implementation
            self.http_client = None
        
        # Initialize session manager if session is provided
        self._session_manager: Optional[SessionManager] = None
        if self.session is not None:
            # Extract JWT token from session if available
            jwt_token = getattr(self.session, 'jwt_token', None)
            if jwt_token:
                self._session_manager = SessionManager(jwt_token=jwt_token)
    
    def set_session_manager(self, session_manager: SessionManager) -> None:
        """
        Set the session manager for this agent.
        
        Args:
            session_manager: SessionManager instance for JWT authentication
        """
        self._session_manager = session_manager
    
    def get_session_manager(self) -> Optional[SessionManager]:
        """
        Get the session manager for this agent.
        
        Returns:
            SessionManager instance or None if not set
        """
        return self._session_manager
    
    def _construct_api_url(self, endpoint: str) -> str:
        """
        Construct full API URL from base URL and endpoint.
        
        Args:
            endpoint: API endpoint path (e.g., "agents/123")
            
        Returns:
            Full URL for the API call
            
        Raises:
            SDKError: If base_url is not configured
        """
        if not self.base_url:
            from ..services.exceptions import SDKError
            raise SDKError("base_url is required for API calls")
        
        # Ensure base_url ends with / and endpoint doesn't start with /
        base = self.base_url.rstrip('/')
        endpoint = endpoint.lstrip('/')
        
        return urljoin(base + '/', endpoint)
    
    async def ensure_authenticated_session(self) -> Session:
        """
        Ensure an authenticated session is available.
        
        Returns:
            Active Session instance
            
        Raises:
            SDKError: If no session manager is available or authentication fails
        """
        if self._session_manager is None:
            from ..services.exceptions import SDKError
            raise SDKError("No session manager available for authentication")
        
        return await self._session_manager.ensure_session()
    
    async def view(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """
        View details of the agent via API call.
        
        Args:
            agent_id: ID of the agent to view. If None, uses the current agent's ID.
            
        Returns:
            Dict containing agent details from the API
            
        Raises:
            SDKError: If API call fails or configuration is invalid
            AgentNotFoundError: If the agent does not exist
            AuthenticationError: If authentication fails
        """
        from ..services.exceptions import SDKError, AgentNotFoundError, AuthenticationError
        
        # Determine which agent ID to use
        target_agent_id = agent_id if agent_id is not None else self.agent_id
        
        if not target_agent_id:
            raise SDKError("No agent_id provided and current agent has no ID")
        
        # Validate base_url is configured
        if not self.base_url:
            raise SDKError("base_url is required for API calls")
        
        # Ensure we have an authenticated session
        try:
            session = await self.ensure_authenticated_session()
        except Exception as e:
            raise AuthenticationError(f"Failed to establish authenticated session: {str(e)}", e)
        
        # Construct the URL for the agent view endpoint
        url = self._construct_api_url(f"agents/{target_agent_id}")
        
        # Prepare headers
        headers = session.get_auth_headers()
        
        # Make the HTTP request
        timeout = self.request_timeout or 180
        
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url, headers=headers)
                
                # Handle different HTTP status codes
                if response.status_code == 200:
                    try:
                        return response.json()
                    except Exception as e:
                        raise SDKError(f"Failed to parse JSON response: {str(e)}", e)
                
                elif response.status_code == 404:
                    raise AgentNotFoundError(target_agent_id)
                
                elif response.status_code == 403:
                    # Handle access restrictions as mentioned in the SDK documentation
                    error_msg = (
                        f"Access denied for agent {target_agent_id}. "
                        "Your access scope may be limited to USER level. "
                        "You may only be able to access agents you have created."
                    )
                    raise AgentNotFoundError(target_agent_id)
                
                elif response.status_code == 401:
                    raise AuthenticationError("Authentication failed - invalid or expired JWT token")
                
                else:
                    # Handle other HTTP errors
                    try:
                        error_detail = response.json().get("detail", "Unknown error")
                    except:
                        error_detail = response.text or "Unknown error"
                    
                    raise SDKError(
                        f"API call failed with status {response.status_code}: {error_detail}"
                    )
        
        except httpx.TimeoutException as e:
            from ..services.exceptions import SDKTimeoutError
            raise SDKTimeoutError(timeout)
        
        except httpx.RequestError as e:
            raise SDKError(f"HTTP request failed: {str(e)}", e)
        
        except (AgentNotFoundError, AuthenticationError, SDKError):
            # Re-raise our custom exceptions as-is
            raise
        
        except Exception as e:
            # Catch any other unexpected errors
            raise SDKError(f"Unexpected error during API call: {str(e)}", e)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert agent to dictionary representation.
        
        Returns:
            Dictionary representation of the agent
        """
        return self.model_dump(exclude_none=True)
    
    def __str__(self) -> str:
        """String representation of the agent."""
        return f"AsyncAgent(id={self.agent_id}, name={self.agent_name}, env={self.env})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the agent."""
        return (
            f"AsyncAgent(agent_id={self.agent_id!r}, agent_name={self.agent_name!r}, "
            f"env={self.env!r}, base_url={self.base_url!r})"
        )
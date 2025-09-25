"""Concrete implementation of Agent SDK using AsyncAgent."""

import asyncio
from typing import Dict, Any, Optional
import structlog

from .interfaces import AgentSDKInterface
from .exceptions import (
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
from ..models.agent_config import AgentSDKConfig, AgentDetailsResponse
from ..models.async_agent import AsyncAgent
from ..models.session import SessionManager

logger = structlog.get_logger(__name__)


class ConcreteAgentSDK(AgentSDKInterface):
    """
    Concrete implementation of Agent SDK using AsyncAgent internally.
    
    This implementation integrates with the real agent service using
    JWT authentication and session management while maintaining
    backward compatibility with the existing AgentSDKInterface.
    """
    
    def __init__(self, config: AgentSDKConfig):
        """
        Initialize ConcreteAgentSDK with configuration.
        
        Args:
            config: AgentSDKConfig instance with all required settings
        """
        self.config = config
        self.session_manager: Optional[SessionManager] = None
        
        # Initialize session manager if JWT token is provided
        if config.jwt_token:
            self.session_manager = SessionManager(jwt_token=config.jwt_token)
        
        logger.info(
            "ConcreteAgentSDK initialized",
            env=config.env,
            base_url=config.base_url,
            timeout=config.request_timeout,
            has_jwt_token=bool(config.jwt_token)
        )
    
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Retrieve agent information using AsyncAgent and transform response.
        
        Args:
            agent_id: The unique identifier for the agent
            
        Returns:
            Dictionary containing agent data in simple format:
            - id: Agent identifier
            - name: Agent name  
            - status: Agent status
            
        Raises:
            SDKError: When SDK operation fails
            AgentNotFoundError: When agent doesn't exist
            SDKTimeoutError: When SDK call times out
            AuthenticationError: When JWT authentication fails
        """
        logger.info("Retrieving agent via ConcreteAgentSDK", agent_id=agent_id)
        
        try:
            # Create AsyncAgent instance with configuration
            async_agent = await self._create_async_agent(agent_id)
            
            # Call view() method to get agent details
            agent_details_raw = await self._call_agent_view_with_retry(async_agent, agent_id)
            
            # Parse and validate the response
            agent_details = self._parse_agent_response(agent_details_raw, agent_id)
            
            # Transform to simple format
            simple_response = agent_details.to_simple_format()
            
            logger.info(
                "Successfully retrieved agent",
                agent_id=agent_id,
                agent_name=simple_response["name"],
                status=simple_response["status"]
            )
            
            return simple_response
            
        except (AgentNotFoundError, AuthenticationError, SDKTimeoutError, AgentAccessError, SDKConnectionError, SDKConfigurationError, SDKResponseError):
            # Re-raise these exceptions as-is (they're already properly mapped)
            raise
            
        except Exception as e:
            logger.error(
                "Unexpected error in ConcreteAgentSDK",
                agent_id=agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            # Use error mapper for consistent error handling
            mapped_error = self._map_sdk_exceptions(e, agent_id, "get_agent")
            raise mapped_error
    
    async def _create_async_agent(self, agent_id: str) -> AsyncAgent:
        """
        Create and configure AsyncAgent instance.
        
        Args:
            agent_id: Agent ID for the AsyncAgent
            
        Returns:
            Configured AsyncAgent instance
            
        Raises:
            SDKError: If configuration is invalid
            AuthenticationError: If session setup fails
        """
        try:
            # Validate configuration before creating AsyncAgent
            if not self.config.base_url:
                raise SDKConfigurationError(
                    "Base URL is required for AsyncAgent creation",
                    missing_fields=["base_url"]
                )
            
            if not self.config.env:
                raise SDKConfigurationError(
                    "Environment is required for AsyncAgent creation",
                    missing_fields=["env"]
                )
            
            # Create AsyncAgent with configuration
            async_agent = AsyncAgent(
                agent_id=agent_id,
                env=self.config.env,
                base_url=self.config.base_url,
                request_timeout=self.config.request_timeout
            )
            
            # Set session manager if available
            if self.session_manager:
                async_agent.set_session_manager(self.session_manager)
            else:
                raise AuthenticationError(
                    "No JWT token configured for authentication",
                    details={"agent_id": agent_id, "operation": "create_async_agent"}
                )
            
            return async_agent
            
        except (AuthenticationError, SDKConfigurationError):
            # Re-raise these as-is
            raise
            
        except Exception as e:
            logger.error(
                "Failed to create AsyncAgent",
                agent_id=agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            # Map the error appropriately
            mapped_error = self._map_sdk_exceptions(e, agent_id, "create_async_agent")
            raise mapped_error
    
    async def _call_agent_view_with_retry(self, async_agent: AsyncAgent, agent_id: str) -> Dict[str, Any]:
        """
        Call AsyncAgent.view() with retry logic.
        
        Args:
            async_agent: AsyncAgent instance
            agent_id: Agent ID to retrieve
            
        Returns:
            Raw agent details from API
            
        Raises:
            SDKTimeoutError: If call times out
            AgentNotFoundError: If agent is not found (no retry)
            AuthenticationError: If authentication fails (no retry)
            SDKError: If call fails after all retries
        """
        last_exception = None
        
        for attempt in range(self.config.retry_count + 1):  # +1 for initial attempt
            try:
                # Call view() with timeout
                agent_details = await asyncio.wait_for(
                    async_agent.view(agent_id),
                    timeout=self.config.request_timeout
                )
                return agent_details
                
            except asyncio.TimeoutError:
                raise SDKTimeoutError(self.config.request_timeout, "agent_view")
                
            except (AgentNotFoundError, AuthenticationError, AgentAccessError, SDKConnectionError):
                # Don't retry for these errors - they won't succeed on retry
                raise
                
            except Exception as e:
                # Map the error to understand if it should be retried
                mapped_error = self._map_sdk_exceptions(e, agent_id, "agent_view")
                
                # Don't retry certain types of errors
                if isinstance(mapped_error, (AgentNotFoundError, AuthenticationError, AgentAccessError, SDKConfigurationError)):
                    raise mapped_error
                
                last_exception = mapped_error
                if attempt < self.config.retry_count:
                    # Wait before retry with exponential backoff
                    wait_time = 2 ** attempt
                    logger.warning(
                        "AsyncAgent view() call failed, retrying",
                        agent_id=agent_id,
                        attempt=attempt + 1,
                        wait_time=wait_time,
                        error=str(e),
                        mapped_error_type=type(mapped_error).__name__
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(
                        "AsyncAgent view() call failed after all retries",
                        agent_id=agent_id,
                        attempts=self.config.retry_count + 1,
                        error=str(e),
                        mapped_error_type=type(mapped_error).__name__
                    )
        
        # If we get here, all retries failed
        raise SDKError(
            f"Agent view call failed after {self.config.retry_count + 1} attempts",
            original_error=last_exception
        )
    
    def _parse_agent_response(self, agent_details_raw: Dict[str, Any], agent_id: str) -> AgentDetailsResponse:
        """
        Parse and validate agent response from API with enhanced validation.
        
        Args:
            agent_details_raw: Raw response from AsyncAgent.view()
            agent_id: Expected agent ID for validation
            
        Returns:
            Validated AgentDetailsResponse instance
            
        Raises:
            SDKResponseError: If response format is invalid
        """
        try:
            # Use enhanced validation method
            agent_details = AgentDetailsResponse.from_dict_with_validation(
                agent_details_raw, 
                agent_id
            )
            
            logger.debug(
                "Successfully parsed agent response",
                agent_id=agent_id,
                agent_name=agent_details.agentName,
                status=agent_details.agentConfig.status,
                tenant_id=agent_details.tenantId
            )
            
            return agent_details
            
        except (TypeError, ValueError) as e:
            logger.error(
                "Failed to parse agent response",
                agent_id=agent_id,
                response_type=type(agent_details_raw).__name__,
                response_keys=list(agent_details_raw.keys()) if isinstance(agent_details_raw, dict) else "not_dict",
                error=str(e),
                error_type=type(e).__name__
            )
            raise SDKResponseError(
                f"Invalid agent response format: {str(e)}", 
                agent_details_raw,
                "AgentDetailsResponse",
                e
            )
            
        except Exception as e:
            logger.error(
                "Unexpected error parsing agent response",
                agent_id=agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise SDKResponseError(
                f"Failed to parse agent response: {str(e)}", 
                agent_details_raw,
                "AgentDetailsResponse",
                e
            )
    
    def _map_sdk_exceptions(self, error: Exception, agent_id: str = None, operation: str = None) -> Exception:
        """
        Map SDK-specific exceptions to existing exception types using enhanced error mapper.
        
        Args:
            error: Original exception from SDK
            agent_id: Agent ID for context
            operation: Operation being performed for context
            
        Returns:
            Mapped exception
        """
        from .exceptions import SDKErrorMapper
        
        error_type = type(error).__name__
        error_message = str(error).lower()
        
        # Map HTTP-related errors
        if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
            return SDKErrorMapper.map_http_status_error(
                error.response.status_code, 
                agent_id, 
                getattr(error.response, 'text', None)
            )
        
        # Map connection errors
        if any(keyword in error_type.lower() for keyword in ['connection', 'timeout', 'network', 'dns']):
            return SDKErrorMapper.map_connection_error(error, self.config.base_url)
        
        # Map authentication errors
        if any(keyword in error_message for keyword in ['authentication', 'unauthorized', 'jwt', 'token', 'auth']):
            return SDKErrorMapper.map_authentication_error(error, operation)
        
        # Map session errors
        if any(keyword in error_message for keyword in ['session', 'expired']):
            return SDKErrorMapper.map_session_error(error, operation)
        
        # Map specific SDK error patterns based on keywords in error message
        if "not found" in error_message or "404" in error_message:
            return AgentNotFoundError(agent_id or "unknown", "Agent not found")
        
        elif "access denied" in error_message or "403" in error_message or "permission denied" in error_message:
            from .exceptions import AgentAccessError
            return AgentAccessError(agent_id or "unknown")
        
        elif "timeout" in error_message or "timed out" in error_message:
            timeout = getattr(error, 'timeout_seconds', self.config.request_timeout)
            return SDKTimeoutError(timeout, operation)
        
        else:
            # Generic SDK error with enhanced context
            return SDKErrorMapper.map_generic_sdk_error(error, operation, agent_id)
    
    def get_config(self) -> AgentSDKConfig:
        """
        Get current SDK configuration.
        
        Returns:
            Current AgentSDKConfig instance
        """
        return self.config
    
    def is_authenticated(self) -> bool:
        """
        Check if SDK is properly authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return (
            self.session_manager is not None and 
            self.session_manager.is_authenticated()
        )
    
    async def health_check(self) -> bool:
        """
        Perform a health check on the SDK connection.
        
        Returns:
            True if SDK is healthy, False otherwise
        """
        try:
            # Try to create a basic AsyncAgent to test configuration
            test_agent = AsyncAgent(
                agent_id="health-check",
                env=self.config.env,
                base_url=self.config.base_url,
                request_timeout=min(self.config.request_timeout, 10)  # Short timeout for health check
            )
            
            if self.session_manager:
                test_agent.set_session_manager(self.session_manager)
            
            # If we can create the agent and it has proper configuration, consider it healthy
            return (
                test_agent.base_url is not None and
                test_agent.env is not None and
                self.is_authenticated()
            )
            
        except Exception as e:
            logger.warning("SDK health check failed", error=str(e))
            return False
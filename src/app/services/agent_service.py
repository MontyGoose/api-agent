"""Agent service for handling agent status operations."""

import re
import asyncio
from typing import Optional
from fastapi import HTTPException, status
import structlog

from app.models.schemas import AgentStatusResponse
from app.services.interfaces import AgentSDKInterface
from app.services.exceptions import (
    SDKError,
    AgentNotFoundError,
    SDKTimeoutError,
    InvalidAgentIdError,
    AuthenticationError,
    SessionError,
    SDKConfigurationError,
)

logger = structlog.get_logger(__name__)


class AgentService:
    """Service for agent operations and SDK integration."""
    
    # Agent ID validation pattern: alphanumeric, hyphens, underscores, 1-255 chars
    AGENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9\-_]{1,255}$")
    
    def __init__(
        self, 
        sdk: AgentSDKInterface,
        timeout_seconds: int = 30,
        retry_count: int = 3
    ):
        """
        Initialize the agent service.
        
        Args:
            sdk: The SDK interface implementation
            timeout_seconds: Timeout for SDK calls
            retry_count: Number of retry attempts for failed SDK calls
        """
        self.sdk = sdk
        self.timeout_seconds = timeout_seconds
        self.retry_count = retry_count
    
    async def get_agent_status(self, agent_id: str) -> AgentStatusResponse:
        """
        Retrieve agent status information.
        
        Args:
            agent_id: The unique identifier for the agent
            
        Returns:
            AgentStatusResponse with agent information
            
        Raises:
            HTTPException: For various error conditions with appropriate status codes
        """
        # Validate agent ID format
        self._validate_agent_id(agent_id)
        
        logger.info("Retrieving agent status", agent_id=agent_id)
        
        try:
            # Call SDK with timeout and retry logic
            agent_data = await self._call_sdk_with_retry(agent_id)
            
            # Transform SDK response to our model
            response = self._transform_sdk_response(agent_data, agent_id)
            
            logger.info(
                "Successfully retrieved agent status",
                agent_id=agent_id,
                status=response.status
            )
            
            return response
            
        except InvalidAgentIdError as e:
            logger.warning("Invalid agent ID format", agent_id=agent_id, error=str(e))
            raise self._handle_validation_error(e)
            
        except AgentNotFoundError as e:
            logger.warning("Agent not found", agent_id=agent_id)
            raise self._handle_not_found_error(e)
            
        except SDKTimeoutError as e:
            logger.error("SDK timeout", agent_id=agent_id, timeout=e.timeout_seconds)
            raise self._handle_timeout_error(e)
            
        except (AuthenticationError, SessionError, SDKConfigurationError) as e:
            logger.error(
                "SDK authentication/configuration error", 
                agent_id=agent_id, 
                error=str(e),
                error_type=type(e).__name__
            )
            raise self._handle_sdk_error(e)
            
        except SDKError as e:
            logger.error(
                "SDK error", 
                agent_id=agent_id, 
                error=str(e),
                original_error=str(e.original_error) if e.original_error else None
            )
            raise self._handle_sdk_error(e)
            
        except Exception as e:
            logger.error("Unexpected error", agent_id=agent_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": {
                        "message": "Internal server error occurred",
                        "code": "INTERNAL_ERROR",
                        "details": {"agent_id": agent_id}
                    }
                }
            )
    
    def _validate_agent_id(self, agent_id: str) -> None:
        """
        Validate agent ID format.
        
        Args:
            agent_id: The agent ID to validate
            
        Raises:
            InvalidAgentIdError: If agent ID format is invalid
        """
        if not agent_id:
            raise InvalidAgentIdError(agent_id, "Agent ID cannot be empty")
        
        if not isinstance(agent_id, str):
            raise InvalidAgentIdError(str(agent_id), "Agent ID must be a string")
        
        if not self.AGENT_ID_PATTERN.match(agent_id):
            raise InvalidAgentIdError(
                agent_id, 
                "Agent ID must contain only alphanumeric characters, hyphens, and underscores (1-255 chars)"
            )
    
    async def _call_sdk_with_retry(self, agent_id: str) -> dict:
        """
        Call SDK with timeout and retry logic.
        
        Args:
            agent_id: The agent ID to retrieve
            
        Returns:
            Raw SDK response data
            
        Raises:
            SDKTimeoutError: If SDK call times out
            SDKError: If SDK call fails after retries
            AgentNotFoundError: If agent is not found
        """
        last_exception = None
        
        for attempt in range(self.retry_count):
            try:
                # Call SDK with timeout
                agent_data = await asyncio.wait_for(
                    self.sdk.get_agent(agent_id),
                    timeout=self.timeout_seconds
                )
                return agent_data
                
            except asyncio.TimeoutError:
                raise SDKTimeoutError(self.timeout_seconds)
                
            except (AgentNotFoundError, AuthenticationError, SessionError, InvalidAgentIdError, SDKConfigurationError):
                # Don't retry for these errors - they won't succeed on retry
                raise
                
            except Exception as e:
                last_exception = e
                if attempt < self.retry_count - 1:
                    # Wait before retry with exponential backoff
                    wait_time = 2 ** attempt
                    logger.warning(
                        "SDK call failed, retrying",
                        agent_id=agent_id,
                        attempt=attempt + 1,
                        wait_time=wait_time,
                        error=str(e)
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(
                        "SDK call failed after all retries",
                        agent_id=agent_id,
                        attempts=self.retry_count,
                        error=str(e)
                    )
        
        # If we get here, all retries failed
        raise SDKError(
            f"SDK call failed after {self.retry_count} attempts",
            original_error=last_exception
        )
    
    def _transform_sdk_response(self, agent_data: dict, agent_id: str) -> AgentStatusResponse:
        """
        Transform SDK response to AgentStatusResponse model.
        
        Args:
            agent_data: Raw SDK response data
            agent_id: The requested agent ID for validation
            
        Returns:
            AgentStatusResponse model
            
        Raises:
            SDKError: If response format is invalid
        """
        try:
            # Validate required fields are present
            required_fields = ["id", "name", "status"]
            missing_fields = [field for field in required_fields if field not in agent_data]
            
            if missing_fields:
                raise SDKError(
                    f"SDK response missing required fields: {', '.join(missing_fields)}"
                )
            
            # Validate that returned ID matches requested ID
            if agent_data["id"] != agent_id:
                raise SDKError(
                    f"SDK returned different agent ID: expected '{agent_id}', got '{agent_data['id']}'"
                )
            
            # Create and validate the response model
            return AgentStatusResponse(
                id=agent_data["id"],
                agent_name=agent_data["name"],
                status=agent_data["status"]
            )
            
        except (KeyError, TypeError, ValueError) as e:
            raise SDKError(
                f"Invalid SDK response format: {str(e)}",
                original_error=e
            )
    
    def _handle_validation_error(self, error: InvalidAgentIdError) -> HTTPException:
        """Handle agent ID validation errors."""
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": {
                    "message": str(error),
                    "code": "INVALID_AGENT_ID",
                    "details": {
                        "agent_id": error.agent_id,
                        "reason": error.reason
                    }
                }
            }
        )
    
    def _handle_not_found_error(self, error: AgentNotFoundError) -> HTTPException:
        """Handle agent not found errors."""
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "message": str(error),
                    "code": "AGENT_NOT_FOUND",
                    "details": {"agent_id": error.agent_id}
                }
            }
        )
    
    def _handle_timeout_error(self, error: SDKTimeoutError) -> HTTPException:
        """Handle SDK timeout errors."""
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": {
                    "message": "Agent service is currently unavailable",
                    "code": "SERVICE_TIMEOUT",
                    "details": {"timeout_seconds": error.timeout_seconds}
                }
            }
        )
    
    def _handle_sdk_error(self, error: SDKError) -> HTTPException:
        """Handle general SDK errors."""
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": {
                    "message": "Agent service error occurred",
                    "code": "SERVICE_ERROR",
                    "details": {"error_message": str(error)}
                }
            }
        )
"""Agent status API endpoints."""

from fastapi import APIRouter, Depends, Path
from typing import Annotated
import structlog

from app.api.deps import get_current_user, get_agent_service
from app.models.schemas import User, AgentStatusResponse, ErrorResponse
from app.services.agent_service import AgentService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["agents"])


@router.get(
    "/{agent_id}",
    response_model=AgentStatusResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "Agent not found"},
        422: {"model": ErrorResponse, "description": "Invalid agent ID"},
        502: {"model": ErrorResponse, "description": "Agent service error"},
    },
    summary="Get agent status",
    description="Retrieve status and basic information for a specific agent by ID",
)
async def get_agent_status(
    agent_id: Annotated[str, Path(
        description="Agent unique identifier",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9\-_]+$"
    )],
    user: Annotated[User, Depends(get_current_user)],
    agent_service: Annotated[AgentService, Depends(get_agent_service)]
) -> AgentStatusResponse:
    """
    Get agent status information.
    
    Retrieves the current status and basic information for the specified agent.
    Requires authentication and appropriate permissions.
    
    Args:
        agent_id: The unique identifier for the agent
        user: Authenticated user (injected by dependency)
        agent_service: Agent service instance (injected by dependency)
        
    Returns:
        AgentStatusResponse containing agent information
        
    Raises:
        HTTPException: Various HTTP errors based on the failure type
    """
    # Log the incoming request
    logger.info(
        "Agent status request received",
        agent_id=agent_id,
        user=user.username,
        user_roles=user.roles
    )
    
    try:
        # Call the service layer to get agent status
        response = await agent_service.get_agent_status(agent_id)
        
        # Log successful response
        logger.info(
            "Agent status request completed successfully",
            agent_id=agent_id,
            user=user.username,
            agent_name=response.agent_name,
            status=response.status
        )
        
        return response
        
    except Exception as e:
        # Log the error (service layer already logs detailed errors)
        logger.error(
            "Agent status request failed",
            agent_id=agent_id,
            user=user.username,
            error=str(e)
        )
        # Re-raise the exception to let FastAPI handle the HTTP response
        raise
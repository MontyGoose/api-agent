"""Factory functions for creating service instances."""

from app.core.config import get_settings
from app.services.agent_service import AgentService
from app.services.interfaces import AgentSDKInterface


def create_agent_service(sdk: AgentSDKInterface) -> AgentService:
    """
    Create an AgentService instance with configuration from settings.
    
    Args:
        sdk: The SDK interface implementation
        
    Returns:
        Configured AgentService instance
    """
    settings = get_settings()
    
    return AgentService(
        sdk=sdk,
        timeout_seconds=settings.AGENT_SDK_TIMEOUT,
        retry_count=settings.AGENT_SDK_RETRY_COUNT
    )
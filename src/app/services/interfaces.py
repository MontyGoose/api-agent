"""Abstract interfaces for external service integrations."""

from abc import ABC, abstractmethod
from typing import Dict, Any


class AgentSDKInterface(ABC):
    """Abstract interface for Python SDK integration."""
    
    @abstractmethod
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Retrieve agent information from the SDK.
        
        Args:
            agent_id: The unique identifier for the agent
            
        Returns:
            Dictionary containing agent data with at minimum:
            - id: Agent identifier
            - name: Agent name
            - status: Agent status
            
        Raises:
            SDKError: When SDK operation fails
            AgentNotFoundError: When agent doesn't exist
            SDKTimeoutError: When SDK call times out
        """
        pass
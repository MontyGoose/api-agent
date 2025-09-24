"""Mock implementation of AgentSDK for development and testing."""

import asyncio
from typing import Dict, Any

from app.services.interfaces import AgentSDKInterface
from app.services.exceptions import AgentNotFoundError, SDKError


class MockAgentSDK(AgentSDKInterface):
    """Mock implementation of the Agent SDK for development purposes."""
    
    # Mock data for testing
    MOCK_AGENTS = {
        "agent-123": {
            "id": "agent-123",
            "name": "Customer Support Bot",
            "status": "active"
        },
        "agent-456": {
            "id": "agent-456", 
            "name": "Sales Assistant",
            "status": "inactive"
        },
        "agent-789": {
            "id": "agent-789",
            "name": "Technical Support Agent", 
            "status": "busy"
        }
    }
    
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Mock implementation of agent retrieval.
        
        Args:
            agent_id: The unique identifier for the agent
            
        Returns:
            Dictionary containing mock agent data
            
        Raises:
            AgentNotFoundError: When agent doesn't exist in mock data
            SDKError: For simulated SDK errors
        """
        # Simulate network delay
        await asyncio.sleep(0.1)
        
        # Simulate SDK error for specific test agent ID
        if agent_id == "error-agent":
            raise SDKError("Simulated SDK error")
        
        # Check if agent exists in mock data
        if agent_id not in self.MOCK_AGENTS:
            raise AgentNotFoundError(agent_id)
        
        return self.MOCK_AGENTS[agent_id].copy()
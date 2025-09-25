"""Mock implementation of AgentSDK for development and testing."""

import asyncio
import structlog
from typing import Dict, Any, Optional

from app.services.interfaces import AgentSDKInterface
from app.services.exceptions import AgentNotFoundError, SDKError

logger = structlog.get_logger(__name__)


class MockAgentSDK(AgentSDKInterface):
    """
    Mock implementation of the Agent SDK for development purposes.
    
    This implementation provides realistic mock data and behavior patterns
    that match the real SDK, making it suitable for development and testing
    without requiring external service dependencies.
    """
    
    # Enhanced mock data for testing various scenarios
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
        },
        "agent-indexing": {
            "id": "agent-indexing",
            "name": "Indexing Agent",
            "status": "indexing"
        },
        "agent-error": {
            "id": "agent-error",
            "name": "Error Test Agent",
            "status": "error"
        }
    }
    
    def __init__(self, simulate_delays: bool = True, simulate_errors: bool = True):
        """
        Initialize MockAgentSDK with configurable behavior.
        
        Args:
            simulate_delays: Whether to simulate network delays
            simulate_errors: Whether to simulate error conditions
        """
        self.simulate_delays = simulate_delays
        self.simulate_errors = simulate_errors
        
        logger.info(
            "MockAgentSDK initialized",
            simulate_delays=simulate_delays,
            simulate_errors=simulate_errors,
            available_agents=len(self.MOCK_AGENTS)
        )
    
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Mock implementation of agent retrieval with enhanced error simulation.
        
        Args:
            agent_id: The unique identifier for the agent
            
        Returns:
            Dictionary containing mock agent data
            
        Raises:
            AgentNotFoundError: When agent doesn't exist in mock data
            SDKError: For simulated SDK errors
        """
        logger.debug(
            "MockAgentSDK.get_agent called",
            agent_id=agent_id,
            simulate_delays=self.simulate_delays,
            simulate_errors=self.simulate_errors
        )
        
        # Simulate network delay if enabled
        if self.simulate_delays:
            await asyncio.sleep(0.1)
        
        # Simulate various error conditions if enabled
        if self.simulate_errors:
            # Simulate SDK error for specific test agent ID
            if agent_id == "error-agent":
                logger.debug("Simulating SDK error for error-agent")
                raise SDKError("Simulated SDK error for testing")
            
            # Simulate timeout error
            if agent_id == "timeout-agent":
                logger.debug("Simulating timeout error for timeout-agent")
                await asyncio.sleep(2)  # Longer delay to simulate timeout
                raise SDKError("Simulated timeout error")
            
            # Simulate authentication error
            if agent_id == "auth-error-agent":
                logger.debug("Simulating authentication error for auth-error-agent")
                raise SDKError("Simulated authentication error")
        
        # Check if agent exists in mock data
        if agent_id not in self.MOCK_AGENTS:
            logger.debug(
                "Agent not found in mock data",
                agent_id=agent_id,
                available_agents=list(self.MOCK_AGENTS.keys())
            )
            raise AgentNotFoundError(agent_id)
        
        # Return mock agent data
        agent_data = self.MOCK_AGENTS[agent_id].copy()
        logger.debug(
            "Returning mock agent data",
            agent_id=agent_id,
            agent_name=agent_data.get("name"),
            agent_status=agent_data.get("status")
        )
        
        return agent_data
    
    def add_mock_agent(self, agent_id: str, agent_data: Dict[str, Any]) -> None:
        """
        Add a new mock agent for testing purposes.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_data: Agent data dictionary
        """
        self.MOCK_AGENTS[agent_id] = agent_data.copy()
        logger.debug(
            "Added mock agent",
            agent_id=agent_id,
            agent_name=agent_data.get("name")
        )
    
    def remove_mock_agent(self, agent_id: str) -> bool:
        """
        Remove a mock agent.
        
        Args:
            agent_id: Unique identifier for the agent to remove
            
        Returns:
            True if agent was removed, False if it didn't exist
        """
        if agent_id in self.MOCK_AGENTS:
            del self.MOCK_AGENTS[agent_id]
            logger.debug("Removed mock agent", agent_id=agent_id)
            return True
        return False
    
    def get_available_agents(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all available mock agents.
        
        Returns:
            Dictionary of all mock agents
        """
        return self.MOCK_AGENTS.copy()
    
    def reset_to_defaults(self) -> None:
        """Reset mock agents to default set."""
        self.MOCK_AGENTS = {
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
            },
            "agent-indexing": {
                "id": "agent-indexing",
                "name": "Indexing Agent",
                "status": "indexing"
            },
            "agent-error": {
                "id": "agent-error",
                "name": "Error Test Agent",
                "status": "error"
            }
        }
        logger.debug("Reset mock agents to defaults")
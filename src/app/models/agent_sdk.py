"""Agent SDK data models and configuration."""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class AgentSDKConfig(BaseModel):
    """Configuration for Agent SDK integration."""
    
    env: str = Field(..., description="Environment (DEV, QA, PROD)")
    base_url: str = Field(..., description="Base URL for agent API")
    jwt_token: Optional[str] = Field(None, description="JWT token for authentication")
    request_timeout: int = Field(180, description="Request timeout in seconds")
    retry_count: int = Field(3, description="Number of retry attempts")
    mock_mode: bool = Field(False, description="Force mock mode")
    
    @classmethod
    def from_settings(cls, settings) -> 'AgentSDKConfig':
        """Create AgentSDKConfig from application settings."""
        return cls(
            env=settings.AGENT_SDK_ENV,
            base_url=settings.AGENT_SDK_BASE_URL,
            jwt_token=settings.AGENT_SDK_JWT_TOKEN,
            request_timeout=settings.AGENT_SDK_TIMEOUT,
            retry_count=settings.AGENT_SDK_RETRY_COUNT,
            mock_mode=settings.AGENT_SDK_MOCK_MODE
        )


class AgentConfig(BaseModel):
    """Agent configuration details from SDK response."""
    
    version: str
    ownerId: str
    agentType: str = "BYOD"
    group: str = "Personal"
    requestUrl: str
    rootUrl: str
    llmModel: str
    status: str
    retrieverStrategy: str
    reasoningAlgorithm: str
    vectorStorage: Optional[str] = None
    azureSearchService: Optional[str] = None
    azureSearchIndex: Optional[str] = None
    azureCosmosDBConfig: Optional[Dict[str, str]] = None
    welcomeMessage: str = "Welcome. How may I assist you?"
    controlFlags: List[str] = Field(default_factory=list)
    initiativeId: Optional[str] = None
    defaultNuggetId: Optional[str] = None
    uiType: str = "chat"
    id: str
    agentHistId: Optional[str] = None
    histActiveFrom: Optional[str] = None
    histActiveTo: Optional[str] = None
    updateTs: Optional[str] = None
    updateUser: Optional[str] = None
    createTs: Optional[str] = None
    createUser: Optional[str] = None


class AgentDetailsResponse(BaseModel):
    """Complete agent details response from SDK."""
    
    agentId: str = Field(..., description="Agent unique identifier")
    agentName: str = Field(..., description="Agent display name")
    orgId: str = Field("", description="Organization ID")
    tenantId: str = Field(..., description="Tenant ID")
    agentConfig: AgentConfig = Field(..., description="Detailed agent configuration")
    
    def to_simple_format(self) -> Dict[str, Any]:
        """Transform to simple format for backward compatibility."""
        return {
            "id": self.agentId,
            "name": self.agentName,
            "status": self.agentConfig.status.lower()
        }
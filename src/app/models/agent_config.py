"""Configuration models for Agent SDK implementation."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.config import Settings


class AgentSDKConfig(BaseModel):
    """
    Configuration model for Agent SDK.
    
    This model contains all the configuration needed to initialize
    and use the concrete Agent SDK implementation.
    """
    
    env: str = Field(..., description="Environment (DEV, QA, PROD)")
    base_url: str = Field(..., description="Base URL for agent API")
    jwt_token: Optional[str] = Field(None, description="JWT token for authentication")
    request_timeout: int = Field(180, description="Request timeout in seconds")
    retry_count: int = Field(3, description="Number of retry attempts")
    mock_mode: bool = Field(False, description="Force mock mode")
    
    @field_validator("env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        """Validate and normalize environment value."""
        valid_envs = {"DEV", "QA", "PROD", "LOCAL", "TEST"}
        v_upper = v.upper()
        if v_upper not in valid_envs:
            raise ValueError(f"env must be one of {valid_envs}, got {v}")
        return v_upper
    
    @field_validator("request_timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout value."""
        if v <= 0:
            raise ValueError("request_timeout must be positive")
        return v
    
    @field_validator("retry_count")
    @classmethod
    def validate_retry_count(cls, v: int) -> int:
        """Validate retry count."""
        if v < 0:
            raise ValueError("retry_count must be non-negative")
        return v
    
    @model_validator(mode="after")
    def validate_production_requirements(self):
        """Validate configuration requirements for production environments."""
        if self.env in ["PROD", "QA"] and not self.mock_mode:
            if not self.jwt_token:
                raise ValueError(f"jwt_token is required for {self.env} environment when not in mock mode")
            
            if self.jwt_token == "your-jwt-token-here":
                raise ValueError("jwt_token must be changed from default value in production")
            
            if self.base_url == "https://lm.qa.example.net" and self.env == "PROD":
                raise ValueError("base_url must be changed from default value in production")
        
        return self
    
    def validate_for_real_usage(self) -> None:
        """
        Validate configuration is suitable for real SDK usage (not mock).
        
        Raises:
            ValueError: If configuration is not suitable for real usage
        """
        if self.mock_mode:
            return  # Mock mode doesn't need real configuration
        
        if not self.jwt_token:
            raise ValueError("jwt_token is required for real SDK usage")
        
        if not self.base_url:
            raise ValueError("base_url is required for real SDK usage")
        
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be a valid URL")
    
    @classmethod
    def from_settings(cls, settings: Settings) -> "AgentSDKConfig":
        """
        Create AgentSDKConfig from application settings.
        
        Args:
            settings: Application settings instance
            
        Returns:
            AgentSDKConfig instance with validation
            
        Raises:
            ValueError: If settings are invalid for the configuration
        """
        # Check if settings are valid for Agent SDK usage
        is_valid, errors = settings.validate_agent_sdk_config()
        if not is_valid and settings.requires_real_sdk:
            raise ValueError(f"Invalid Agent SDK configuration: {'; '.join(errors)}")
        
        config = cls(
            env=settings.AGENT_SDK_ENV,
            base_url=settings.AGENT_SDK_BASE_URL,
            jwt_token=settings.AGENT_SDK_JWT_TOKEN,
            request_timeout=settings.AGENT_SDK_TIMEOUT,
            retry_count=settings.AGENT_SDK_RETRY_COUNT,
            mock_mode=settings.AGENT_SDK_MOCK_MODE
        )
        
        # Additional validation for real usage if needed
        if settings.requires_real_sdk:
            config.validate_for_real_usage()
        
        return config


class AgentConfig(BaseModel):
    """
    Agent configuration model matching SDK JSON structure.
    
    This model represents the agentConfig section from the SDK response.
    """
    
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
    welcomeMessage: Optional[str] = "Hi! How can I assist you today?"
    controlFlags: Optional[list[str]] = Field(default_factory=list)
    initiativeId: Optional[str] = None
    defaultNuggetId: Optional[str] = None
    uiType: Optional[str] = "chat"
    id: Optional[str] = None
    agentHistId: Optional[str] = None
    histActiveFrom: Optional[str] = None
    histActiveTo: Optional[str] = None
    updateTs: Optional[str] = None
    updateUser: Optional[str] = None
    createTs: Optional[str] = None
    createUser: Optional[str] = None


class AgentDetailsResponse(BaseModel):
    """
    Complete agent details response model matching SDK JSON structure.
    
    This model represents the full response from the agent view API call.
    """
    
    agentId: str = Field(..., min_length=1, description="Agent unique identifier")
    agentName: str = Field(..., min_length=1, description="Agent display name")
    orgId: str = Field("", description="Organization ID")
    tenantId: str = Field(..., min_length=1, description="Tenant ID")
    agentConfig: AgentConfig = Field(..., description="Detailed agent configuration")
    
    @field_validator("agentId")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        """Validate agent ID format."""
        if not v or not v.strip():
            raise ValueError("agentId cannot be empty")
        return v.strip()
    
    @field_validator("agentName")
    @classmethod
    def validate_agent_name(cls, v: str) -> str:
        """Validate agent name."""
        if not v or not v.strip():
            raise ValueError("agentName cannot be empty")
        return v.strip()
    
    @field_validator("tenantId")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID."""
        if not v or not v.strip():
            raise ValueError("tenantId cannot be empty")
        return v.strip()
    
    def to_simple_format(self) -> Dict[str, Any]:
        """
        Transform detailed agent response to simple format for backward compatibility.
        
        This method ensures the response format matches what existing code expects
        and what the MockAgentSDK returns.
        
        Returns:
            Dictionary in simple format with keys: id, name, status
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        # Validate that we have the required data for transformation
        if not self.agentId:
            raise ValueError("Cannot transform response: agentId is required")
        
        if not self.agentName:
            raise ValueError("Cannot transform response: agentName is required")
        
        if not self.agentConfig or not self.agentConfig.status:
            raise ValueError("Cannot transform response: agentConfig.status is required")
        
        # Normalize status to lowercase for consistency
        status = self.agentConfig.status.strip().lower()
        if not status:
            raise ValueError("Cannot transform response: status cannot be empty")
        
        return {
            "id": self.agentId,
            "name": self.agentName,
            "status": status
        }
    
    def validate_response_completeness(self) -> None:
        """
        Validate that the response contains all required fields for a complete agent.
        
        This method performs additional validation beyond Pydantic's basic validation
        to ensure the response is suitable for use in the application.
        
        Raises:
            ValueError: If the response is incomplete or invalid
        """
        # Check core identification fields
        if not self.agentId or not self.agentId.strip():
            raise ValueError("Agent response missing or empty agentId")
        
        if not self.agentName or not self.agentName.strip():
            raise ValueError("Agent response missing or empty agentName")
        
        if not self.tenantId or not self.tenantId.strip():
            raise ValueError("Agent response missing or empty tenantId")
        
        # Check agent configuration
        if not self.agentConfig:
            raise ValueError("Agent response missing agentConfig")
        
        # Validate critical agentConfig fields
        required_config_fields = {
            "status": "Agent status",
            "llmModel": "LLM model",
            "requestUrl": "Request URL",
            "rootUrl": "Root URL"
        }
        
        for field_name, field_description in required_config_fields.items():
            field_value = getattr(self.agentConfig, field_name, None)
            if not field_value or (isinstance(field_value, str) and not field_value.strip()):
                raise ValueError(f"Agent response missing or empty agentConfig.{field_name} ({field_description})")
        
        # Validate URLs are properly formatted (basic check)
        for url_field in ["requestUrl", "rootUrl"]:
            url_value = getattr(self.agentConfig, url_field)
            if not url_value.startswith(("http://", "https://")):
                raise ValueError(f"Agent response agentConfig.{url_field} must be a valid URL")
    
    @classmethod
    def from_dict_with_validation(cls, data: Dict[str, Any], agent_id: Optional[str] = None) -> "AgentDetailsResponse":
        """
        Create AgentDetailsResponse from dictionary with enhanced validation.
        
        Args:
            data: Raw response data from SDK
            agent_id: Expected agent ID for validation (optional)
            
        Returns:
            Validated AgentDetailsResponse instance
            
        Raises:
            ValueError: If data is invalid or doesn't match expected agent_id
            TypeError: If data is not a dictionary
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dictionary, got {type(data).__name__}")
        
        # Create the instance (this will run Pydantic validation)
        instance = cls(**data)
        
        # Run additional validation
        instance.validate_response_completeness()
        
        # Validate agent ID matches if provided
        if agent_id and instance.agentId != agent_id:
            raise ValueError(
                f"Response agent ID mismatch: expected '{agent_id}', got '{instance.agentId}'"
            )
        
        return instance
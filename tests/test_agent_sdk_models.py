"""Tests for Agent SDK models and configuration."""

import pytest
from pydantic import ValidationError
from unittest.mock import Mock

from app.models.agent_sdk import AgentSDKConfig, AgentConfig, AgentDetailsResponse


class TestAgentSDKConfig:
    """Test cases for AgentSDKConfig model."""
    
    def test_agent_sdk_config_creation(self):
        """Test creating AgentSDKConfig with valid data."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://lm.qa.example.net",
            jwt_token="test-token",
            request_timeout=180,
            retry_count=3,
            mock_mode=False
        )
        
        assert config.env == "DEV"
        assert config.base_url == "https://lm.qa.example.net"
        assert config.jwt_token == "test-token"
        assert config.request_timeout == 180
        assert config.retry_count == 3
        assert config.mock_mode is False
    
    def test_agent_sdk_config_defaults(self):
        """Test AgentSDKConfig with default values."""
        config = AgentSDKConfig(
            env="PROD",
            base_url="https://api.example.com"
        )
        
        assert config.env == "PROD"
        assert config.base_url == "https://api.example.com"
        assert config.jwt_token is None
        assert config.request_timeout == 180
        assert config.retry_count == 3
        assert config.mock_mode is False
    
    def test_agent_sdk_config_from_settings(self):
        """Test creating AgentSDKConfig from settings object."""
        # Mock settings object
        mock_settings = Mock()
        mock_settings.AGENT_SDK_ENV = "QA"
        mock_settings.AGENT_SDK_BASE_URL = "https://qa.example.com"
        mock_settings.AGENT_SDK_JWT_TOKEN = "qa-token"
        mock_settings.AGENT_SDK_TIMEOUT = 120
        mock_settings.AGENT_SDK_RETRY_COUNT = 5
        mock_settings.AGENT_SDK_MOCK_MODE = True
        
        config = AgentSDKConfig.from_settings(mock_settings)
        
        assert config.env == "QA"
        assert config.base_url == "https://qa.example.com"
        assert config.jwt_token == "qa-token"
        assert config.request_timeout == 120
        assert config.retry_count == 5
        assert config.mock_mode is True
    
    def test_agent_sdk_config_validation_errors(self):
        """Test AgentSDKConfig validation errors."""
        # Missing required fields
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig()
        
        errors = exc_info.value.errors()
        error_fields = {error['loc'][0] for error in errors}
        assert 'env' in error_fields
        assert 'base_url' in error_fields


class TestAgentConfig:
    """Test cases for AgentConfig model."""
    
    def test_agent_config_creation(self):
        """Test creating AgentConfig with valid data."""
        config = AgentConfig(
            version="3",
            ownerId="owner123",
            agentType="BYOD",
            group="Personal",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="ACTIVE",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent123"
        )
        
        assert config.version == "3"
        assert config.ownerId == "owner123"
        assert config.agentType == "BYOD"
        assert config.group == "Personal"
        assert config.status == "ACTIVE"
        assert config.id == "agent123"
    
    def test_agent_config_defaults(self):
        """Test AgentConfig with default values."""
        config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="ACTIVE",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent123"
        )
        
        assert config.agentType == "BYOD"
        assert config.group == "Personal"
        assert config.welcomeMessage == "Welcome. How may I assist you?"
        assert config.controlFlags == []
        assert config.uiType == "chat"
        assert config.vectorStorage is None
    
    def test_agent_config_with_optional_fields(self):
        """Test AgentConfig with optional fields populated."""
        azure_config = {"dbId": "cog-db-01", "containerId": "cog-container-01"}
        
        config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="INDEXING",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            vectorStorage="AZURE_SEARCH",
            azureSearchService="search-service",
            azureSearchIndex="cog-user-01",
            azureCosmosDBConfig=azure_config,
            controlFlags=["USE_HYBRID_RAG", "EXTRACT_EXTENDED_ATTRIBUTES"],
            initiativeId="init001",
            defaultNuggetId="nugget-123",
            id="agent123"
        )
        
        assert config.vectorStorage == "AZURE_SEARCH"
        assert config.azureSearchService == "search-service"
        assert config.azureSearchIndex == "cog-user-01"
        assert config.azureCosmosDBConfig == azure_config
        assert config.controlFlags == ["USE_HYBRID_RAG", "EXTRACT_EXTENDED_ATTRIBUTES"]
        assert config.initiativeId == "init001"
        assert config.defaultNuggetId == "nugget-123"


class TestAgentDetailsResponse:
    """Test cases for AgentDetailsResponse model."""
    
    def test_agent_details_response_creation(self):
        """Test creating AgentDetailsResponse with valid data."""
        agent_config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="ACTIVE",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent123"
        )
        
        response = AgentDetailsResponse(
            agentId="agent123",
            agentName="Test Agent",
            orgId="org456",
            tenantId="DEV",
            agentConfig=agent_config
        )
        
        assert response.agentId == "agent123"
        assert response.agentName == "Test Agent"
        assert response.orgId == "org456"
        assert response.tenantId == "DEV"
        assert response.agentConfig == agent_config
    
    def test_agent_details_response_defaults(self):
        """Test AgentDetailsResponse with default values."""
        agent_config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="ACTIVE",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent123"
        )
        
        response = AgentDetailsResponse(
            agentId="agent123",
            agentName="Test Agent",
            tenantId="DEV",
            agentConfig=agent_config
        )
        
        assert response.orgId == ""  # Default value
    
    def test_to_simple_format(self):
        """Test transformation to simple format for backward compatibility."""
        agent_config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="ACTIVE",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent123"
        )
        
        response = AgentDetailsResponse(
            agentId="agent123",
            agentName="Test Agent",
            tenantId="DEV",
            agentConfig=agent_config
        )
        
        simple_format = response.to_simple_format()
        
        assert simple_format == {
            "id": "agent123",
            "name": "Test Agent",
            "status": "active"  # Lowercase conversion
        }
    
    def test_to_simple_format_with_different_status(self):
        """Test simple format transformation with different status values."""
        agent_config = AgentConfig(
            version="3",
            ownerId="owner123",
            requestUrl="https://api.example.com/chat",
            rootUrl="https://api.example.com/",
            llmModel="openai-gpt-4.1-mini-ptu",
            status="INDEXING",
            retrieverStrategy="NUGGET",
            reasoningAlgorithm="GPT_FUNCTION_REASONING",
            id="agent456"
        )
        
        response = AgentDetailsResponse(
            agentId="agent456",
            agentName="Indexing Agent",
            tenantId="PROD",
            agentConfig=agent_config
        )
        
        simple_format = response.to_simple_format()
        
        assert simple_format == {
            "id": "agent456",
            "name": "Indexing Agent",
            "status": "indexing"
        }
    
    def test_agent_details_response_validation_errors(self):
        """Test AgentDetailsResponse validation errors."""
        # Missing required fields
        with pytest.raises(ValidationError) as exc_info:
            AgentDetailsResponse()
        
        errors = exc_info.value.errors()
        error_fields = {error['loc'][0] for error in errors}
        assert 'agentId' in error_fields
        assert 'agentName' in error_fields
        assert 'tenantId' in error_fields
        assert 'agentConfig' in error_fields


class TestAgentSDKConfigIntegration:
    """Integration tests for AgentSDKConfig with real settings."""
    
    def test_config_integration_with_settings_class(self):
        """Test AgentSDKConfig integration with actual Settings class."""
        from app.core.config import Settings
        
        # Create settings with environment variables
        settings = Settings(
            SECRET_KEY="test-secret",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_BASE_URL="https://prod.example.com",
            AGENT_SDK_JWT_TOKEN="prod-token",
            AGENT_SDK_TIMEOUT=300,
            AGENT_SDK_RETRY_COUNT=5,
            AGENT_SDK_MOCK_MODE=False
        )
        
        config = AgentSDKConfig.from_settings(settings)
        
        assert config.env == "PROD"
        assert config.base_url == "https://prod.example.com"
        assert config.jwt_token == "prod-token"
        assert config.request_timeout == 300
        assert config.retry_count == 5
        assert config.mock_mode is False
    
    def test_config_with_missing_optional_token(self):
        """Test AgentSDKConfig when JWT token is not provided."""
        from app.core.config import Settings
        
        settings = Settings(
            SECRET_KEY="test-secret",
            AGENT_SDK_ENV="DEV",
            AGENT_SDK_BASE_URL="https://dev.example.com"
            # JWT token not provided
        )
        
        config = AgentSDKConfig.from_settings(settings)
        
        assert config.env == "DEV"
        assert config.base_url == "https://dev.example.com"
        assert config.jwt_token is None
        assert config.request_timeout == 180  # Default
        assert config.retry_count == 3  # Default
        assert config.mock_mode is False  # Default
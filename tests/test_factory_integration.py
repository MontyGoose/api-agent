"""Integration tests for SDK factory with dependency injection."""

import pytest
from unittest.mock import patch

from app.core.config import Settings
from app.api.deps import get_agent_service
from app.services.agent_service import AgentService
from app.services.mock_sdk import MockAgentSDK
from app.services.concrete_sdk import ConcreteAgentSDK


class TestFactoryIntegration:
    """Integration tests for factory with dependency injection."""
    
    @patch('app.api.deps.get_settings')
    def test_get_agent_service_uses_mock_in_local_env(self, mock_get_settings):
        """Test that get_agent_service returns service with mock SDK in local environment."""
        mock_settings = Settings(
            ENV="local",
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False
        )
        mock_get_settings.return_value = mock_settings
        
        service = get_agent_service()
        
        assert isinstance(service, AgentService)
        assert isinstance(service.sdk, MockAgentSDK)
    
    @patch('app.api.deps.get_settings')
    def test_get_agent_service_uses_concrete_in_prod_with_config(self, mock_get_settings):
        """Test that get_agent_service returns service with concrete SDK in production with proper config."""
        mock_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_TIMEOUT=180,
            AGENT_SDK_RETRY_COUNT=3
        )
        mock_get_settings.return_value = mock_settings
        
        service = get_agent_service()
        
        assert isinstance(service, AgentService)
        assert isinstance(service.sdk, ConcreteAgentSDK)
        assert service.sdk.config.env == "PROD"
        assert service.sdk.config.base_url == "https://api.example.com"
        assert service.sdk.config.jwt_token == "test-token"
    
    @patch('app.api.deps.get_settings')
    def test_get_agent_service_falls_back_to_mock_missing_config(self, mock_get_settings):
        """Test that get_agent_service falls back to mock SDK when config is missing."""
        mock_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,  # Missing JWT token
            AGENT_SDK_BASE_URL="https://api.example.com"
        )
        mock_get_settings.return_value = mock_settings
        
        service = get_agent_service()
        
        assert isinstance(service, AgentService)
        assert isinstance(service.sdk, MockAgentSDK)
    
    @patch('app.api.deps.get_settings')
    def test_get_agent_service_respects_forced_mock_mode(self, mock_get_settings):
        """Test that get_agent_service respects forced mock mode even with valid config."""
        mock_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,  # Forced mock mode
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        mock_get_settings.return_value = mock_settings
        
        service = get_agent_service()
        
        assert isinstance(service, AgentService)
        assert isinstance(service.sdk, MockAgentSDK)
    
    def test_agent_service_configuration_consistency(self):
        """Test that AgentService receives consistent configuration from factory."""
        # Test with default settings (should use mock)
        service = get_agent_service()
        
        assert isinstance(service, AgentService)
        assert service.timeout_seconds > 0
        assert service.retry_count >= 0
        
        # The service should have the SDK configured
        assert service.sdk is not None
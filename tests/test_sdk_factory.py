"""Tests for AgentSDKFactory."""

import pytest
from unittest.mock import Mock, patch

from app.core.config import Settings
from app.services.sdk_factory import AgentSDKFactory
from app.services.mock_sdk import MockAgentSDK
from app.services.concrete_sdk import ConcreteAgentSDK


class TestAgentSDKFactory:
    """Test cases for AgentSDKFactory."""
    
    def test_create_mock_sdk_local_environment(self):
        """Test that mock SDK is created for local environment."""
        settings = Settings(
            ENV="local",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_test_environment(self):
        """Test that mock SDK is created for test environment."""
        settings = Settings(
            ENV="test",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_debug_mode(self):
        """Test that mock SDK is created when debug mode is enabled."""
        settings = Settings(
            ENV="prod",
            DEBUG=True,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_forced_mock_mode(self):
        """Test that mock SDK is created when mock mode is forced."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_missing_jwt_token(self):
        """Test that mock SDK is created when JWT token is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_empty_jwt_token(self):
        """Test that mock SDK is created when JWT token is empty."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_mock_sdk_missing_base_url(self):
        """Test that mock SDK is created when base URL is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL=""
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_create_concrete_sdk_production_ready(self):
        """Test that concrete SDK is created when all requirements are met."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_TIMEOUT=180,
            AGENT_SDK_RETRY_COUNT=3
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, ConcreteAgentSDK)
        assert sdk.config.env == "PROD"
        assert sdk.config.base_url == "https://test.example.com"
        assert sdk.config.jwt_token == "test-token"
        assert sdk.config.request_timeout == 180
        assert sdk.config.retry_count == 3
    
    def test_create_concrete_sdk_dev_environment(self):
        """Test that concrete SDK can be created in dev environment with proper config."""
        settings = Settings(
            ENV="dev",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://dev.example.com",
            AGENT_SDK_ENV="DEV"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, ConcreteAgentSDK)
        assert sdk.config.env == "DEV"
        assert sdk.config.base_url == "https://dev.example.com"
    
    def test_should_use_mock_local_environment(self):
        """Test _should_use_mock returns True for local environment."""
        settings = Settings(
            ENV="local",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token"
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is True
    
    def test_should_use_mock_test_environment(self):
        """Test _should_use_mock returns True for test environment."""
        settings = Settings(
            ENV="test",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token"
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is True
    
    def test_should_use_mock_forced_mode(self):
        """Test _should_use_mock returns True when mock mode is forced."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,
            AGENT_SDK_JWT_TOKEN="test-token"
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is True
    
    def test_should_use_mock_debug_mode(self):
        """Test _should_use_mock returns True in debug mode."""
        settings = Settings(
            ENV="prod",
            DEBUG=True,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token"
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is True
    
    def test_should_use_mock_missing_jwt(self):
        """Test _should_use_mock returns True when JWT token is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is True
    
    def test_should_use_mock_production_ready(self):
        """Test _should_use_mock returns False when all requirements are met."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        result = AgentSDKFactory._should_use_mock(settings)
        
        assert result is False
    
    def test_validate_concrete_config_valid(self):
        """Test validate_concrete_config returns True for valid configuration."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        result = AgentSDKFactory.validate_concrete_config(settings)
        
        assert result is True
    
    def test_validate_concrete_config_missing_jwt(self):
        """Test validate_concrete_config returns False when JWT token is missing."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN=None,
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        result = AgentSDKFactory.validate_concrete_config(settings)
        
        assert result is False
    
    def test_validate_concrete_config_empty_jwt(self):
        """Test validate_concrete_config returns False when JWT token is empty."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="",
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        result = AgentSDKFactory.validate_concrete_config(settings)
        
        assert result is False
    
    def test_validate_concrete_config_missing_base_url(self):
        """Test validate_concrete_config returns False when base URL is missing."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="",
            AGENT_SDK_ENV="PROD"
        )
        
        result = AgentSDKFactory.validate_concrete_config(settings)
        
        assert result is False
    
    def test_validate_concrete_config_missing_env(self):
        """Test validate_concrete_config returns False when SDK env is missing."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV=""
        )
        
        result = AgentSDKFactory.validate_concrete_config(settings)
        
        assert result is False
    
    def test_get_sdk_info_mock_selection(self):
        """Test get_sdk_info returns correct information for mock SDK selection."""
        settings = Settings(
            ENV="local",
            DEBUG=True,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        info = AgentSDKFactory.get_sdk_info(settings)
        
        assert info["sdk_type"] == "mock"
        assert info["env"] == "local"
        assert info["debug"] is True
        assert info["mock_mode_forced"] is False
        assert info["config_valid"] is True
        assert info["has_jwt_token"] is True
        assert info["base_url"] == "https://test.example.com"
        assert "Environment is local" in info["reasons"]
        assert "Debug mode is enabled" in info["reasons"]
    
    def test_get_sdk_info_concrete_selection(self):
        """Test get_sdk_info returns correct information for concrete SDK selection."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        info = AgentSDKFactory.get_sdk_info(settings)
        
        assert info["sdk_type"] == "concrete"
        assert info["env"] == "prod"
        assert info["debug"] is False
        assert info["mock_mode_forced"] is False
        assert info["config_valid"] is True
        assert info["has_jwt_token"] is True
        assert info["base_url"] == "https://test.example.com"
        assert "All requirements met for concrete SDK" in info["reasons"]
    
    def test_get_sdk_info_forced_mock(self):
        """Test get_sdk_info shows forced mock mode in reasons."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        info = AgentSDKFactory.get_sdk_info(settings)
        
        assert info["sdk_type"] == "mock"
        assert info["mock_mode_forced"] is True
        assert "Mock mode explicitly enabled" in info["reasons"]
    
    def test_get_sdk_info_missing_config(self):
        """Test get_sdk_info shows missing configuration in reasons."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,
            AGENT_SDK_BASE_URL=""
        )
        
        info = AgentSDKFactory.get_sdk_info(settings)
        
        assert info["sdk_type"] == "mock"
        assert info["config_valid"] is False
        assert info["has_jwt_token"] is False
        assert "No JWT token configured" in info["reasons"]
        assert "No base URL configured" in info["reasons"]
    
    def test_get_selection_reasons_multiple_conditions(self):
        """Test _get_selection_reasons returns all applicable reasons."""
        settings = Settings(
            ENV="local",
            DEBUG=True,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,
            AGENT_SDK_JWT_TOKEN=None,
            AGENT_SDK_BASE_URL=""
        )
        
        reasons = AgentSDKFactory._get_selection_reasons(settings)
        
        expected_reasons = [
            "Mock mode explicitly enabled",
            "Environment is local",
            "Debug mode is enabled",
            "No JWT token configured",
            "No base URL configured"
        ]
        
        for reason in expected_reasons:
            assert reason in reasons
    
    def test_get_selection_reasons_production_ready(self):
        """Test _get_selection_reasons for production-ready configuration."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="test-token",
            AGENT_SDK_BASE_URL="https://test.example.com"
        )
        
        reasons = AgentSDKFactory._get_selection_reasons(settings)
        
        assert reasons == ["All requirements met for concrete SDK"]
    
    @patch('app.services.sdk_factory.get_settings')
    def test_create_sdk_uses_get_settings_when_none_provided(self, mock_get_settings):
        """Test that create_sdk uses get_settings() when no settings provided."""
        mock_settings = Settings(
            ENV="local",
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False
        )
        mock_get_settings.return_value = mock_settings
        
        sdk = AgentSDKFactory.create_sdk()
        
        mock_get_settings.assert_called_once()
        assert isinstance(sdk, MockAgentSDK)
    
    @patch('app.services.sdk_factory.get_settings')
    def test_get_sdk_info_uses_get_settings_when_none_provided(self, mock_get_settings):
        """Test that get_sdk_info uses get_settings() when no settings provided."""
        mock_settings = Settings(
            ENV="local",
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False
        )
        mock_get_settings.return_value = mock_settings
        
        info = AgentSDKFactory.get_sdk_info()
        
        mock_get_settings.assert_called_once()
        assert info["sdk_type"] == "mock"
        assert info["env"] == "local"


class TestAgentSDKFactoryIntegration:
    """Integration tests for AgentSDKFactory with different configuration scenarios."""
    
    def test_factory_with_default_settings(self):
        """Test factory behavior with default settings."""
        # Default settings should use mock SDK
        sdk = AgentSDKFactory.create_sdk()
        
        assert isinstance(sdk, MockAgentSDK)
    
    def test_factory_configuration_validation_flow(self):
        """Test the complete flow from configuration validation to SDK creation."""
        # Test invalid configuration
        invalid_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN=None
        )
        
        assert not AgentSDKFactory.validate_concrete_config(invalid_settings)
        sdk = AgentSDKFactory.create_sdk(invalid_settings)
        assert isinstance(sdk, MockAgentSDK)
        
        # Test valid configuration
        valid_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        assert AgentSDKFactory.validate_concrete_config(valid_settings)
        sdk = AgentSDKFactory.create_sdk(valid_settings)
        assert isinstance(sdk, ConcreteAgentSDK)
    
    def test_factory_environment_precedence(self):
        """Test that environment settings take precedence over other factors."""
        # Even with valid config, local environment should use mock
        settings = Settings(
            ENV="local",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        assert isinstance(sdk, MockAgentSDK)
        
        info = AgentSDKFactory.get_sdk_info(settings)
        assert "Environment is local" in info["reasons"]
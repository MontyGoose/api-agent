"""Tests for mock mode support and fallback behavior."""

import pytest
from unittest.mock import Mock, patch
import asyncio

from app.core.config import Settings
from app.services.sdk_factory import AgentSDKFactory
from app.services.mock_sdk import MockAgentSDK
from app.services.concrete_sdk import ConcreteAgentSDK
from app.services.exceptions import SDKError, AgentNotFoundError
from app.models.agent_config import AgentSDKConfig


class TestMockModeSupport:
    """Test cases for mock mode support and configuration."""
    
    def test_mock_mode_forced_in_production(self):
        """Test that mock mode can be forced even in production environment."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,  # Force mock mode
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert "Mock mode explicitly enabled via AGENT_SDK_MOCK_MODE" in reasons
    
    def test_mock_mode_available_for_development(self):
        """Test that MockAgentSDK remains available for development."""
        # Test direct instantiation
        mock_sdk = MockAgentSDK()
        assert isinstance(mock_sdk, MockAgentSDK)
        
        # Test factory creation in local environment
        settings = Settings(
            ENV="local",
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        assert isinstance(sdk, MockAgentSDK)
    
    def test_mock_mode_configuration_options(self):
        """Test MockAgentSDK configuration options."""
        # Test with default configuration
        mock_sdk_default = MockAgentSDK()
        assert mock_sdk_default.simulate_delays is True
        assert mock_sdk_default.simulate_errors is True
        
        # Test with custom configuration
        mock_sdk_custom = MockAgentSDK(simulate_delays=False, simulate_errors=False)
        assert mock_sdk_custom.simulate_delays is False
        assert mock_sdk_custom.simulate_errors is False
    
    @pytest.mark.asyncio
    async def test_mock_sdk_enhanced_functionality(self):
        """Test enhanced MockAgentSDK functionality."""
        mock_sdk = MockAgentSDK()
        
        # Test getting existing agent
        agent_data = await mock_sdk.get_agent("agent-123")
        assert agent_data["id"] == "agent-123"
        assert agent_data["name"] == "Customer Support Bot"
        assert agent_data["status"] == "active"
        
        # Test adding custom mock agent
        custom_agent = {
            "id": "custom-agent",
            "name": "Custom Test Agent",
            "status": "ready"
        }
        mock_sdk.add_mock_agent("custom-agent", custom_agent)
        
        retrieved_agent = await mock_sdk.get_agent("custom-agent")
        assert retrieved_agent["name"] == "Custom Test Agent"
        
        # Test removing mock agent
        assert mock_sdk.remove_mock_agent("custom-agent") is True
        assert mock_sdk.remove_mock_agent("non-existent") is False
        
        # Test getting all available agents
        available_agents = mock_sdk.get_available_agents()
        assert "agent-123" in available_agents
        assert "custom-agent" not in available_agents


class TestFallbackBehavior:
    """Test cases for graceful fallback behavior."""
    
    def test_fallback_missing_jwt_token(self):
        """Test fallback to mock when JWT token is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,  # Missing JWT token
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("JWT token" in reason for reason in reasons)
    
    def test_fallback_empty_jwt_token(self):
        """Test fallback to mock when JWT token is empty."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="",  # Empty JWT token
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("No JWT token configured" in reason for reason in reasons)
    
    def test_fallback_placeholder_jwt_token(self):
        """Test fallback to mock when JWT token is placeholder value."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="your-jwt-token-here",  # Placeholder value
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("placeholder" in reason for reason in reasons)
    
    def test_fallback_missing_base_url(self):
        """Test fallback to mock when base URL is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="",  # Empty base URL
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("No base URL configured" in reason for reason in reasons)
    
    def test_fallback_invalid_base_url(self):
        """Test fallback to mock when base URL is invalid."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="invalid-url",  # Invalid URL format
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("valid HTTP/HTTPS URL" in reason for reason in reasons)
    
    def test_fallback_missing_sdk_env(self):
        """Test fallback to mock when SDK environment is missing."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV=""  # Empty SDK environment
        )
        
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify the reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        assert use_mock is True
        assert any("No SDK environment configured" in reason for reason in reasons)
    
    @patch('app.models.agent_config.AgentSDKConfig.from_settings')
    def test_fallback_on_concrete_sdk_creation_failure(self, mock_from_settings):
        """Test fallback to mock when concrete SDK creation fails."""
        # Mock the configuration creation to raise an exception
        mock_from_settings.side_effect = ValueError("Configuration error")
        
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        # Should fall back to mock SDK when concrete SDK creation fails
        sdk = AgentSDKFactory.create_sdk(settings)
        
        assert isinstance(sdk, MockAgentSDK)
        mock_from_settings.assert_called_once()
    
    def test_enhanced_fallback_with_allow_fallback_false(self):
        """Test enhanced fallback behavior when fallback is disabled."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        # Should work normally when configuration is valid
        sdk = AgentSDKFactory.create_sdk_with_fallback(settings, allow_fallback=False)
        assert isinstance(sdk, ConcreteAgentSDK)
        
        # Test with invalid configuration and fallback disabled
        invalid_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN=None,  # Invalid configuration
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        # Should still fall back to mock because the factory logic determines mock is needed
        sdk = AgentSDKFactory.create_sdk_with_fallback(invalid_settings, allow_fallback=False)
        assert isinstance(sdk, MockAgentSDK)


class TestConfigurationValidation:
    """Test cases for configuration validation with detailed error reporting."""
    
    def test_validate_concrete_config_detailed_valid(self):
        """Test detailed validation with valid configuration."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_TIMEOUT=180,
            AGENT_SDK_RETRY_COUNT=3
        )
        
        is_valid, errors = AgentSDKFactory.validate_concrete_config_detailed(settings)
        
        assert is_valid is True
        assert len(errors) == 0
    
    def test_validate_concrete_config_detailed_multiple_errors(self):
        """Test detailed validation with multiple configuration errors."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="",  # Empty token
            AGENT_SDK_BASE_URL="invalid-url",  # Invalid URL
            AGENT_SDK_ENV="INVALID",  # Invalid environment
            AGENT_SDK_TIMEOUT=-1,  # Invalid timeout
            AGENT_SDK_RETRY_COUNT=-1  # Invalid retry count
        )
        
        is_valid, errors = AgentSDKFactory.validate_concrete_config_detailed(settings)
        
        assert is_valid is False
        assert len(errors) > 0
        
        # Check that all expected errors are present
        error_text = " ".join(errors)
        assert "AGENT_SDK_JWT_TOKEN is required" in error_text
        assert "valid HTTP/HTTPS URL" in error_text
        assert "must be one of DEV, QA, PROD" in error_text
        assert "TIMEOUT must be positive" in error_text
        assert "RETRY_COUNT must be non-negative" in error_text
    
    def test_validate_concrete_config_detailed_placeholder_values(self):
        """Test detailed validation catches placeholder values."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="test-key",
            AGENT_SDK_JWT_TOKEN="your-jwt-token-here",  # Placeholder
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        is_valid, errors = AgentSDKFactory.validate_concrete_config_detailed(settings)
        
        assert is_valid is False
        assert any("placeholder" in error for error in errors)


class TestSDKConnectivityTesting:
    """Test cases for SDK connectivity testing functionality."""
    
    def test_test_sdk_connectivity_mock_sdk(self):
        """Test connectivity testing with MockAgentSDK."""
        mock_sdk = MockAgentSDK()
        
        # Should return True for properly functioning mock SDK
        result = AgentSDKFactory.test_sdk_connectivity(mock_sdk)
        assert result is True
    
    def test_test_sdk_connectivity_concrete_sdk(self):
        """Test connectivity testing with ConcreteAgentSDK."""
        # Create a properly configured ConcreteAgentSDK
        config = AgentSDKConfig(
            env="PROD",
            base_url="https://api.example.com",
            jwt_token="valid-token"
        )
        concrete_sdk = ConcreteAgentSDK(config)
        
        # Should return True for properly configured concrete SDK
        result = AgentSDKFactory.test_sdk_connectivity(concrete_sdk)
        assert result is True
    
    def test_test_sdk_connectivity_invalid_sdk(self):
        """Test connectivity testing with invalid SDK."""
        # Create a mock object that's not a proper SDK
        invalid_sdk = Mock()
        
        # Should return False for invalid SDK
        result = AgentSDKFactory.test_sdk_connectivity(invalid_sdk)
        assert result is False


class TestMockSDKErrorSimulation:
    """Test cases for MockAgentSDK error simulation capabilities."""
    
    @pytest.mark.asyncio
    async def test_mock_sdk_error_simulation_enabled(self):
        """Test MockAgentSDK error simulation when enabled."""
        mock_sdk = MockAgentSDK(simulate_errors=True)
        
        # Test simulated SDK error
        with pytest.raises(SDKError, match="Simulated SDK error"):
            await mock_sdk.get_agent("error-agent")
        
        # Test simulated timeout error
        with pytest.raises(SDKError, match="timeout"):
            await mock_sdk.get_agent("timeout-agent")
        
        # Test simulated authentication error
        with pytest.raises(SDKError, match="authentication"):
            await mock_sdk.get_agent("auth-error-agent")
    
    @pytest.mark.asyncio
    async def test_mock_sdk_error_simulation_disabled(self):
        """Test MockAgentSDK with error simulation disabled."""
        mock_sdk = MockAgentSDK(simulate_errors=False)
        
        # Should not raise errors for special agent IDs when simulation is disabled
        with pytest.raises(AgentNotFoundError):
            await mock_sdk.get_agent("error-agent")
    
    @pytest.mark.asyncio
    async def test_mock_sdk_delay_simulation(self):
        """Test MockAgentSDK delay simulation."""
        import time
        
        # Test with delays enabled
        mock_sdk_with_delays = MockAgentSDK(simulate_delays=True)
        start_time = time.time()
        await mock_sdk_with_delays.get_agent("agent-123")
        elapsed_time = time.time() - start_time
        assert elapsed_time >= 0.1  # Should have some delay
        
        # Test with delays disabled
        mock_sdk_no_delays = MockAgentSDK(simulate_delays=False)
        start_time = time.time()
        await mock_sdk_no_delays.get_agent("agent-123")
        elapsed_time = time.time() - start_time
        assert elapsed_time < 0.05  # Should be much faster


class TestFactoryReasoningAndLogging:
    """Test cases for factory reasoning and logging functionality."""
    
    def test_get_selection_reasons_comprehensive(self):
        """Test comprehensive reasoning for SDK selection."""
        # Test multiple conditions that lead to mock SDK
        settings = Settings(
            ENV="local",  # Development environment
            DEBUG=True,   # Debug mode
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=True,  # Forced mock mode
            AGENT_SDK_JWT_TOKEN=None,  # Missing token
            AGENT_SDK_BASE_URL=""      # Empty URL
        )
        
        reasons = AgentSDKFactory._get_selection_reasons(settings)
        
        # Should include all applicable reasons
        expected_reasons = [
            "Mock mode explicitly enabled",
            "Environment is local",
            "Debug mode is enabled",
            "No JWT token configured",
            "No base URL configured"
        ]
        
        for expected_reason in expected_reasons:
            assert any(expected_reason in reason for reason in reasons)
    
    def test_get_sdk_info_comprehensive(self):
        """Test comprehensive SDK information reporting."""
        settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="test-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://api.example.com",
            AGENT_SDK_ENV="PROD"
        )
        
        info = AgentSDKFactory.get_sdk_info(settings)
        
        # Verify all expected information is present
        assert "sdk_type" in info
        assert "env" in info
        assert "debug" in info
        assert "mock_mode_forced" in info
        assert "config_valid" in info
        assert "has_jwt_token" in info
        assert "base_url" in info
        assert "reasons" in info
        
        # Verify values are correct
        assert info["sdk_type"] == "concrete"
        assert info["env"] == "prod"
        assert info["debug"] is False
        assert info["mock_mode_forced"] is False
        assert info["config_valid"] is True
        assert info["has_jwt_token"] is True
        assert info["base_url"] == "https://api.example.com"
        assert "All requirements met for concrete SDK" in info["reasons"]


class TestIntegrationScenarios:
    """Integration test cases for real-world scenarios."""
    
    def test_development_workflow(self):
        """Test typical development workflow with mock SDK."""
        # Developer working locally
        local_settings = Settings(
            ENV="local",
            DEBUG=True,
            SECRET_KEY="dev-key",
            AGENT_SDK_MOCK_MODE=False
        )
        
        sdk = AgentSDKFactory.create_sdk(local_settings)
        assert isinstance(sdk, MockAgentSDK)
        
        # Get SDK info for debugging
        info = AgentSDKFactory.get_sdk_info(local_settings)
        assert info["sdk_type"] == "mock"
        assert "Environment is local" in info["reasons"]
    
    def test_production_deployment_with_valid_config(self):
        """Test production deployment with valid configuration."""
        prod_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="prod-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            AGENT_SDK_JWT_TOKEN="prod-jwt-token",
            AGENT_SDK_BASE_URL="https://api.production.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(prod_settings)
        assert isinstance(sdk, ConcreteAgentSDK)
        
        # Verify configuration
        assert sdk.config.env == "PROD"
        assert sdk.config.base_url == "https://api.production.com"
        assert sdk.config.jwt_token == "prod-jwt-token"
    
    def test_production_deployment_with_forced_mock(self):
        """Test production deployment with forced mock mode."""
        prod_mock_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="prod-secret-key",
            AGENT_SDK_MOCK_MODE=True,  # Forced mock for testing in prod
            AGENT_SDK_JWT_TOKEN="prod-jwt-token",
            AGENT_SDK_BASE_URL="https://api.production.com",
            AGENT_SDK_ENV="PROD"
        )
        
        sdk = AgentSDKFactory.create_sdk(prod_mock_settings)
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify reasoning
        info = AgentSDKFactory.get_sdk_info(prod_mock_settings)
        assert "Mock mode explicitly enabled" in info["reasons"]
    
    def test_misconfigured_production_deployment(self):
        """Test production deployment with missing configuration."""
        misconfigured_settings = Settings(
            ENV="prod",
            DEBUG=False,
            SECRET_KEY="prod-secret-key",
            AGENT_SDK_MOCK_MODE=False,
            # Missing JWT token and other required config
            AGENT_SDK_JWT_TOKEN=None,
            AGENT_SDK_BASE_URL="https://api.production.com",
            AGENT_SDK_ENV="PROD"
        )
        
        # Should gracefully fall back to mock SDK
        sdk = AgentSDKFactory.create_sdk(misconfigured_settings)
        assert isinstance(sdk, MockAgentSDK)
        
        # Verify detailed validation shows the issues
        is_valid, errors = AgentSDKFactory.validate_concrete_config_detailed(misconfigured_settings)
        assert is_valid is False
        assert any("JWT_TOKEN is required" in error for error in errors)
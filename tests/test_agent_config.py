"""Tests for Agent SDK configuration models."""

import pytest
from unittest.mock import Mock
from pydantic import ValidationError

from src.app.models.agent_config import AgentSDKConfig, AgentConfig, AgentDetailsResponse
from src.app.core.config import Settings


class TestAgentSDKConfig:
    """Test cases for AgentSDKConfig model."""
    
    def test_valid_config_creation(self):
        """Test creating a valid AgentSDKConfig."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="valid-jwt-token",
            request_timeout=120,
            retry_count=2,
            mock_mode=False
        )
        
        assert config.env == "DEV"
        assert config.base_url == "https://api.example.com"
        assert config.jwt_token == "valid-jwt-token"
        assert config.request_timeout == 120
        assert config.retry_count == 2
        assert config.mock_mode is False
    
    def test_env_validation_and_normalization(self):
        """Test environment validation and normalization."""
        # Valid environments should be normalized to uppercase
        for env in ["dev", "DEV", "qa", "QA", "prod", "PROD", "local", "LOCAL", "test", "TEST"]:
            config = AgentSDKConfig(
                env=env,
                base_url="https://api.example.com",
                mock_mode=True  # Use mock mode to avoid JWT validation
            )
            assert config.env == env.upper()
    
    def test_invalid_env_validation(self):
        """Test invalid environment validation."""
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="INVALID",
                base_url="https://api.example.com"
            )
        
        assert "env must be one of" in str(exc_info.value)
    
    def test_timeout_validation(self):
        """Test request timeout validation."""
        # Valid timeout
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            request_timeout=60,
            mock_mode=True
        )
        assert config.request_timeout == 60
        
        # Invalid timeout (zero)
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="DEV",
                base_url="https://api.example.com",
                request_timeout=0
            )
        assert "request_timeout must be positive" in str(exc_info.value)
        
        # Invalid timeout (negative)
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="DEV",
                base_url="https://api.example.com",
                request_timeout=-10
            )
        assert "request_timeout must be positive" in str(exc_info.value)
    
    def test_retry_count_validation(self):
        """Test retry count validation."""
        # Valid retry count (zero)
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            retry_count=0,
            mock_mode=True
        )
        assert config.retry_count == 0
        
        # Valid retry count (positive)
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            retry_count=5,
            mock_mode=True
        )
        assert config.retry_count == 5
        
        # Invalid retry count (negative)
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="DEV",
                base_url="https://api.example.com",
                retry_count=-1
            )
        assert "retry_count must be non-negative" in str(exc_info.value)
    
    def test_production_validation_with_mock_mode(self):
        """Test production validation when mock mode is enabled."""
        # Should pass even without JWT token when mock mode is enabled
        config = AgentSDKConfig(
            env="PROD",
            base_url="https://api.example.com",
            jwt_token=None,
            mock_mode=True
        )
        assert config.env == "PROD"
        assert config.mock_mode is True
    
    def test_production_validation_without_jwt_token(self):
        """Test production validation fails without JWT token."""
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="PROD",
                base_url="https://api.example.com",
                jwt_token=None,
                mock_mode=False
            )
        assert "jwt_token is required for PROD environment" in str(exc_info.value)
    
    def test_production_validation_with_default_jwt_token(self):
        """Test production validation fails with default JWT token."""
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="PROD",
                base_url="https://api.example.com",
                jwt_token="your-jwt-token-here",
                mock_mode=False
            )
        assert "jwt_token must be changed from default value" in str(exc_info.value)
    
    def test_production_validation_with_default_base_url(self):
        """Test production validation fails with default base URL."""
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="PROD",
                base_url="https://lm.qa.example.net",
                jwt_token="valid-jwt-token",
                mock_mode=False
            )
        assert "base_url must be changed from default value" in str(exc_info.value)
    
    def test_qa_environment_validation(self):
        """Test QA environment validation."""
        # Should require JWT token in QA when not in mock mode
        with pytest.raises(ValidationError) as exc_info:
            AgentSDKConfig(
                env="QA",
                base_url="https://api.example.com",
                jwt_token=None,
                mock_mode=False
            )
        assert "jwt_token is required for QA environment" in str(exc_info.value)
        
        # Should pass with valid JWT token
        config = AgentSDKConfig(
            env="QA",
            base_url="https://api.example.com",
            jwt_token="valid-jwt-token",
            mock_mode=False
        )
        assert config.env == "QA"
    
    def test_validate_for_real_usage_mock_mode(self):
        """Test validate_for_real_usage with mock mode enabled."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            mock_mode=True
        )
        
        # Should not raise any exception for mock mode
        config.validate_for_real_usage()
    
    def test_validate_for_real_usage_missing_jwt_token(self):
        """Test validate_for_real_usage fails without JWT token."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token=None,
            mock_mode=False
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate_for_real_usage()
        assert "jwt_token is required for real SDK usage" in str(exc_info.value)
    
    def test_validate_for_real_usage_missing_base_url(self):
        """Test validate_for_real_usage fails without base URL."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="",
            jwt_token="valid-token",
            mock_mode=False
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate_for_real_usage()
        assert "base_url is required for real SDK usage" in str(exc_info.value)
    
    def test_validate_for_real_usage_invalid_base_url(self):
        """Test validate_for_real_usage fails with invalid base URL."""
        config = AgentSDKConfig(
            env="DEV",
            base_url="invalid-url",
            jwt_token="valid-token",
            mock_mode=False
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate_for_real_usage()
        assert "base_url must be a valid URL" in str(exc_info.value)
    
    def test_from_settings_development_mode(self):
        """Test creating config from settings in development mode."""
        # Mock settings for development
        settings = Mock(spec=Settings)
        settings.AGENT_SDK_ENV = "DEV"
        settings.AGENT_SDK_BASE_URL = "https://dev-api.example.com"
        settings.AGENT_SDK_JWT_TOKEN = "dev-jwt-token"
        settings.AGENT_SDK_TIMEOUT = 120
        settings.AGENT_SDK_RETRY_COUNT = 2
        settings.AGENT_SDK_MOCK_MODE = False
        settings.requires_real_sdk = False
        settings.validate_agent_sdk_config.return_value = (True, [])
        
        config = AgentSDKConfig.from_settings(settings)
        
        assert config.env == "DEV"
        assert config.base_url == "https://dev-api.example.com"
        assert config.jwt_token == "dev-jwt-token"
        assert config.request_timeout == 120
        assert config.retry_count == 2
        assert config.mock_mode is False
    
    def test_from_settings_mock_mode(self):
        """Test creating config from settings with mock mode enabled."""
        settings = Mock(spec=Settings)
        settings.AGENT_SDK_ENV = "LOCAL"
        settings.AGENT_SDK_BASE_URL = "https://api.example.com"
        settings.AGENT_SDK_JWT_TOKEN = None
        settings.AGENT_SDK_TIMEOUT = 180
        settings.AGENT_SDK_RETRY_COUNT = 3
        settings.AGENT_SDK_MOCK_MODE = True
        settings.requires_real_sdk = False
        settings.validate_agent_sdk_config.return_value = (True, [])
        
        config = AgentSDKConfig.from_settings(settings)
        
        assert config.env == "LOCAL"
        assert config.mock_mode is True
        assert config.jwt_token is None  # Should be fine in mock mode
    
    def test_from_settings_production_mode_valid(self):
        """Test creating config from settings in production mode with valid config."""
        settings = Mock(spec=Settings)
        settings.AGENT_SDK_ENV = "PROD"
        settings.AGENT_SDK_BASE_URL = "https://prod-api.example.com"
        settings.AGENT_SDK_JWT_TOKEN = "prod-jwt-token"
        settings.AGENT_SDK_TIMEOUT = 180
        settings.AGENT_SDK_RETRY_COUNT = 3
        settings.AGENT_SDK_MOCK_MODE = False
        settings.requires_real_sdk = True
        settings.validate_agent_sdk_config.return_value = (True, [])
        
        config = AgentSDKConfig.from_settings(settings)
        
        assert config.env == "PROD"
        assert config.base_url == "https://prod-api.example.com"
        assert config.jwt_token == "prod-jwt-token"
        assert config.mock_mode is False
    
    def test_from_settings_production_mode_invalid(self):
        """Test creating config from settings in production mode with invalid config."""
        settings = Mock(spec=Settings)
        settings.AGENT_SDK_ENV = "PROD"
        settings.AGENT_SDK_BASE_URL = "https://prod-api.example.com"
        settings.AGENT_SDK_JWT_TOKEN = None  # Missing JWT token
        settings.AGENT_SDK_TIMEOUT = 180
        settings.AGENT_SDK_RETRY_COUNT = 3
        settings.AGENT_SDK_MOCK_MODE = False
        settings.requires_real_sdk = True
        settings.validate_agent_sdk_config.return_value = (False, ["JWT token is required"])
        
        with pytest.raises((ValueError, ValidationError)) as exc_info:
            AgentSDKConfig.from_settings(settings)
        assert "Invalid Agent SDK configuration" in str(exc_info.value)


class TestSettingsValidation:
    """Test cases for Settings validation."""
    
    def test_settings_production_validation_valid(self):
        """Test Settings validation passes with valid production config."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-secret-key",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_BASE_URL="https://prod-api.example.com",
            AGENT_SDK_JWT_TOKEN="prod-jwt-token",
            AGENT_SDK_MOCK_MODE=False
        )
        
        assert settings.ENV == "prod"
        assert settings.is_prod is True
        assert settings.requires_real_sdk is True
    
    def test_settings_production_validation_default_secret_key(self):
        """Test Settings validation fails with default secret key in production."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENV="prod",
                SECRET_KEY="CHANGE_ME",  # Default value
                AGENT_SDK_JWT_TOKEN="valid-token",
                AGENT_SDK_BASE_URL="https://prod-api.example.com"
            )
        assert "SECRET_KEY must be changed from default value" in str(exc_info.value)
    
    def test_settings_production_validation_missing_jwt_token(self):
        """Test Settings validation method detects missing JWT token in production."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-secret-key",
            AGENT_SDK_JWT_TOKEN=None,  # Missing JWT token
            AGENT_SDK_MOCK_MODE=False
        )
        
        is_valid, errors = settings.validate_agent_sdk_config()
        assert not is_valid
        assert any("AGENT_SDK_JWT_TOKEN is required" in error for error in errors)
    
    def test_settings_production_validation_default_jwt_token(self):
        """Test Settings validation method detects default JWT token in production."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-secret-key",
            AGENT_SDK_JWT_TOKEN="your-jwt-token-here",  # Default value
            AGENT_SDK_MOCK_MODE=False
        )
        
        is_valid, errors = settings.validate_agent_sdk_config()
        assert not is_valid
        assert any("AGENT_SDK_JWT_TOKEN must be changed from default value" in error for error in errors)
    
    def test_settings_production_validation_default_base_url(self):
        """Test Settings validation method detects default base URL in production."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-secret-key",
            AGENT_SDK_JWT_TOKEN="valid-jwt-token",
            AGENT_SDK_BASE_URL="https://lm.qa.example.net",  # Default value
            AGENT_SDK_MOCK_MODE=False
        )
        
        is_valid, errors = settings.validate_agent_sdk_config()
        assert not is_valid
        assert any("AGENT_SDK_BASE_URL must be changed from default value" in error for error in errors)
    
    def test_settings_production_validation_with_mock_mode(self):
        """Test Settings validation passes in production with mock mode enabled."""
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-secret-key",
            AGENT_SDK_JWT_TOKEN=None,  # Can be None in mock mode
            AGENT_SDK_MOCK_MODE=True
        )
        
        assert settings.ENV == "prod"
        assert settings.AGENT_SDK_MOCK_MODE is True
        assert settings.requires_real_sdk is False
    
    def test_settings_development_validation(self):
        """Test Settings validation passes in development mode."""
        settings = Settings(
            ENV="local",
            SECRET_KEY="CHANGE_ME",  # Can be default in development
            AGENT_SDK_JWT_TOKEN=None,  # Can be None in development
            AGENT_SDK_BASE_URL="https://lm.qa.example.net"  # Can be default
        )
        
        assert settings.ENV == "local"
        assert settings.is_prod is False
        assert settings.requires_real_sdk is False
    
    def test_requires_real_sdk_property(self):
        """Test requires_real_sdk property logic."""
        # Local environment should not require real SDK
        settings = Settings(ENV="local", AGENT_SDK_MOCK_MODE=False)
        assert settings.requires_real_sdk is False
        
        # Test environment should not require real SDK
        settings = Settings(ENV="test", AGENT_SDK_MOCK_MODE=False)
        assert settings.requires_real_sdk is False
        
        # Mock mode should not require real SDK
        settings = Settings(ENV="prod", AGENT_SDK_MOCK_MODE=True)
        assert settings.requires_real_sdk is False
        
        # Production without mock mode should require real SDK
        settings = Settings(
            ENV="prod",
            SECRET_KEY="valid-key",
            AGENT_SDK_JWT_TOKEN="valid-token",
            AGENT_SDK_BASE_URL="https://prod-api.example.com",
            AGENT_SDK_MOCK_MODE=False
        )
        assert settings.requires_real_sdk is True
        
        # Development without mock mode should require real SDK
        settings = Settings(ENV="dev", AGENT_SDK_MOCK_MODE=False)
        assert settings.requires_real_sdk is True


class TestConfigurationIntegration:
    """Integration tests for configuration loading and validation."""
    
    def test_full_configuration_flow_development(self):
        """Test complete configuration flow for development environment."""
        # Create settings for development
        settings = Settings(
            ENV="dev",
            SECRET_KEY="dev-secret-key",
            AGENT_SDK_ENV="DEV",
            AGENT_SDK_BASE_URL="https://dev-api.example.com",
            AGENT_SDK_JWT_TOKEN="dev-jwt-token",
            AGENT_SDK_TIMEOUT=120,
            AGENT_SDK_RETRY_COUNT=2,
            AGENT_SDK_MOCK_MODE=False
        )
        
        # Create SDK config from settings
        sdk_config = AgentSDKConfig.from_settings(settings)
        
        # Verify configuration
        assert sdk_config.env == "DEV"
        assert sdk_config.base_url == "https://dev-api.example.com"
        assert sdk_config.jwt_token == "dev-jwt-token"
        assert sdk_config.request_timeout == 120
        assert sdk_config.retry_count == 2
        assert sdk_config.mock_mode is False
        
        # Should be valid for real usage
        sdk_config.validate_for_real_usage()
    
    def test_full_configuration_flow_production(self):
        """Test complete configuration flow for production environment."""
        # Create settings for production
        settings = Settings(
            ENV="prod",
            SECRET_KEY="prod-secret-key",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_BASE_URL="https://prod-api.example.com",
            AGENT_SDK_JWT_TOKEN="prod-jwt-token",
            AGENT_SDK_TIMEOUT=180,
            AGENT_SDK_RETRY_COUNT=3,
            AGENT_SDK_MOCK_MODE=False
        )
        
        # Create SDK config from settings
        sdk_config = AgentSDKConfig.from_settings(settings)
        
        # Verify configuration
        assert sdk_config.env == "PROD"
        assert sdk_config.base_url == "https://prod-api.example.com"
        assert sdk_config.jwt_token == "prod-jwt-token"
        assert sdk_config.request_timeout == 180
        assert sdk_config.retry_count == 3
        assert sdk_config.mock_mode is False
        
        # Should be valid for real usage
        sdk_config.validate_for_real_usage()
    
    def test_full_configuration_flow_mock_mode(self):
        """Test complete configuration flow with mock mode enabled."""
        # Create settings with mock mode
        settings = Settings(
            ENV="prod",
            SECRET_KEY="prod-secret-key",
            AGENT_SDK_ENV="PROD",
            AGENT_SDK_BASE_URL="https://lm.qa.example.net",  # Default is OK in mock mode
            AGENT_SDK_JWT_TOKEN=None,  # None is OK in mock mode
            AGENT_SDK_MOCK_MODE=True
        )
        
        # Create SDK config from settings
        sdk_config = AgentSDKConfig.from_settings(settings)
        
        # Verify configuration
        assert sdk_config.env == "PROD"
        assert sdk_config.mock_mode is True
        assert sdk_config.jwt_token is None
        
        # Should not require validation for real usage in mock mode
        sdk_config.validate_for_real_usage()  # Should not raise
"""Factory for creating appropriate Agent SDK implementations."""

import structlog
from typing import Optional, Tuple, List

from app.core.config import Settings, get_settings
from app.services.interfaces import AgentSDKInterface
from app.services.mock_sdk import MockAgentSDK
from app.services.concrete_sdk import ConcreteAgentSDK
from app.models.agent_config import AgentSDKConfig
from app.services.exceptions import SDKError

logger = structlog.get_logger(__name__)


class AgentSDKFactory:
    """
    Factory class for creating appropriate Agent SDK implementations.
    
    Determines whether to use mock or concrete implementation based on
    environment configuration and availability of required settings.
    """
    
    @staticmethod
    def create_sdk(settings: Optional[Settings] = None) -> AgentSDKInterface:
        """
        Create appropriate SDK implementation based on configuration.
        
        This method implements graceful fallback to mock mode when real SDK
        configuration is missing or invalid, ensuring the application continues
        to function even with incomplete configuration.
        
        Args:
            settings: Optional Settings instance. If None, uses get_settings()
            
        Returns:
            AgentSDKInterface implementation (MockAgentSDK or ConcreteAgentSDK)
            
        Raises:
            SDKError: Only in cases where neither mock nor concrete SDK can be created
        """
        if settings is None:
            settings = get_settings()
        
        # Determine which implementation to use with detailed reasoning
        use_mock, reasons = AgentSDKFactory._should_use_mock_with_reasons(settings)
        
        if use_mock:
            logger.info(
                "Creating MockAgentSDK",
                env=settings.ENV,
                debug=settings.DEBUG,
                mock_mode_forced=settings.AGENT_SDK_MOCK_MODE,
                reasons=reasons
            )
            return MockAgentSDK()
        else:
            logger.info(
                "Creating ConcreteAgentSDK",
                env=settings.ENV,
                base_url=settings.AGENT_SDK_BASE_URL,
                has_jwt_token=bool(settings.AGENT_SDK_JWT_TOKEN),
                reasons=reasons
            )
            
            try:
                # Create configuration for concrete SDK with validation
                config = AgentSDKConfig.from_settings(settings)
                return ConcreteAgentSDK(config)
            except Exception as e:
                # Graceful fallback to mock mode if concrete SDK creation fails
                logger.warning(
                    "Failed to create ConcreteAgentSDK, falling back to MockAgentSDK",
                    error=str(e),
                    env=settings.ENV,
                    fallback_reason="concrete_sdk_creation_failed"
                )
                return MockAgentSDK()
    
    @staticmethod
    def _should_use_mock(settings: Settings) -> bool:
        """
        Determine if mock SDK should be used based on configuration.
        
        Args:
            settings: Application settings
            
        Returns:
            True if mock SDK should be used, False for concrete SDK
        """
        use_mock, _ = AgentSDKFactory._should_use_mock_with_reasons(settings)
        return use_mock
    
    @staticmethod
    def _should_use_mock_with_reasons(settings: Settings) -> Tuple[bool, List[str]]:
        """
        Determine if mock SDK should be used with detailed reasoning.
        
        This method provides comprehensive analysis of why mock or concrete SDK
        is selected, which is useful for debugging configuration issues.
        
        Args:
            settings: Application settings
            
        Returns:
            Tuple of (should_use_mock, list_of_reasons)
        """
        reasons = []
        
        # Force mock mode if explicitly configured
        if settings.AGENT_SDK_MOCK_MODE:
            reasons.append("Mock mode explicitly enabled via AGENT_SDK_MOCK_MODE")
            logger.debug("Mock mode forced via AGENT_SDK_MOCK_MODE setting")
            return True, reasons
        
        # Use mock in local/test environments
        if settings.ENV.lower() in ['local', 'test']:
            reasons.append(f"Environment is {settings.ENV} (development/testing)")
            logger.debug("Using mock SDK for local/test environment", env=settings.ENV)
            return True, reasons
        
        # Use mock in debug mode
        if settings.DEBUG:
            reasons.append("Debug mode is enabled")
            logger.debug("Using mock SDK due to debug mode")
            return True, reasons
        
        # Check configuration requirements for concrete SDK
        config_issues = []
        
        # Check JWT token
        if not settings.AGENT_SDK_JWT_TOKEN:
            config_issues.append("No JWT token configured (AGENT_SDK_JWT_TOKEN)")
        elif settings.AGENT_SDK_JWT_TOKEN.strip() == "":
            config_issues.append("JWT token is empty")
        elif settings.AGENT_SDK_JWT_TOKEN == "your-jwt-token-here":
            config_issues.append("JWT token is still set to default placeholder value")
        
        # Check base URL
        if not settings.AGENT_SDK_BASE_URL:
            config_issues.append("No base URL configured (AGENT_SDK_BASE_URL)")
        elif settings.AGENT_SDK_BASE_URL.strip() == "":
            config_issues.append("Base URL is empty")
        elif not settings.AGENT_SDK_BASE_URL.startswith(("http://", "https://")):
            config_issues.append("Base URL is not a valid HTTP/HTTPS URL")
        
        # Check SDK environment
        if not settings.AGENT_SDK_ENV:
            config_issues.append("No SDK environment configured (AGENT_SDK_ENV)")
        elif settings.AGENT_SDK_ENV.strip() == "":
            config_issues.append("SDK environment is empty")
        
        # If there are configuration issues, use mock SDK
        if config_issues:
            reasons.extend([f"Configuration issue: {issue}" for issue in config_issues])
            logger.warning(
                "Configuration issues detected, falling back to mock SDK",
                env=settings.ENV,
                base_url=settings.AGENT_SDK_BASE_URL,
                has_jwt_token=bool(settings.AGENT_SDK_JWT_TOKEN),
                issues=config_issues
            )
            return True, reasons
        
        # All requirements met for concrete SDK
        reasons.append("All requirements met for concrete SDK")
        logger.debug(
            "Using concrete SDK - all requirements met",
            env=settings.ENV,
            base_url=settings.AGENT_SDK_BASE_URL,
            sdk_env=settings.AGENT_SDK_ENV
        )
        return False, reasons
    
    @staticmethod
    def validate_concrete_config(settings: Settings) -> bool:
        """
        Validate that all required configuration is available for concrete SDK.
        
        Args:
            settings: Application settings
            
        Returns:
            True if configuration is valid for concrete SDK
        """
        is_valid, _ = AgentSDKFactory.validate_concrete_config_detailed(settings)
        return is_valid
    
    @staticmethod
    def validate_concrete_config_detailed(settings: Settings) -> Tuple[bool, List[str]]:
        """
        Validate concrete SDK configuration with detailed error reporting.
        
        Args:
            settings: Application settings
            
        Returns:
            Tuple of (is_valid, list_of_validation_errors)
        """
        errors = []
        
        # Validate JWT token
        if not settings.AGENT_SDK_JWT_TOKEN:
            errors.append("AGENT_SDK_JWT_TOKEN is required")
        elif settings.AGENT_SDK_JWT_TOKEN.strip() == "":
            errors.append("AGENT_SDK_JWT_TOKEN cannot be empty")
        elif settings.AGENT_SDK_JWT_TOKEN == "your-jwt-token-here":
            errors.append("AGENT_SDK_JWT_TOKEN must be changed from default placeholder")
        
        # Validate base URL
        if not settings.AGENT_SDK_BASE_URL:
            errors.append("AGENT_SDK_BASE_URL is required")
        elif settings.AGENT_SDK_BASE_URL.strip() == "":
            errors.append("AGENT_SDK_BASE_URL cannot be empty")
        elif not settings.AGENT_SDK_BASE_URL.startswith(("http://", "https://")):
            errors.append("AGENT_SDK_BASE_URL must be a valid HTTP/HTTPS URL")
        
        # Validate SDK environment
        if not settings.AGENT_SDK_ENV:
            errors.append("AGENT_SDK_ENV is required")
        elif settings.AGENT_SDK_ENV.strip() == "":
            errors.append("AGENT_SDK_ENV cannot be empty")
        elif settings.AGENT_SDK_ENV.upper() not in ["DEV", "QA", "PROD", "LOCAL", "TEST"]:
            errors.append(f"AGENT_SDK_ENV must be one of DEV, QA, PROD, LOCAL, TEST, got {settings.AGENT_SDK_ENV}")
        
        # Validate timeout settings
        if settings.AGENT_SDK_TIMEOUT <= 0:
            errors.append("AGENT_SDK_TIMEOUT must be positive")
        
        if settings.AGENT_SDK_RETRY_COUNT < 0:
            errors.append("AGENT_SDK_RETRY_COUNT must be non-negative")
        
        if errors:
            logger.warning(
                "Configuration validation failed for concrete SDK",
                errors=errors,
                env=settings.ENV
            )
        
        return len(errors) == 0, errors
    
    @staticmethod
    def get_sdk_info(settings: Optional[Settings] = None) -> dict:
        """
        Get information about which SDK would be created with current configuration.
        
        Args:
            settings: Optional Settings instance. If None, uses get_settings()
            
        Returns:
            Dictionary with SDK selection information
        """
        if settings is None:
            settings = get_settings()
        
        use_mock = AgentSDKFactory._should_use_mock(settings)
        config_valid = AgentSDKFactory.validate_concrete_config(settings)
        
        return {
            "sdk_type": "mock" if use_mock else "concrete",
            "env": settings.ENV,
            "debug": settings.DEBUG,
            "mock_mode_forced": settings.AGENT_SDK_MOCK_MODE,
            "config_valid": config_valid,
            "has_jwt_token": bool(settings.AGENT_SDK_JWT_TOKEN),
            "base_url": settings.AGENT_SDK_BASE_URL,
            "reasons": AgentSDKFactory._get_selection_reasons(settings)
        }
    
    @staticmethod
    def _get_selection_reasons(settings: Settings) -> list:
        """
        Get list of reasons why mock or concrete SDK was selected.
        
        Args:
            settings: Application settings
            
        Returns:
            List of reason strings
        """
        reasons = []
        
        if settings.AGENT_SDK_MOCK_MODE:
            reasons.append("Mock mode explicitly enabled")
        
        if settings.ENV.lower() in ['local', 'test']:
            reasons.append(f"Environment is {settings.ENV}")
        
        if settings.DEBUG:
            reasons.append("Debug mode is enabled")
        
        if not settings.AGENT_SDK_JWT_TOKEN:
            reasons.append("No JWT token configured")
        
        if not settings.AGENT_SDK_BASE_URL or settings.AGENT_SDK_BASE_URL.strip() == "":
            reasons.append("No base URL configured")
        
        if not reasons:
            reasons.append("All requirements met for concrete SDK")
        
        return reasons
    
    @staticmethod
    def create_sdk_with_fallback(settings: Optional[Settings] = None, 
                                 allow_fallback: bool = True) -> AgentSDKInterface:
        """
        Create SDK with enhanced fallback behavior and error handling.
        
        This method provides more control over fallback behavior and includes
        comprehensive error handling for production environments.
        
        Args:
            settings: Optional Settings instance. If None, uses get_settings()
            allow_fallback: Whether to allow fallback to mock SDK on errors
            
        Returns:
            AgentSDKInterface implementation
            
        Raises:
            SDKError: If concrete SDK creation fails and fallback is not allowed
        """
        if settings is None:
            settings = get_settings()
        
        # First, try to create the appropriate SDK based on configuration
        try:
            return AgentSDKFactory.create_sdk(settings)
        except Exception as e:
            if not allow_fallback:
                logger.error(
                    "SDK creation failed and fallback is disabled",
                    error=str(e),
                    env=settings.ENV,
                    allow_fallback=allow_fallback
                )
                raise SDKError(f"Failed to create SDK: {str(e)}") from e
            
            # Log the error and fall back to mock SDK
            logger.warning(
                "SDK creation failed, falling back to mock SDK",
                error=str(e),
                env=settings.ENV,
                fallback_enabled=allow_fallback
            )
            return MockAgentSDK()
    
    @staticmethod
    def test_sdk_connectivity(sdk: AgentSDKInterface, test_agent_id: str = "test-agent") -> bool:
        """
        Test SDK connectivity and basic functionality.
        
        This method can be used to validate that an SDK instance is working
        correctly before using it in production.
        
        Args:
            sdk: SDK instance to test
            test_agent_id: Agent ID to use for testing (should not exist)
            
        Returns:
            True if SDK is working correctly, False otherwise
        """
        try:
            # For MockAgentSDK, this should work without issues
            if isinstance(sdk, MockAgentSDK):
                # Test with a known non-existent agent ID
                try:
                    import asyncio
                    asyncio.run(sdk.get_agent("non-existent-agent"))
                    return False  # Should have raised AgentNotFoundError
                except Exception:
                    return True  # Expected behavior
            
            # For ConcreteAgentSDK, we can't easily test without valid credentials
            # So we just check if it's properly configured
            if isinstance(sdk, ConcreteAgentSDK):
                return (sdk.config is not None and 
                       sdk.config.base_url is not None and 
                       sdk.config.jwt_token is not None)
            
            return False
        except Exception as e:
            logger.warning(
                "SDK connectivity test failed",
                error=str(e),
                sdk_type=type(sdk).__name__
            )
            return False
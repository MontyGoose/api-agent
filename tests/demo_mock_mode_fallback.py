#!/usr/bin/env python3
"""
Demo script showing enhanced mock mode support and fallback behavior.

This script demonstrates the various scenarios where the SDK factory
gracefully falls back to mock mode and provides detailed reasoning.
"""

import asyncio
from app.core.config import Settings
from app.services.sdk_factory import AgentSDKFactory
from app.services.mock_sdk import MockAgentSDK
from app.services.concrete_sdk import ConcreteAgentSDK


def print_separator(title: str):
    """Print a formatted separator with title."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")


def demo_scenario(title: str, settings: Settings):
    """Demonstrate a configuration scenario."""
    print(f"\n--- {title} ---")
    
    # Get SDK info for detailed analysis
    info = AgentSDKFactory.get_sdk_info(settings)
    print(f"SDK Type: {info['sdk_type']}")
    print(f"Environment: {info['env']}")
    print(f"Debug Mode: {info['debug']}")
    print(f"Mock Mode Forced: {info['mock_mode_forced']}")
    print(f"Config Valid: {info['config_valid']}")
    print(f"Has JWT Token: {info['has_jwt_token']}")
    print(f"Base URL: {info['base_url']}")
    
    print("\nReasons for SDK selection:")
    for reason in info['reasons']:
        print(f"  • {reason}")
    
    # Create the actual SDK
    sdk = AgentSDKFactory.create_sdk(settings)
    print(f"\nCreated SDK: {type(sdk).__name__}")
    
    # Test detailed validation if it would use concrete SDK
    if info['sdk_type'] == 'concrete':
        is_valid, errors = AgentSDKFactory.validate_concrete_config_detailed(settings)
        if not is_valid:
            print(f"\nConfiguration errors:")
            for error in errors:
                print(f"  ❌ {error}")
    
    return sdk


async def demo_mock_sdk_functionality():
    """Demonstrate enhanced MockAgentSDK functionality."""
    print_separator("MockAgentSDK Enhanced Functionality")
    
    # Create mock SDK with different configurations
    print("\n--- Standard Mock SDK ---")
    mock_sdk = MockAgentSDK()
    print(f"Simulate delays: {mock_sdk.simulate_delays}")
    print(f"Simulate errors: {mock_sdk.simulate_errors}")
    
    # Test getting an agent
    try:
        agent = await mock_sdk.get_agent("agent-123")
        print(f"Retrieved agent: {agent['name']} (status: {agent['status']})")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test error simulation
    print("\n--- Error Simulation ---")
    try:
        await mock_sdk.get_agent("error-agent")
    except Exception as e:
        print(f"Simulated error: {e}")
    
    # Test adding custom agent
    print("\n--- Custom Agent Management ---")
    custom_agent = {
        "id": "demo-agent",
        "name": "Demo Agent",
        "status": "ready"
    }
    mock_sdk.add_mock_agent("demo-agent", custom_agent)
    
    retrieved = await mock_sdk.get_agent("demo-agent")
    print(f"Custom agent: {retrieved['name']} (status: {retrieved['status']})")
    
    # Show available agents
    available = mock_sdk.get_available_agents()
    print(f"\nTotal available agents: {len(available)}")
    for agent_id, agent_data in available.items():
        print(f"  • {agent_id}: {agent_data['name']}")


def main():
    """Run the demo scenarios."""
    print_separator("Mock Mode Support and Fallback Behavior Demo")
    
    # Scenario 1: Development environment (should use mock)
    dev_settings = Settings(
        ENV="local",
        DEBUG=True,
        SECRET_KEY="dev-key",
        AGENT_SDK_MOCK_MODE=False
    )
    demo_scenario("Development Environment", dev_settings)
    
    # Scenario 2: Production with forced mock mode
    prod_mock_settings = Settings(
        ENV="prod",
        DEBUG=False,
        SECRET_KEY="prod-key",
        AGENT_SDK_MOCK_MODE=True,  # Forced mock
        AGENT_SDK_JWT_TOKEN="valid-token",
        AGENT_SDK_BASE_URL="https://api.example.com",
        AGENT_SDK_ENV="PROD"
    )
    demo_scenario("Production with Forced Mock Mode", prod_mock_settings)
    
    # Scenario 3: Production with missing JWT token (fallback to mock)
    prod_no_jwt_settings = Settings(
        ENV="prod",
        DEBUG=False,
        SECRET_KEY="prod-key",
        AGENT_SDK_MOCK_MODE=False,
        AGENT_SDK_JWT_TOKEN=None,  # Missing JWT
        AGENT_SDK_BASE_URL="https://api.example.com",
        AGENT_SDK_ENV="PROD"
    )
    demo_scenario("Production with Missing JWT (Fallback)", prod_no_jwt_settings)
    
    # Scenario 4: Production with invalid configuration (fallback to mock)
    prod_invalid_settings = Settings(
        ENV="prod",
        DEBUG=False,
        SECRET_KEY="prod-key",
        AGENT_SDK_MOCK_MODE=False,
        AGENT_SDK_JWT_TOKEN="your-jwt-token-here",  # Placeholder
        AGENT_SDK_BASE_URL="invalid-url",  # Invalid URL
        AGENT_SDK_ENV="INVALID",  # Invalid environment
        AGENT_SDK_TIMEOUT=-1,  # Invalid timeout
        AGENT_SDK_RETRY_COUNT=-1  # Invalid retry count
    )
    demo_scenario("Production with Invalid Configuration", prod_invalid_settings)
    
    # Scenario 5: Production with valid configuration (should use concrete)
    prod_valid_settings = Settings(
        ENV="prod",
        DEBUG=False,
        SECRET_KEY="prod-key",
        AGENT_SDK_MOCK_MODE=False,
        AGENT_SDK_JWT_TOKEN="valid-production-token",
        AGENT_SDK_BASE_URL="https://api.production.com",
        AGENT_SDK_ENV="PROD",
        AGENT_SDK_TIMEOUT=180,
        AGENT_SDK_RETRY_COUNT=3
    )
    demo_scenario("Production with Valid Configuration", prod_valid_settings)
    
    # Demonstrate enhanced fallback behavior
    print_separator("Enhanced Fallback Behavior")
    
    print("\n--- Testing create_sdk_with_fallback ---")
    try:
        # This should work normally
        sdk = AgentSDKFactory.create_sdk_with_fallback(prod_valid_settings, allow_fallback=True)
        print(f"Created SDK with fallback enabled: {type(sdk).__name__}")
        
        # Test connectivity
        connectivity_ok = AgentSDKFactory.test_sdk_connectivity(sdk)
        print(f"SDK connectivity test: {'✅ PASS' if connectivity_ok else '❌ FAIL'}")
        
    except Exception as e:
        print(f"Error with fallback: {e}")
    
    # Run async demo
    print_separator("Running Async MockSDK Demo")
    asyncio.run(demo_mock_sdk_functionality())
    
    print_separator("Demo Complete")
    print("\nKey Features Demonstrated:")
    print("✅ MockAgentSDK remains available for development and testing")
    print("✅ Configuration option to force mock mode even in production")
    print("✅ Graceful fallback to mock mode when real SDK configuration is missing")
    print("✅ Comprehensive unit tests for mock mode selection and fallback scenarios")
    print("✅ Enhanced error handling and detailed logging")
    print("✅ Configuration validation with detailed error reporting")


if __name__ == "__main__":
    main()
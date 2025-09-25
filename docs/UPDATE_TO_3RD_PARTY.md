# Migration Guide: Updating to 3rd Party ada_lovelace SDK

This guide details the changes needed to integrate the `ada_lovelace` 3rd party SDK to replace our custom AsyncAgent implementation.

## Overview

The `ada_lovelace` SDK provides:
- `lovelace.Session.connect(jwt_token)` for authentication
- `Agent(id, env, agent_name)` for agent instances
- `agent.view()` for getting agent status JSON

## Required Changes

### 1. Update Dependencies

Add to `pyproject.toml`:
```toml
[tool.poetry.dependencies]
ada-lovelace = "^1.0.0"  # Replace with actual version
```

# 2. Replace Custom AsyncAgent Implementation
Current file to replace: src/app/models/async_agent.py

```
# src/app/models/async_agent.py - NEW IMPLEMENTATION
"""3rd party ada_lovelace SDK integration."""

import ada_lovelace as lovelace
from ada_lovelace.agent import Agent
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)

class AsyncAgent:
    """Wrapper around ada_lovelace Agent for compatibility."""
    
    def __init__(
        self,
        agent_id: str,
        env: str,
        agent_name: Optional[str] = None,
        base_url: Optional[str] = None,
        request_timeout: Optional[int] = 180,
        **kwargs
    ):
        self.agent_id = agent_id
        self.env = env
        self.agent_name = agent_name
        self.base_url = base_url
        self.request_timeout = request_timeout
        self._session = None
        self._agent = None
        
    def set_session_manager(self, session_manager):
        """Set session manager for authentication."""
        self._session_manager = session_manager
        
    async def ensure_authenticated_session(self):
        """Ensure we have an authenticated session."""
        if not self._session_manager:
            raise ValueError("No session manager configured")
            
        jwt_token = self._session_manager.jwt_token
        if not jwt_token:
            raise ValueError("No JWT token available")
            
        # Create lovelace session
        self._session = lovelace.Session.connect(jwt_token=jwt_token)
        lovelace.session = self._session
        
        return self._session
        
    async def _get_agent(self) -> Agent:
        """Get or create ada_lovelace Agent instance."""
        if not self._agent:
            # Ensure we have a session
            await self.ensure_authenticated_session()
            
            # Create ada_lovelace Agent
            self._agent = Agent(
                id=self.agent_id,
                env=self.env,
                agent_name=self.agent_name
            )
            
        return self._agent
        
    async def view(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get agent view using ada_lovelace SDK."""
        try:
            agent = await self._get_agent()
            
            # Use the agent_id parameter if provided, otherwise use instance agent_id
            if agent_id and agent_id != self.agent_id:
                # Create new agent instance for different ID
                temp_agent = Agent(
                    id=agent_id,
                    env=self.env,
                    agent_name=self.agent_name
                )
                result = temp_agent.view()
            else:
                result = agent.view()
                
            logger.debug(
                "Successfully retrieved agent view",
                agent_id=agent_id or self.agent_id,
                result_keys=list(result.keys()) if isinstance(result, dict) else "not_dict"
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "Failed to get agent view",
                agent_id=agent_id or self.agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
```

# 3. Update Session Management
Update: src/app/models/session.py

```
# src/app/models/session.py - UPDATED
"""Session management using ada_lovelace SDK."""

import ada_lovelace as lovelace
from ada_lovelace.agent import Agent
import jwt
from datetime import datetime, timezone
from typing import Dict, Optional
import structlog

logger = structlog.get_logger(__name__)

class Session:
    """Session wrapper for ada_lovelace integration."""
    
    def __init__(self, jwt_token: str):
        self.jwt_token = jwt_token
        self._lovelace_session = None
        self._decoded_token = None
        
    @classmethod
    def connect(cls, jwt_token: str) -> 'Session':
        """Create and connect session using ada_lovelace."""
        session = cls(jwt_token)
        
        try:
            # Connect using ada_lovelace
            lovelace_session = lovelace.Session.connect(jwt_token=jwt_token)
            session._lovelace_session = lovelace_session
            
            # Set global session
            lovelace.session = lovelace_session
            
            logger.info("Successfully connected ada_lovelace session")
            return session
            
        except Exception as e:
            logger.error("Failed to connect ada_lovelace session", error=str(e))
            raise
    
    @property
    def user_id(self) -> Optional[str]:
        """Get user ID from JWT token."""
        if not self._decoded_token:
            try:
                # Decode without verification for user_id (verification handled by ada_lovelace)
                self._decoded_token = jwt.decode(
                    self.jwt_token, 
                    options={"verify_signature": False}
                )
            except Exception:
                return None
        return self._decoded_token.get("sub")
    
    @property
    def roles(self) -> list:
        """Get roles from JWT token."""
        if not self._decoded_token:
            try:
                self._decoded_token = jwt.decode(
                    self.jwt_token, 
                    options={"verify_signature": False}
                )
            except Exception:
                return []
        return self._decoded_token.get("roles", [])
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if not self._decoded_token:
            try:
                self._decoded_token = jwt.decode(
                    self.jwt_token, 
                    options={"verify_signature": False}
                )
            except Exception:
                return True
                
        exp = self._decoded_token.get("exp")
        if not exp:
            return True
            
        return datetime.now(timezone.utc).timestamp() > exp
    
    def is_valid(self) -> bool:
        """Check if session is valid."""
        return not self.is_expired() and self._lovelace_session is not None
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": f"Bearer {self.jwt_token}",
            "Content-Type": "application/json"
        }

class SessionManager:
    """Session manager for ada_lovelace integration."""
    
    def __init__(self, jwt_token: Optional[str] = None):
        self.jwt_token = jwt_token
        self._session = None
        
    def set_token(self, jwt_token: str):
        """Set JWT token and reset session."""
        self.jwt_token = jwt_token
        self._session = None
        
    def get_session(self) -> Optional[Session]:
        """Get current session."""
        return self._session
        
    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return (
            self.jwt_token is not None and 
            self._session is not None and 
            self._session.is_valid()
        )
        
    def validate_token(self, token: Optional[str] = None) -> bool:
        """Validate JWT token."""
        token_to_validate = token or self.jwt_token
        if not token_to_validate:
            return False
            
        try:
            # Let ada_lovelace handle validation by attempting connection
            test_session = lovelace.Session.connect(jwt_token=token_to_validate)
            return test_session is not None
        except Exception:
            return False
```
# 4. Update ConcreteAgentSDK
Update: src/app/services/concrete_sdk.py
```
# Key changes to ConcreteAgentSDK

class ConcreteAgentSDK(AgentSDKInterface):
    """Concrete implementation using ada_lovelace SDK."""
    
    async def _create_async_agent(self, agent_id: str) -> AsyncAgent:
        """Create AsyncAgent using ada_lovelace."""
        try:
            # Validate configuration
            if not self.config.env:
                raise SDKConfigurationError(
                    "Environment is required for ada_lovelace Agent creation",
                    missing_fields=["env"]
                )
            
            # Create AsyncAgent wrapper
            async_agent = AsyncAgent(
                agent_id=agent_id,
                env=self.config.env,
                agent_name=f"Agent-{agent_id}",  # Default name
                request_timeout=self.config.request_timeout
            )
            
            # Set session manager
            if self.session_manager:
                async_agent.set_session_manager(self.session_manager)
            else:
                raise AuthenticationError(
                    "No JWT token configured for ada_lovelace authentication",
                    details={"agent_id": agent_id, "operation": "create_async_agent"}
                )
            
            return async_agent
            
        except (AuthenticationError, SDKConfigurationError):
            raise
        except Exception as e:
            logger.error(
                "Failed to create AsyncAgent with ada_lovelace",
                agent_id=agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            mapped_error = self._map_sdk_exceptions(e, agent_id, "create_async_agent")
            raise mapped_error
```
# 5. Update Error Mapping
Add to: src/app/services/exceptions.py
```
# Add ada_lovelace specific error mappings

class SDKErrorMapper:
    """Enhanced error mapper for ada_lovelace SDK."""
    
    @staticmethod
    def map_ada_lovelace_error(error: Exception, agent_id: str = None, operation: str = None) -> Exception:
        """Map ada_lovelace specific errors."""
        error_message = str(error).lower()
        error_type = type(error).__name__
        
        # Map ada_lovelace authentication errors
        if "authentication" in error_message or "unauthorized" in error_message:
            return AuthenticationError(
                f"ada_lovelace authentication failed: {str(error)}",
                details={"agent_id": agent_id, "operation": operation}
            )
        
        # Map ada_lovelace session errors
        if "session" in error_message or "token" in error_message:
            return SessionError(
                f"ada_lovelace session error: {str(error)}",
                details={"agent_id": agent_id, "operation": operation}
            )
        
        # Map ada_lovelace agent not found
        if "not found" in error_message or "404" in error_message:
            return AgentNotFoundError(
                agent_id or "unknown",
                f"Agent not found in ada_lovelace: {str(error)}"
            )
        
        # Map ada_lovelace connection errors
        if any(keyword in error_type.lower() for keyword in ['connection', 'network', 'timeout']):
            return SDKConnectionError(
                f"ada_lovelace connection failed: {str(error)}",
                original_error=error
            )
        
        # Generic ada_lovelace error
        return SDKError(
            f"ada_lovelace SDK error: {str(error)}",
            original_error=error
        )
```
# 6. Update Configuration
Add to: src/app/core/config.py
```
class Settings(BaseSettings):
    # ... existing settings ...
    
    # ada_lovelace SDK settings
    ADA_LOVELACE_VERSION: str = "1.0.0"
    ADA_LOVELACE_DEBUG: bool = False
    
    # Keep existing SDK settings for compatibility
    AGENT_SDK_JWT_TOKEN: Optional[str] = None
    AGENT_SDK_ENV: str = "DEV"
    AGENT_SDK_TIMEOUT: int = 180
    AGENT_SDK_RETRY_COUNT: int = 3

```
# 7. Update Tests
Update: tests/test_concrete_sdk.py
```
# Add ada_lovelace specific tests

class TestAdaLovelaceIntegration:
    """Tests for ada_lovelace SDK integration."""
    
    @patch('ada_lovelace.Session.connect')
    @patch('ada_lovelace.agent.Agent')
    def test_ada_lovelace_agent_creation(self, mock_agent_class, mock_session_connect):
        """Test ada_lovelace Agent creation."""
        # Mock ada_lovelace components
        mock_session = MagicMock()
        mock_session_connect.return_value = mock_session
        
        mock_agent = MagicMock()
        mock_agent.view.return_value = {
            "agentId": "test-agent",
            "agentName": "Test Agent",
            "agentConfig": {"status": "active"}
        }
        mock_agent_class.return_value = mock_agent
        
        # Test agent creation and view
        config = AgentSDKConfig(
            jwt_token="test-token",
            env="TEST",
            base_url="https://test.example.com"
        )
        
        sdk = ConcreteAgentSDK(config)
        
        # This should work with ada_lovelace
        result = asyncio.run(sdk.get_agent("test-agent"))
        
        # Verify ada_lovelace was called correctly
        mock_session_connect.assert_called_once_with(jwt_token="test-token")
        mock_agent_class.assert_called_once_with(
            id="test-agent",
            env="TEST",
            agent_name="Agent-test-agent"
        )
        mock_agent.view.assert_called_once()
        
        assert result["id"] == "test-agent"
        assert result["name"] == "Test Agent"
        assert result["status"] == "active"
```
# 8. Update Requirements
Add to requirements or pyproject.toml:
```
ada-lovelace>=1.0.0
```
# 9. Migration Steps
Install ada_lovelace SDK:
```
pip install ada-lovelace
# or
poetry add ada-lovelace
```
Update imports in affected files:
- Replace custom AsyncAgent imports with ada_lovelace imports
- Update session management imports

Test the integration:
```
pytest tests/test_concrete_sdk.py -v
pytest tests/test_session_integration.py -v
```
Update environment variables:

- Ensure AGENT_SDK_JWT_TOKEN is set
- Ensure AGENT_SDK_ENV matches ada_lovelace environment expectations

# 10. Rollback Plan
If issues occur:

Keep backup of original files:

- src/app/models/async_agent.py.backup
- src/app/models/session.py.backup
- src/app/services/concrete_sdk.py.backup

Revert changes:

- git checkout HEAD~1 -- src/app/models/async_agent.py
- git checkout HEAD~1 -- src/app/models/session.py
- git checkout HEAD~1 -- src/app/services/concrete_sdk.py

Remove ada_lovelace dependency:

```pip uninstall ada-lovelace
```
11. Validation Checklist
- [ ] ada_lovelace SDK installed successfully
- [ ] All imports updated
- [ ] Session management works with ada_lovelace
- [ ] Agent creation and view() method work
- [ ] All existing tests pass
- [ ] Integration tests pass with real ada_lovelace SDK
- [ ] Error handling works correctly
- [ ] Logging captures ada_lovelace operations
- [ ] Configuration supports ada_lovelace settings

This migration maintains backward compatibility while leveraging the robust ada_lovelace SDK for production use.
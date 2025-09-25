"""Integration tests for session management with AsyncAgent."""

import pytest
import jwt
from datetime import datetime, timezone, timedelta

from src.app.models.async_agent import AsyncAgent
from src.app.models.session import Session, SessionManager
from src.app.services.exceptions import SDKError


class TestSessionIntegration:
    """Integration tests for session management functionality."""
    
    @pytest.mark.asyncio
    async def test_complete_session_workflow(self):
        """Test complete session workflow from JWT token to authenticated agent."""
        # Step 1: Create JWT token
        payload = {
            "sub": "user123",
            "roles": ["user", "admin"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        jwt_token = jwt.encode(payload, "test-secret", algorithm="HS256")
        
        # Step 2: Create SessionManager
        session_manager = SessionManager(jwt_token=jwt_token)
        
        # Step 3: Create AsyncAgent and set session manager
        agent = AsyncAgent(
            agent_id="test-agent-123",
            agent_name="Test Agent",
            env="DEV",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Step 4: Ensure authenticated session
        session = await agent.ensure_authenticated_session()
        
        # Step 5: Verify session properties
        assert session.jwt_token == jwt_token
        assert session.user_id == "user123"
        assert session.roles == ["user", "admin"]
        assert not session.is_expired()
        assert session.is_valid()
        
        # Step 6: Get authentication headers
        auth_headers = session.get_auth_headers()
        expected_headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        }
        assert auth_headers == expected_headers
        
        # Step 7: Verify session manager state
        assert session_manager.is_authenticated()
        assert session_manager.validate_token()
        current_session = session_manager.get_session()
        assert current_session == session
    
    @pytest.mark.asyncio
    async def test_agent_initialization_with_session_object(self):
        """Test agent initialization directly with Session object."""
        # Create JWT token and session
        payload = {
            "sub": "user456",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
        }
        jwt_token = jwt.encode(payload, "test-secret", algorithm="HS256")
        session = Session.connect(jwt_token)
        
        # Create agent with session
        agent = AsyncAgent(
            agent_id="test-agent-456",
            session=session,
            env="QA"
        )
        
        # Verify session manager was created automatically
        assert agent.session == session
        session_manager = agent.get_session_manager()
        assert session_manager is not None
        assert session_manager.jwt_token == jwt_token
        
        # Verify we can get authenticated session
        auth_session = await agent.ensure_authenticated_session()
        assert auth_session.jwt_token == jwt_token
        assert auth_session.user_id == "user456"
    
    @pytest.mark.asyncio
    async def test_session_expiration_handling(self):
        """Test handling of expired sessions."""
        # Create expired JWT token
        expired_payload = {
            "sub": "user789",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "test-secret", algorithm="HS256")
        
        # Create session manager with expired token
        session_manager = SessionManager(jwt_token=expired_token)
        agent = AsyncAgent()
        agent.set_session_manager(session_manager)
        
        # Should still create session (expiration is checked but doesn't prevent creation)
        session = await agent.ensure_authenticated_session()
        assert session.is_expired()
        assert not session.is_valid()
        
        # Session manager should report not authenticated due to expired token
        assert not session_manager.is_authenticated()
    
    @pytest.mark.asyncio
    async def test_session_token_refresh(self):
        """Test refreshing session with new token."""
        # Create initial token
        payload1 = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp())
        }
        token1 = jwt.encode(payload1, "test-secret", algorithm="HS256")
        
        # Create agent with initial session
        session_manager = SessionManager(jwt_token=token1)
        agent = AsyncAgent()
        agent.set_session_manager(session_manager)
        
        # Get initial session
        session1 = await agent.ensure_authenticated_session()
        assert session1.jwt_token == token1
        
        # Create new token (simulating refresh)
        payload2 = {
            "sub": "user123",
            "roles": ["user", "premium"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
        }
        token2 = jwt.encode(payload2, "test-secret", algorithm="HS256")
        
        # Update session manager with new token
        session_manager.set_token(token2)
        
        # Get new session
        session2 = await agent.ensure_authenticated_session()
        assert session2.jwt_token == token2
        assert session2.roles == ["user", "premium"]
        assert session2 is not session1  # Should be a new session instance
    
    @pytest.mark.asyncio
    async def test_multiple_agents_with_different_sessions(self):
        """Test multiple agents with different session managers."""
        # Create two different JWT tokens
        payload1 = {
            "sub": "user1",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token1 = jwt.encode(payload1, "test-secret", algorithm="HS256")
        
        payload2 = {
            "sub": "user2",
            "roles": ["admin"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token2 = jwt.encode(payload2, "test-secret", algorithm="HS256")
        
        # Create two agents with different sessions
        agent1 = AsyncAgent(agent_id="agent1")
        agent1.set_session_manager(SessionManager(jwt_token=token1))
        
        agent2 = AsyncAgent(agent_id="agent2")
        agent2.set_session_manager(SessionManager(jwt_token=token2))
        
        # Get sessions for both agents
        session1 = await agent1.ensure_authenticated_session()
        session2 = await agent2.ensure_authenticated_session()
        
        # Verify they have different sessions and users
        assert session1.user_id == "user1"
        assert session1.roles == ["user"]
        assert session2.user_id == "user2"
        assert session2.roles == ["admin"]
        assert session1.jwt_token != session2.jwt_token
    
    def test_session_manager_validation_methods(self):
        """Test session manager validation methods."""
        # Valid token
        valid_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        valid_token = jwt.encode(valid_payload, "test-secret", algorithm="HS256")
        
        # Expired token
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "test-secret", algorithm="HS256")
        
        # Test with valid token
        manager = SessionManager(jwt_token=valid_token)
        assert manager.validate_token()
        assert manager.validate_token(valid_token)
        
        # Test with expired token
        manager.set_token(expired_token)
        assert not manager.validate_token()
        assert not manager.validate_token(expired_token)
        
        # Test with invalid format
        assert not manager.validate_token("invalid.format")
        
        # Test with no token
        manager_no_token = SessionManager()
        assert not manager_no_token.validate_token()
    
    @pytest.mark.asyncio
    async def test_error_scenarios(self):
        """Test various error scenarios in session management."""
        # Agent without session manager
        agent = AsyncAgent()
        with pytest.raises(SDKError, match="No session manager available"):
            await agent.ensure_authenticated_session()
        
        # Session manager without token
        empty_manager = SessionManager()
        agent.set_session_manager(empty_manager)
        with pytest.raises(SDKError, match="No JWT token available"):
            await agent.ensure_authenticated_session()
        
        # Invalid JWT token format
        with pytest.raises(ValueError, match="Invalid JWT token format"):
            Session(jwt_token="invalid.format")
        
        # Malformed JWT token
        with pytest.raises(SDKError, match="Invalid JWT token"):
            Session.connect("invalid.jwt.token")
"""Tests for session management and JWT authentication."""

import pytest
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from src.app.models.session import Session, SessionManager, AuthenticationError, SessionError
from src.app.services.exceptions import SDKError


class TestSession:
    """Test cases for Session class."""
    
    def test_session_creation_with_valid_token(self):
        """Test creating session with valid JWT token."""
        # Create a valid JWT token
        payload = {
            "sub": "user123",
            "roles": ["user", "admin"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        session = Session.connect(token)
        
        assert session.jwt_token == token
        assert session.user_id == "user123"
        assert session.roles == ["user", "admin"]
        assert session.expires_at is not None
        assert not session.is_expired()
        assert session.is_valid()
    
    def test_session_creation_with_invalid_token_format(self):
        """Test session creation fails with invalid token format."""
        invalid_tokens = [
            "",
            "invalid",
            "invalid.token",
            "invalid.token.format.extra"
        ]
        
        for invalid_token in invalid_tokens:
            with pytest.raises(ValueError):
                Session(jwt_token=invalid_token)
        
        # Test None separately
        with pytest.raises(ValueError):
            Session(jwt_token=None)
    
    def test_session_jwt_format_validation(self):
        """Test JWT format validation."""
        # Valid format
        valid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
        session = Session(jwt_token=valid_token)
        assert session.jwt_token == valid_token
        
        # Invalid formats
        with pytest.raises(ValueError, match="Invalid JWT token format"):
            Session(jwt_token="invalid.format")
        
        with pytest.raises(ValueError, match="JWT token must be a non-empty string"):
            Session(jwt_token="")
    
    def test_session_expiration_check(self):
        """Test session expiration checking."""
        # Create expired token
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        
        session = Session.connect(expired_token)
        assert session.is_expired()
        assert not session.is_valid()
        
        # Create valid token
        valid_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        valid_token = jwt.encode(valid_payload, "secret", algorithm="HS256")
        
        session = Session.connect(valid_token)
        assert not session.is_expired()
        assert session.is_valid()
    
    def test_session_without_expiration(self):
        """Test session without expiration time."""
        payload = {"sub": "user123"}  # No exp claim
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        session = Session.connect(token)
        assert session.expires_at is None
        assert not session.is_expired()  # Should not be expired if no exp claim
        assert session.is_valid()
    
    def test_get_auth_headers(self):
        """Test getting authentication headers."""
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
        session = Session(jwt_token=token)
        
        headers = session.get_auth_headers()
        expected_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        assert headers == expected_headers
    
    def test_session_connect_with_malformed_jwt(self):
        """Test session creation with malformed JWT."""
        # JWT with invalid base64 encoding
        malformed_token = "invalid.jwt.token"
        
        with pytest.raises(SDKError, match="Invalid JWT token"):
            Session.connect(malformed_token)


class TestSessionManager:
    """Test cases for SessionManager class."""
    
    def test_session_manager_initialization(self):
        """Test SessionManager initialization."""
        # Without token
        manager = SessionManager()
        assert manager.jwt_token is None
        assert manager._session is None
        assert not manager.is_authenticated()
        
        # With token
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
        manager = SessionManager(jwt_token=token)
        assert manager.jwt_token == token
        assert manager._session is None
    
    @pytest.mark.asyncio
    async def test_ensure_session_success(self):
        """Test successful session creation."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        session = await manager.ensure_session()
        
        assert session is not None
        assert session.jwt_token == token
        assert session.user_id == "user123"
        assert manager._session == session
    
    @pytest.mark.asyncio
    async def test_ensure_session_without_token(self):
        """Test ensure_session fails without token."""
        manager = SessionManager()
        
        with pytest.raises(SDKError, match="No JWT token available"):
            await manager.ensure_session()
    
    @pytest.mark.asyncio
    async def test_ensure_session_reuses_valid_session(self):
        """Test that ensure_session reuses valid existing session."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        
        # First call creates session
        session1 = await manager.ensure_session()
        
        # Second call should reuse the same session
        session2 = await manager.ensure_session()
        
        assert session1 is session2
    
    @pytest.mark.asyncio
    async def test_ensure_session_recreates_expired_session(self):
        """Test that ensure_session recreates expired session."""
        # Create expired token
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        
        # Create valid token
        valid_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        valid_token = jwt.encode(valid_payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=expired_token)
        
        # First call with expired token should create expired session
        session1 = await manager.ensure_session()
        assert session1.is_expired()
        
        # Update token and call again
        manager.set_token(valid_token)
        session2 = await manager.ensure_session()
        
        assert session2 is not session1
        assert not session2.is_expired()
    
    def test_set_token(self):
        """Test setting JWT token."""
        manager = SessionManager()
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
        
        manager.set_token(token)
        
        assert manager.jwt_token == token
        assert manager._session is None  # Should clear existing session
    
    def test_validate_token_valid(self):
        """Test token validation with valid token."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        
        assert manager.validate_token()
        assert manager.validate_token(token)  # Explicit token
    
    def test_validate_token_expired(self):
        """Test token validation with expired token."""
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=expired_token)
        
        assert not manager.validate_token()
        assert not manager.validate_token(expired_token)
    
    def test_validate_token_invalid_format(self):
        """Test token validation with invalid format."""
        manager = SessionManager(jwt_token="invalid.format")
        
        assert not manager.validate_token()
        assert not manager.validate_token("invalid.format")
    
    def test_validate_token_no_token(self):
        """Test token validation without token."""
        manager = SessionManager()
        
        assert not manager.validate_token()
        assert not manager.validate_token(None)
    
    def test_get_session_valid(self):
        """Test getting valid session."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        manager._session = Session.connect(token)
        
        session = manager.get_session()
        assert session is not None
        assert session.is_valid()
    
    def test_get_session_expired(self):
        """Test getting expired session returns None."""
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=expired_token)
        manager._session = Session.connect(expired_token)
        
        session = manager.get_session()
        assert session is None  # Should return None for expired session
    
    def test_get_session_none(self):
        """Test getting session when none exists."""
        manager = SessionManager()
        
        session = manager.get_session()
        assert session is None
    
    def test_clear_session(self):
        """Test clearing session."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        manager._session = Session.connect(token)
        
        assert manager._session is not None
        
        manager.clear_session()
        
        assert manager._session is None
    
    def test_is_authenticated_true(self):
        """Test is_authenticated returns True for valid session."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        manager._session = Session.connect(token)
        
        assert manager.is_authenticated()
    
    def test_is_authenticated_false(self):
        """Test is_authenticated returns False for invalid/no session."""
        # No session
        manager = SessionManager()
        assert not manager.is_authenticated()
        
        # Expired session
        expired_payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=expired_token)
        manager._session = Session.connect(expired_token)
        
        assert not manager.is_authenticated()


class TestAuthenticationScenarios:
    """Test various authentication scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete authentication flow."""
        # Create valid JWT token
        payload = {
            "sub": "user123",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        # Initialize session manager
        manager = SessionManager(jwt_token=token)
        
        # Ensure session is created
        session = await manager.ensure_session()
        
        # Verify authentication
        assert manager.is_authenticated()
        assert session.user_id == "user123"
        assert session.roles == ["user"]
        
        # Get auth headers
        headers = session.get_auth_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == f"Bearer {token}"
    
    @pytest.mark.asyncio
    async def test_token_refresh_scenario(self):
        """Test token refresh scenario."""
        # Create initial token
        payload1 = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
        }
        token1 = jwt.encode(payload1, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token1)
        session1 = await manager.ensure_session()
        
        # Simulate token refresh with new token
        payload2 = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token2 = jwt.encode(payload2, "secret", algorithm="HS256")
        
        manager.set_token(token2)
        session2 = await manager.ensure_session()
        
        # Should have new session with new token
        assert session2 is not session1
        assert session2.jwt_token == token2
    
    def test_authentication_error_scenarios(self):
        """Test various authentication error scenarios."""
        # Invalid token format
        with pytest.raises(ValueError):
            Session(jwt_token="invalid")
        
        # Malformed JWT
        with pytest.raises(SDKError):
            Session.connect("invalid.jwt.token")
        
        # Empty token
        with pytest.raises(ValueError):
            Session(jwt_token="")
    
    @pytest.mark.asyncio
    async def test_concurrent_session_access(self):
        """Test concurrent access to session manager."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        manager = SessionManager(jwt_token=token)
        
        # Simulate concurrent calls to ensure_session
        import asyncio
        sessions = await asyncio.gather(
            manager.ensure_session(),
            manager.ensure_session(),
            manager.ensure_session()
        )
        
        # All should return the same session instance
        assert all(session is sessions[0] for session in sessions)
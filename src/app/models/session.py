"""Session management and JWT authentication for Agent SDK."""

import jwt
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator

from ..services.exceptions import SDKError


class Session(BaseModel):
    """
    Session model representing an active JWT-authenticated session.
    
    This class represents an active session with JWT token validation
    and provides methods for session lifecycle management.
    """
    
    jwt_token: str = Field(..., description="JWT token for authentication")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")
    user_id: Optional[str] = Field(None, description="User ID from token")
    roles: Optional[list[str]] = Field(None, description="User roles from token")
    
    @field_validator("jwt_token")
    @classmethod
    def validate_jwt_format(cls, v: str) -> str:
        """
        Validate JWT token format.
        
        Args:
            v: JWT token string
            
        Returns:
            Validated JWT token
            
        Raises:
            ValueError: If JWT format is invalid
        """
        if not v or not isinstance(v, str):
            raise ValueError("JWT token must be a non-empty string")
        
        # Basic JWT format validation (3 parts separated by dots)
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        if not jwt_pattern.match(v):
            raise ValueError("Invalid JWT token format")
        
        return v
    
    @classmethod
    def connect(cls, jwt_token: str) -> "Session":
        """
        Create a new session with JWT token validation.
        
        Args:
            jwt_token: JWT token for authentication
            
        Returns:
            New Session instance
            
        Raises:
            SDKError: If token validation fails
        """
        try:
            # Create session instance (this will validate the token format)
            session = cls(jwt_token=jwt_token)
            
            # Decode token to extract information (without verification for now)
            # In a real implementation, you would verify the signature
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Extract user information
            session.user_id = decoded.get("sub")
            session.roles = decoded.get("roles", [])
            
            # Extract expiration time
            if "exp" in decoded:
                session.expires_at = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
            
            return session
            
        except jwt.InvalidTokenError as e:
            raise SDKError(f"Invalid JWT token: {str(e)}", original_error=e)
        except Exception as e:
            raise SDKError(f"Failed to create session: {str(e)}", original_error=e)
    
    def is_expired(self) -> bool:
        """
        Check if the session token is expired.
        
        Returns:
            True if token is expired, False otherwise
        """
        if self.expires_at is None:
            return False
        
        return datetime.now(timezone.utc) >= self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if the session is valid (not expired and has valid token).
        
        Returns:
            True if session is valid, False otherwise
        """
        return not self.is_expired() and bool(self.jwt_token)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for API requests.
        
        Returns:
            Dictionary with authorization header
        """
        return {
            "Authorization": f"Bearer {self.jwt_token}",
            "Content-Type": "application/json"
        }


class SessionManager:
    """
    Manages JWT session lifecycle and authentication.
    
    This class handles JWT token validation, session creation,
    and session lifecycle management with proper error handling.
    """
    
    def __init__(self, jwt_token: Optional[str] = None):
        """
        Initialize SessionManager.
        
        Args:
            jwt_token: Optional JWT token for immediate session creation
        """
        self.jwt_token = jwt_token
        self._session: Optional[Session] = None
    
    async def ensure_session(self) -> Session:
        """
        Ensure an active session exists.
        
        Returns:
            Active Session instance
            
        Raises:
            SDKError: If no token is available or session creation fails
        """
        if self._session is None or not self._session.is_valid():
            if not self.jwt_token:
                raise SDKError("No JWT token available for session creation")
            
            self._session = Session.connect(self.jwt_token)
        
        return self._session
    
    def set_token(self, jwt_token: str) -> None:
        """
        Set JWT token and invalidate current session.
        
        Args:
            jwt_token: New JWT token
        """
        self.jwt_token = jwt_token
        self._session = None
    
    def validate_token(self, jwt_token: Optional[str] = None) -> bool:
        """
        Validate JWT token format and expiration.
        
        Args:
            jwt_token: Token to validate, uses instance token if None
            
        Returns:
            True if token is valid, False otherwise
        """
        token = jwt_token or self.jwt_token
        if not token:
            return False
        
        try:
            # Validate format
            Session.validate_jwt_format(token)
            
            # Check expiration
            decoded = jwt.decode(token, options={"verify_signature": False})
            if "exp" in decoded:
                exp_time = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
                if datetime.now(timezone.utc) >= exp_time:
                    return False
            
            return True
            
        except (jwt.InvalidTokenError, ValueError):
            return False
    
    def get_session(self) -> Optional[Session]:
        """
        Get current session if available and valid.
        
        Returns:
            Current Session or None if no valid session
        """
        if self._session and self._session.is_valid():
            return self._session
        return None
    
    def clear_session(self) -> None:
        """Clear current session."""
        self._session = None
    
    def is_authenticated(self) -> bool:
        """
        Check if currently authenticated with valid session.
        
        Returns:
            True if authenticated, False otherwise
        """
        session = self.get_session()
        return session is not None and session.is_valid()


# Import exceptions from the main exceptions module to avoid duplication
from ..services.exceptions import AuthenticationError, SessionError
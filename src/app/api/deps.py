from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated, Any, Dict

from app.core.config import get_settings
from app.core.security import decode_token
from app.models.schemas import User
from app.services.agent_service import AgentService
from app.services.factory import create_agent_service
from app.services.sdk_factory import AgentSDKFactory

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    settings = get_settings()
    try:
        payload: Dict[str, Any] = decode_token(token, settings.SECRET_KEY)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    username = payload.get("sub")
    roles = payload.get("roles", [])
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    return User(username=username, roles=roles)


def require_roles(*required: str):
    def checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        if not set(required).issubset(set(user.roles)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user

    return checker


def get_agent_service() -> AgentService:
    """Get configured AgentService instance with appropriate SDK implementation."""
    settings = get_settings()
    
    # Use factory to create appropriate SDK implementation
    sdk = AgentSDKFactory.create_sdk(settings)
    
    return create_agent_service(sdk)

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated, Any, Dict

from app.core.config import get_settings
from app.core.security import decode_token
from app.models.schemas import User

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

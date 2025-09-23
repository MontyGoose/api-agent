from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.schemas import Token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

@router.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()) -> Token:
    # Demo login: accepts any username and returns a JWT with 'user' role.
    # Replace with your identity provider / user store and real validation.
    settings = get_settings()
    roles = ["user"]
    if form.username == "admin":
        roles.append("admin")
    token = create_access_token(
        subject=form.username,
        roles=roles,
        secret_key=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    return Token(access_token=token)

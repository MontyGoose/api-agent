from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt


def create_access_token(*, subject: str, roles: list[str], secret_key: str, expires_minutes: int = 15) -> str:
    now = datetime.now(timezone.utc)
    to_encode: Dict[str, Any] = {
        "sub": subject,
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(to_encode, secret_key, algorithm="HS256")


def decode_token(token: str, secret_key: str) -> Dict[str, Any]:
    return jwt.decode(token, secret_key, algorithms=["HS256"])

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

import jwt
from jwt import PyJWTError

from app.core.config import settings

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def create_jwt(payload: dict[str, Any], expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    now = _utcnow()
    to_encode.update(
        {
            "iat": int(now.timestamp()),
            "exp": int((now + expires_delta).timestamp()),
        }
    )
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_jwt(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except PyJWTError as e:
        raise ValueError("Invalid token") from e

def new_jti() -> str:
    return str(uuid.uuid4())

def create_access_token(user_id: str) -> str:
    return create_jwt(
        {"sub": user_id, "type": "ACCESS"},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

def create_refresh_token(user_id: str, jti: str) -> str:
    return create_jwt(
        {"sub": user_id, "type": "REFRESH", "jti": jti},
        expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES),
    )

def create_one_time_token(user_id: str, token_type: str, jti: str, ttl_minutes: int) -> str:
    return create_jwt(
        {"sub": user_id, "type": token_type, "jti": jti},
        expires_delta=timedelta(minutes=ttl_minutes),
    )

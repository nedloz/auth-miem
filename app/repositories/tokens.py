from __future__ import annotations

from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from app.models.token import Token

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

async def add_token(
    db: AsyncSession,
    *,
    user_id: str,
    jti: str,
    token_type: str,
    expires_at: datetime,
) -> Token:
    token = Token(
        user_id=user_id,
        jti=jti,
        token_type=token_type,
        expires_at=expires_at,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token

async def get_by_jti(db: AsyncSession, jti: str) -> Token | None:
    result = await db.execute(select(Token).where(Token.jti == jti))
    return result.scalar_one_or_none()

async def mark_used(db: AsyncSession, jti: str) -> None:
    await db.execute(update(Token).where(Token.jti == jti).values(used_at=_utcnow()))
    await db.commit()

async def revoke(db: AsyncSession, jti: str) -> None:
    await db.execute(update(Token).where(Token.jti == jti).values(revoked_at=_utcnow()))
    await db.commit()

async def revoke_all_refresh(db: AsyncSession, user_id: str) -> None:
    await db.execute(
        update(Token)
        .where(Token.user_id == user_id, Token.token_type == "REFRESH", Token.revoked_at.is_(None))
        .values(revoked_at=_utcnow())
    )
    await db.commit()

async def delete_expired(db: AsyncSession) -> None:
    await db.execute(delete(Token).where(Token.expires_at < _utcnow()))
    await db.commit()

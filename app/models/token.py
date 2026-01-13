from __future__ import annotations

from sqlalchemy import String, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone
import uuid

from app.db.base import Base

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"), index=True)

    # JWT jti (unique identifier) used for one-time tokens and refresh tokens
    jti: Mapped[str] = mapped_column(String, unique=True, index=True)

    # ACCESS tokens are not stored. Stored types: REFRESH, EMAIL_VERIFY, LOGIN_MAGIC, PASSWORD_RESET
    token_type: Mapped[str] = mapped_column(String, index=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

Index("ix_tokens_user_type", Token.user_id, Token.token_type)

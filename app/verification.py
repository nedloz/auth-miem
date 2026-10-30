"""Единый сценарий подтверждения почты для публичного и внутреннего API."""

import hashlib
import math
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.mail import EmailDeliveryError, send_verification_email
from app.models import EmailVerification, User
from app.redis import cache_one_time_token, delete_cached_one_time_token


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def build_frontend_url(path: str, token: str) -> str:
    return (
        f"{settings.FRONTEND_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
        f"?{urlencode({'token': token})}"
    )


async def request_email_verification(
    db: AsyncSession,
    user_id: UUID,
    *,
    delivery_error_detail: str = "Verification email could not be sent",
) -> str:
    # Все выдачи и подтверждения сериализуются на одной строке пользователя.
    # Это также не даёт параллельным resend обходить интервал отправки.
    user = (
        await db.execute(
            select(User)
            .where(User.id == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalars().first()
    if user is None or not user.is_active or user.is_email_verified:
        return "skipped"

    now = datetime.now(timezone.utc)
    latest = (
        await db.execute(
            select(EmailVerification)
            .where(
                EmailVerification.user_id == user.id,
                EmailVerification.used_at.is_(None),
            )
            .order_by(EmailVerification.created_at.desc())
            .limit(1)
        )
    ).scalars().first()
    if latest is not None:
        retry_after = math.ceil(
            (
                latest.created_at
                + timedelta(seconds=settings.EMAIL_VERIFY_RESEND_COOLDOWN_SECONDS)
                - now
            ).total_seconds()
        )
        if retry_after > 0:
            raise HTTPException(
                status_code=429,
                detail="Please wait before requesting another verification email",
                headers={"Retry-After": str(retry_after)},
            )

    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    record = EmailVerification(
        user_id=user.id, email=user.email, token_hash=token_hash,
    )
    recipient = user.email
    db.add(record)
    # Ссылка должна существовать в БД до того, как попадёт в письмо.
    # Старые неистёкшие ссылки сохраняются: ошибка SMTP не лишает пользователя доступа.
    await db.commit()

    try:
        await send_verification_email(recipient, build_frontend_url("/verify-email", raw_token))
    except EmailDeliveryError as exc:
        # Неудачная отправка не блокирует немедленную повторную попытку.
        record.used_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=503, detail=delivery_error_detail) from exc

    await cache_one_time_token(
        "verify", token_hash, user_id, settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES * 60,
    )
    return "sent"


async def confirm_email(db: AsyncSession, token: str) -> None:
    token_hash = hash_token(token)
    invalid = HTTPException(status_code=400, detail="Invalid or expired token")
    # Сначала блокируется пользователь, затем читается токен. Одинаковый порядок
    # блокировок у resend и verify исключает гонки и взаимную блокировку разных ссылок.
    user = (
        await db.execute(
            select(User)
            .join(EmailVerification, EmailVerification.user_id == User.id)
            .where(EmailVerification.token_hash == token_hash)
            .with_for_update(of=User)
            .execution_options(populate_existing=True)
        )
    ).scalars().first()
    if user is None or not user.is_active or user.is_email_verified:
        raise invalid

    record = (
        await db.execute(
            select(EmailVerification).where(
                EmailVerification.token_hash == token_hash,
                EmailVerification.used_at.is_(None),
            ).execution_options(populate_existing=True)
        )
    ).scalars().first()
    now = datetime.now(timezone.utc)
    if (
        record is None
        or record.email.casefold() != user.email.casefold()
        or now >= record.created_at + timedelta(minutes=settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES)
    ):
        raise invalid

    user.is_email_verified = True
    # После подтверждения ни одна из ранее выданных ссылок больше не действует.
    await db.execute(
        update(EmailVerification)
        .where(EmailVerification.user_id == user.id, EmailVerification.used_at.is_(None))
        .values(used_at=now)
    )
    await db.commit()
    # Redis — только дополнительный кэш; решение всегда принимает PostgreSQL.
    await delete_cached_one_time_token("verify", token_hash)

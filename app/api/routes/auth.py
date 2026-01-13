from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.core.jwt import (
    new_jti,
    create_access_token,
    create_refresh_token,
    create_one_time_token,
    decode_jwt,
)
from app.db.session import get_db
from app.models.user import User
from app.repositories.users import create_user, get_user_by_email, get_user_by_id
from app.repositories.tokens import add_token, get_by_jti, mark_used, revoke, revoke_all_refresh
from app.schemas.auth import (
    RegisterRequest,
    LoginLinkRequest,
    ConfirmTokenRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    LogoutRequest,
    TokenPairResponse,
    MessageResponse,
)
from app.services.mail import send_email

router = APIRouter()

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _token_expires_at(minutes: int) -> datetime:
    return _utcnow() + timedelta(minutes=minutes)

def _build_link(path: str, token: str) -> str:
    # Link points to API by default. Later you can point to frontend and have it call API.
    return f"{settings.API_BASE_URL}{path}?token={token}"

@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if await get_user_by_email(db, data.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        email_verified=False,
        university=data.university,
        study_direction=data.study_direction,
        admission_year=data.adm_year,
    )
    user = await create_user(db, user)

    jti = new_jti()
    token = create_one_time_token(
        user.id,
        token_type="EMAIL_VERIFY",
        jti=jti,
        ttl_minutes=settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES,
    )
    await add_token(
        db,
        user_id=user.id,
        jti=jti,
        token_type="EMAIL_VERIFY",
        expires_at=_token_expires_at(settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES),
    )

    link = _build_link("/auth/verify-email", token)
    send_email(
        to=user.email,
        subject="Подтверждение почты",
        body=f"Перейдите по ссылке, чтобы подтвердить почту: {link}",
    )

    return {"message": "Registered. Please verify your email."}

@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_jwt(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    if payload.get("type") != "EMAIL_VERIFY":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    token_row = await get_by_jti(db, jti)
    if not token_row or token_row.token_type != "EMAIL_VERIFY":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token not found")
    if token_row.used_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token already used")
    if token_row.expires_at < _utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expired")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.email_verified = True
    db.add(user)
    await db.commit()
    await mark_used(db, jti)

    # Redirect to frontend (nice UX). Frontend can show "email verified".
    return RedirectResponse(url=f"{settings.FRONTEND_BASE_URL}/email-verified", status_code=307)

@router.post("/login/request-link", response_model=MessageResponse)
async def request_login_link(data: LoginLinkRequest, db: AsyncSession = Depends(get_db)):
    # Always respond 200 to avoid leaking whether email exists
    user = await get_user_by_email(db, data.email)
    if not user or not user.email_verified:
        return {"message": "If the account exists, an email was sent."}

    jti = new_jti()
    token = create_one_time_token(
        user.id,
        token_type="LOGIN_MAGIC",
        jti=jti,
        ttl_minutes=settings.MAGIC_LOGIN_TOKEN_EXPIRE_MINUTES,
    )
    await add_token(
        db,
        user_id=user.id,
        jti=jti,
        token_type="LOGIN_MAGIC",
        expires_at=_token_expires_at(settings.MAGIC_LOGIN_TOKEN_EXPIRE_MINUTES),
    )

    link = _build_link("/auth/login/confirm", token)
    send_email(
        to=user.email,
        subject="Вход в аккаунт",
        body=f"Ссылка для входа (одноразовая): {link}",
    )
    return {"message": "If the account exists, an email was sent."}

@router.post("/login/confirm", response_model=TokenPairResponse)
async def confirm_login(data: ConfirmTokenRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_jwt(data.token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    if payload.get("type") != "LOGIN_MAGIC":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    token_row = await get_by_jti(db, jti)
    if not token_row or token_row.token_type != "LOGIN_MAGIC":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token not found")
    if token_row.used_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token already used")
    if token_row.expires_at < _utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expired")

    user = await get_user_by_id(db, user_id)
    if not user or not user.email_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not allowed")

    await mark_used(db, jti)

    refresh_jti = new_jti()
    refresh_token = create_refresh_token(user.id, refresh_jti)
    await add_token(
        db,
        user_id=user.id,
        jti=refresh_jti,
        token_type="REFRESH",
        expires_at=_token_expires_at(settings.REFRESH_TOKEN_EXPIRE_MINUTES),
    )

    access_token = create_access_token(user.id)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/password/reset-request", response_model=MessageResponse)
async def password_reset_request(data: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    if not user or not user.email_verified:
        return {"message": "If the account exists, an email was sent."}

    jti = new_jti()
    token = create_one_time_token(
        user.id,
        token_type="PASSWORD_RESET",
        jti=jti,
        ttl_minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
    )
    await add_token(
        db,
        user_id=user.id,
        jti=jti,
        token_type="PASSWORD_RESET",
        expires_at=_token_expires_at(settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    )

    link = _build_link("/auth/password/reset-confirm", token)
    send_email(
        to=user.email,
        subject="Сброс пароля",
        body=f"Чтобы сбросить пароль, перейдите по ссылке: {link}",
    )
    return {"message": "If the account exists, an email was sent."}

@router.post("/password/reset-confirm", response_model=MessageResponse)
async def password_reset_confirm(data: PasswordResetConfirm, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_jwt(data.token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    if payload.get("type") != "PASSWORD_RESET":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    token_row = await get_by_jti(db, jti)
    if not token_row or token_row.token_type != "PASSWORD_RESET":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token not found")
    if token_row.used_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token already used")
    if token_row.expires_at < _utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expired")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.password_hash = hash_password(data.new_password)
    db.add(user)
    await db.commit()
    await mark_used(db, jti)

    # Security: revoke all refresh tokens after password reset
    await revoke_all_refresh(db, user.id)

    return {"message": "Password updated."}

@router.post("/refresh", response_model=TokenPairResponse)
async def refresh_tokens(data: LogoutRequest, db: AsyncSession = Depends(get_db)):
    # Reuse schema: it contains refresh_token
    try:
        payload = decode_jwt(data.refresh_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if payload.get("type") != "REFRESH":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    token_row = await get_by_jti(db, jti)
    if not token_row or token_row.token_type != "REFRESH":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not found")
    if token_row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    if token_row.expires_at < _utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Rotate refresh token
    await revoke(db, jti)

    new_refresh_jti = new_jti()
    new_refresh = create_refresh_token(user.id, new_refresh_jti)
    await add_token(
        db,
        user_id=user.id,
        jti=new_refresh_jti,
        token_type="REFRESH",
        expires_at=_token_expires_at(settings.REFRESH_TOKEN_EXPIRE_MINUTES),
    )

    new_access = create_access_token(user.id)
    return {"access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer"}

@router.post("/logout", response_model=MessageResponse)
async def logout(data: LogoutRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_jwt(data.refresh_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if payload.get("type") != "REFRESH":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    token_row = await get_by_jti(db, jti)
    if token_row and token_row.revoked_at is None:
        await revoke(db, jti)

    return {"message": "Logged out."}

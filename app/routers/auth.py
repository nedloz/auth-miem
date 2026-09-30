import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import settings
from app.database import get_db
from app.mail import (
    EmailDeliveryError,
    send_password_reset_email,
    send_verification_email,
)
from app.models import (
    EmailVerification,
    PasswordReset,
    RefreshToken,
    User,
    UserProfile,
)
from app.redis import (
    cache_one_time_token,
    delete_cached_one_time_token,
    get_cached_one_time_token,
)
from app.schemas import (
    ForgotPassword,
    ResendVerification,
    ResetPassword,
    Token,
    UserCreate,
    UserLogin,
    UserRead,
)
from app.security import (
    ADMIN_SESSION_COOKIE_NAME,
    ADMIN_SESSION_COOKIE_PATH,
    ADMIN_SESSION_COOKIE_SECURE,
    ADMIN_SESSION_EXPIRE_MINUTES,
    create_access_token,
    create_admin_session_token,
    get_admin_from_cookie,
    get_current_user,
    get_password_hash,
    get_user_from_token,
    verify_password,
)


router = APIRouter()


# =========================================================
# HELPERS
# =========================================================

def hash_token(token: str) -> str:
    """
    В БД и Redis сохраняем только SHA-256 hash.
    """

    return hashlib.sha256(
        token.encode()
    ).hexdigest()


def build_frontend_url(
    path: str,
    token: str,
) -> str:
    """
    Формируем публичную frontend-ссылку.
    """

    base_url = (
        settings.FRONTEND_BASE_URL
        .rstrip("/")
    )

    return (
        f"{base_url}"
        f"/{path.lstrip('/')}"
        f"?token={token}"
    )


def is_token_expired(
    created_at: datetime,
    lifetime_minutes: int,
) -> bool:
    """
    Единая проверка срока жизни token.
    """

    expires_at = (
        created_at
        + timedelta(
            minutes=lifetime_minutes
        )
    )

    return (
        datetime.now(timezone.utc)
        >= expires_at
    )


def remaining_ttl_seconds(
    created_at: datetime,
    lifetime_minutes: int,
) -> int:
    """
    Если Redis-кэш токена пропал раньше,
    восстанавливаем его только на оставшееся время.
    """

    expires_at = (
        created_at
        + timedelta(
            minutes=lifetime_minutes
        )
    )

    remaining = int(
        (
            expires_at
            - datetime.now(timezone.utc)
        ).total_seconds()
    )

    return max(1, remaining)


# -------------------------------------------------------------------
# 1. REGISTER
# -------------------------------------------------------------------

@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(
        User.email == user_in.email
    )

    result = await db.execute(stmt)

    existing_user = result.scalars().first()

    # =========================================================
    # EMAIL ALREADY EXISTS
    # =========================================================

    if existing_user:

        if existing_user.is_email_verified:
            raise HTTPException(
                status_code=400,
                detail="Email already registered",
            )

        existing_user.password_hash = (
            get_password_hash(
                user_in.password
            )
        )

        raw_verify_token = (
            secrets.token_urlsafe(32)
        )

        verify_hash = hash_token(
            raw_verify_token
        )

        verify_record = EmailVerification(
            user_id=existing_user.id,
            email=existing_user.email,
            token_hash=verify_hash,
        )

        db.add(verify_record)

        await db.commit()
        await db.refresh(existing_user)

        # Redis хранит hash токена с тем же TTL,
        # что задан в конфигурации.
        await cache_one_time_token(
            "verify",
            verify_hash,
            existing_user.id,
            settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES * 60,
        )

        verification_url = build_frontend_url(
            "/verify-email",
            raw_verify_token,
        )

        try:
            await send_verification_email(
                existing_user.email,
                verification_url,
            )

        except EmailDeliveryError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Verification email "
                    "could not be sent"
                ),
            ) from exc

        return existing_user

    # =========================================================
    # NEW USER
    # =========================================================

    hashed_pwd = get_password_hash(
        user_in.password
    )

    new_user = User(
        email=user_in.email,
        password_hash=hashed_pwd,
    )

    db.add(new_user)

    await db.flush()

    new_profile = UserProfile(
        user_id=new_user.id
    )

    db.add(new_profile)

    raw_verify_token = (
        secrets.token_urlsafe(32)
    )

    verify_hash = hash_token(
        raw_verify_token
    )

    verify_record = EmailVerification(
        user_id=new_user.id,
        email=new_user.email,
        token_hash=verify_hash,
    )

    db.add(verify_record)

    await db.commit()
    await db.refresh(new_user)

    await cache_one_time_token(
        "verify",
        verify_hash,
        new_user.id,
        settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES * 60,
    )

    verification_url = build_frontend_url(
        "/verify-email",
        raw_verify_token,
    )

    try:
        await send_verification_email(
            new_user.email,
            verification_url,
        )

    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Account created, but "
                "verification email could not be sent"
            ),
        ) from exc

    return new_user


# -------------------------------------------------------------------
# 2.5. RESEND VERIFICATION EMAIL
# -------------------------------------------------------------------

@router.post(
    "/resend-verification",
    status_code=status.HTTP_200_OK,
)
async def resend_verification(
    data: ResendVerification,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(
        User.email == data.email
    )

    result = await db.execute(stmt)

    user = result.scalars().first()

    if not user or user.is_email_verified:
        return {
            "detail": (
                "If the account exists and is unverified, "
                "a new link has been sent."
            )
        }

    raw_verify_token = (
        secrets.token_urlsafe(32)
    )

    verify_hash = hash_token(
        raw_verify_token
    )

    verify_record = EmailVerification(
        user_id=user.id,
        email=user.email,
        token_hash=verify_hash,
    )

    db.add(verify_record)

    await db.commit()

    await cache_one_time_token(
        "verify",
        verify_hash,
        user.id,
        settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES * 60,
    )

    verification_url = build_frontend_url(
        "/verify-email",
        raw_verify_token,
    )

    try:
        await send_verification_email(
            user.email,
            verification_url,
        )

    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Verification email "
                "could not be sent"
            ),
        ) from exc

    return {
        "detail": (
            "If the account exists and is unverified, "
            "a new link has been sent."
        )
    }


# -------------------------------------------------------------------
# 2. VERIFY EMAIL
# -------------------------------------------------------------------

@router.get("/verify-email")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    t_hash = hash_token(token)

    # Сначала используем Redis как быстрый TTL/cache слой.
    cached_user_id = await get_cached_one_time_token(
        "verify",
        t_hash,
    )

    if cached_user_id is None:

        # Redis miss:
        # PostgreSQL остаётся источником истины.
        stmt = select(
            EmailVerification
        ).where(
            EmailVerification.token_hash == t_hash,
            EmailVerification.used_at == None,
        )

    else:

        stmt = select(
            EmailVerification
        ).where(
            EmailVerification.token_hash == t_hash,
            EmailVerification.user_id == cached_user_id,
            EmailVerification.used_at == None,
        )

    result = await db.execute(stmt)

    ver_record = result.scalars().first()

    if not ver_record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired token",
        )

    # Даже при наличии Redis проверяем реальный TTL.
    if is_token_expired(
        ver_record.created_at,
        settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES,
    ):
        await delete_cached_one_time_token(
            "verify",
            t_hash,
        )

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired token",
        )

    # Если Redis потерял ключ раньше DB TTL,
    # восстанавливаем cache на оставшееся время.
    if cached_user_id is None:
        await cache_one_time_token(
            "verify",
            t_hash,
            ver_record.user_id,
            remaining_ttl_seconds(
                ver_record.created_at,
                settings.EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES,
            ),
        )

    stmt_u = select(User).where(
        User.id == ver_record.user_id
    )

    user = (
        await db.execute(stmt_u)
    ).scalars().first()

    if user:
        user.is_email_verified = True

    ver_record.used_at = (
        datetime.now(timezone.utc)
    )

    await db.commit()

    # Verification token одноразовый.
    await delete_cached_one_time_token(
        "verify",
        t_hash,
    )

    return {
        "msg": "Email successfully verified"
    }


# -------------------------------------------------------------------
# 3. LOGIN
# -------------------------------------------------------------------

@router.post(
    "/login",
    response_model=Token,
)
async def login(
    user_in: UserLogin,
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(
        User.email == user_in.email
    )

    result = await db.execute(stmt)

    user = result.scalars().first()

    if not user or not verify_password(
        user_in.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User is deactivated",
        )

    if not user.is_email_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified",
        )

    # Access JWT оставляем существующим.
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
        }
    )

    # Refresh token остаётся в PostgreSQL.
    # В Redis его специально НЕ переносим:
    # здесь нужен audit/rotation/revocation.
    raw_refresh_token = (
        secrets.token_urlsafe(64)
    )

    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(
            raw_refresh_token
        ),
        ip_address=request.client.host,
        user_agent=request.headers.get(
            "user-agent"
        ),
    )

    db.add(refresh_record)

    user.last_login_at = (
        datetime.now(timezone.utc)
    )

    await db.commit()

    # TTL cookie теперь конфигурируемый.
    response.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=(
            settings.REFRESH_TOKEN_EXPIRE_MINUTES
            * 60
        ),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# -------------------------------------------------------------------
# 4. REFRESH
# -------------------------------------------------------------------

@router.post(
    "/refresh",
    response_model=Token,
)
async def refresh_tokens(
    response: Response,
    request: Request,
    refresh_token: str | None = Cookie(
        default=None
    ),
    db: AsyncSession = Depends(get_db),
):
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing",
        )

    t_hash = hash_token(
        refresh_token
    )

    stmt = select(
        RefreshToken
    ).where(
        RefreshToken.token_hash == t_hash
    )

    result = await db.execute(stmt)

    db_token = result.scalars().first()

    if not db_token:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token",
        )

    if db_token.revoked_at is not None:
        raise HTTPException(
            status_code=401,
            detail=(
                "Refresh token has been revoked"
            ),
        )

    # Раньше здесь age token не проверялся.
    if is_token_expired(
        db_token.created_at,
        settings.REFRESH_TOKEN_EXPIRE_MINUTES,
    ):
        db_token.revoked_at = (
            datetime.now(timezone.utc)
        )

        await db.commit()

        raise HTTPException(
            status_code=401,
            detail="Refresh token expired",
        )

    stmt_user = select(User).where(
        User.id == db_token.user_id
    )

    user = (
        await db.execute(stmt_user)
    ).scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail=(
                "User not found or inactive"
            ),
        )

    # Существующая rotation логика сохраняется.
    db_token.revoked_at = (
        datetime.now(timezone.utc)
    )

    new_access_token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
        }
    )

    new_raw_refresh = (
        secrets.token_urlsafe(64)
    )

    new_refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(
            new_raw_refresh
        ),
        replaced_by_token_id=db_token.id,
        ip_address=request.client.host,
        user_agent=request.headers.get(
            "user-agent"
        ),
    )

    db.add(new_refresh_record)

    await db.commit()

    response.set_cookie(
        key="refresh_token",
        value=new_raw_refresh,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=(
            settings.REFRESH_TOKEN_EXPIRE_MINUTES
            * 60
        ),
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }


# -------------------------------------------------------------------
# 5. LOGOUT
# -------------------------------------------------------------------

@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
)
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None
    ),
    db: AsyncSession = Depends(get_db),
):
    if refresh_token:

        t_hash = hash_token(
            refresh_token
        )

        stmt = select(
            RefreshToken
        ).where(
            RefreshToken.token_hash == t_hash
        )

        result = await db.execute(stmt)

        db_token = result.scalars().first()

        if (
            db_token
            and not db_token.revoked_at
        ):
            db_token.revoked_at = (
                datetime.now(timezone.utc)
            )

            await db.commit()

    response.delete_cookie(
        key="refresh_token"
    )

    return {
        "detail": "Successfully logged out"
    }


# -------------------------------------------------------------------
# 6. VALIDATE (For NGINX)
# -------------------------------------------------------------------

@router.get(
    "/validate",
    status_code=status.HTTP_200_OK,
)
async def validate_token_for_nginx(
    response: Response,
    current_user: User = Depends(
        get_user_from_token
    ),
):
    response.headers["X-User-Id"] = (
        str(current_user.id)
    )

    response.headers["X-User-Role"] = (
        current_user.role
    )

    return {
        "status": "valid"
    }


# -------------------------------------------------------------------
# 6b. АДМИН-СЕССИЯ
# -------------------------------------------------------------------

@router.post(
    "/admin-session",
    status_code=status.HTTP_200_OK,
)
async def open_admin_session(
    response: Response,
    current_user: User = Depends(
        get_current_user
    ),
):
    """
    Выдаёт короткоживущую HttpOnly-куку
    для входа в админ-панель.
    """

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )

    response.set_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        value=create_admin_session_token(
            current_user
        ),
        httponly=True,
        secure=ADMIN_SESSION_COOKIE_SECURE,
        samesite="lax",
        path=ADMIN_SESSION_COOKIE_PATH,
        max_age=(
            ADMIN_SESSION_EXPIRE_MINUTES * 60
        ),
    )

    return {
        "status": "ok",
        "expires_in": (
            ADMIN_SESSION_EXPIRE_MINUTES * 60
        ),
        "url": "/admin/",
    }


@router.post(
    "/admin-session/close",
    status_code=status.HTTP_200_OK,
)
async def close_admin_session(
    response: Response,
):
    response.delete_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        path=ADMIN_SESSION_COOKIE_PATH,
    )

    return {
        "status": "ok"
    }


@router.get(
    "/validate-admin",
    status_code=status.HTTP_200_OK,
)
async def validate_admin_for_nginx(
    response: Response,
    current_user: User = Depends(
        get_admin_from_cookie
    ),
):
    """
    auth_request endpoint для nginx
    перед проксированием в db-svc.
    """

    response.headers["X-User-Id"] = (
        str(current_user.id)
    )

    response.headers["X-User-Role"] = (
        current_user.role
    )

    return {
        "status": "valid"
    }


# -------------------------------------------------------------------
# 7. FORGOT PASSWORD
# -------------------------------------------------------------------

@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
)
async def forgot_password(
    data: ForgotPassword,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    generic_response = {
        "detail": (
            "If the email is registered, "
            "a password reset link has been sent."
        )
    }

    stmt = select(User).where(
        User.email == data.email
    )

    result = await db.execute(stmt)

    user = result.scalars().first()

    if not user:
        return generic_response

    raw_reset_token = (
        secrets.token_urlsafe(32)
    )

    reset_hash = hash_token(
        raw_reset_token
    )

    reset_record = PasswordReset(
        user_id=user.id,
        token_hash=reset_hash,
        requested_ip=request.client.host,
        requested_user_agent=(
            request.headers.get(
                "user-agent"
            )
        ),
    )

    db.add(reset_record)

    await db.commit()

    # Сохраняем hash reset token в Redis с TTL.
    await cache_one_time_token(
        "reset",
        reset_hash,
        user.id,
        settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES * 60,
    )

    reset_url = build_frontend_url(
        "/reset-password",
        raw_reset_token,
    )

    try:
        await send_password_reset_email(
            user.email,
            reset_url,
        )

    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Password reset email "
                "could not be sent"
            ),
        ) from exc

    return generic_response


# -------------------------------------------------------------------
# 8. UPDATE PASSWORD
# -------------------------------------------------------------------

@router.post(
    "/update-password",
    status_code=status.HTTP_200_OK,
)
async def update_password(
    data: ResetPassword,
    db: AsyncSession = Depends(get_db),
):
    t_hash = hash_token(
        data.token
    )

    cached_user_id = (
        await get_cached_one_time_token(
            "reset",
            t_hash,
        )
    )

    if cached_user_id is None:

        # Redis miss → PostgreSQL fallback.
        stmt = select(
            PasswordReset
        ).where(
            PasswordReset.token_hash == t_hash,
            PasswordReset.used_at == None,
        )

    else:

        stmt = select(
            PasswordReset
        ).where(
            PasswordReset.token_hash == t_hash,
            PasswordReset.user_id == cached_user_id,
            PasswordReset.used_at == None,
        )

    result = await db.execute(stmt)

    reset_record = result.scalars().first()

    if not reset_record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    if is_token_expired(
        reset_record.created_at,
        settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
    ):
        await delete_cached_one_time_token(
            "reset",
            t_hash,
        )

        raise HTTPException(
            status_code=400,
            detail="Token expired",
        )

    # Восстанавливаем Redis cache,
    # если он был потерян до окончания DB TTL.
    if cached_user_id is None:
        await cache_one_time_token(
            "reset",
            t_hash,
            reset_record.user_id,
            remaining_ttl_seconds(
                reset_record.created_at,
                settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
            ),
        )

    stmt_user = select(User).where(
        User.id == reset_record.user_id
    )

    user = (
        await db.execute(stmt_user)
    ).scalars().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    user.password_hash = (
        get_password_hash(
            data.new_password
        )
    )

    reset_record.used_at = (
        datetime.now(timezone.utc)
    )

    await db.commit()

    # Reset token одноразовый.
    await delete_cached_one_time_token(
        "reset",
        t_hash,
    )

    return {
        "detail": (
            "Password has been updated successfully"
        )
    }

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, UserProfile, EmailVerification, RefreshToken, PasswordReset
from app.schemas import UserCreate, UserRead, UserLogin, Token, ForgotPassword, ResetPassword, ResendVerification
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

# Вспомогательная функция для хэширования токенов перед сохранением в БД
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# -------------------------------------------------------------------
# 1. REGISTER
# -------------------------------------------------------------------

@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    # СЦЕНАРИЙ А: Email уже есть в базе
    if existing_user:
        if existing_user.is_email_verified:
            # Аккаунт уже полностью рабочий, регаться нельзя
            raise HTTPException(status_code=400, detail="Email already registered")
        else:
            # Аккаунт завис (не подтвержден). 
            # Обновляем ему пароль и просто шлем новый токен.
            existing_user.password_hash = get_password_hash(user_in.password)
            
            raw_verify_token = secrets.token_urlsafe(32)
            verify_record = EmailVerification(
                user_id=existing_user.id,
                email=existing_user.email,
                token_hash=hash_token(raw_verify_token)
            )
            db.add(verify_record)
            await db.commit()
            await db.refresh(existing_user)

            print(f"DEBUG EMAIL LINK (RESENT VIA REGISTER): /verify-email?token={raw_verify_token}")
            return existing_user

    # СЦЕНАРИЙ Б: Полностью новый юзер
    hashed_pwd = get_password_hash(user_in.password)
    new_user = User(email=user_in.email, password_hash=hashed_pwd)
    db.add(new_user)
    await db.flush() # Получаем new_user.id

    new_profile = UserProfile(user_id=new_user.id)
    db.add(new_profile)

    raw_verify_token = secrets.token_urlsafe(32)
    verify_record = EmailVerification(
        user_id=new_user.id,
        email=new_user.email,
        token_hash=hash_token(raw_verify_token)
    )
    db.add(verify_record)
    
    await db.commit()
    await db.refresh(new_user)

    print(f"DEBUG EMAIL LINK: /verify-email?token={raw_verify_token}")
    return new_user

# -------------------------------------------------------------------
# 2.5. RESEND VERIFICATION EMAIL
# -------------------------------------------------------------------
@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(
    data: ResendVerification, # Эту схему нужно импортировать из app.schemas!
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    # Возвращаем 200 OK даже если юзера нет или он верифицирован, 
    # чтобы хакеры не могли перебирать email-ы через эту ручку (безопасность!)
    if not user or user.is_email_verified:
        return {"detail": "If the account exists and is unverified, a new link has been sent."}

    # Генерируем новый токен
    raw_verify_token = secrets.token_urlsafe(32)
    verify_record = EmailVerification(
        user_id=user.id,
        email=user.email,
        token_hash=hash_token(raw_verify_token)
    )
    db.add(verify_record)
    await db.commit()

    print(f"DEBUG EMAIL LINK (RESEND ROUTE): /verify-email?token={raw_verify_token}")

    return {"detail": "If the account exists and is unverified, a new link has been sent."}
# -------------------------------------------------------------------
# 2. VERIFY EMAIL
# -------------------------------------------------------------------
@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    t_hash = hash_token(token)
    stmt = select(EmailVerification).where(EmailVerification.token_hash == t_hash, EmailVerification.used_at == None)
    result = await db.execute(stmt)
    ver_record = result.scalars().first()

    if not ver_record:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Обновляем юзера
    stmt_u = select(User).where(User.id == ver_record.user_id)
    user = (await db.execute(stmt_u)).scalars().first()
    if user:
        user.is_email_verified = True
    
    ver_record.used_at = datetime.now(timezone.utc)
    await db.commit()

    return {"msg": "Email successfully verified"}

# -------------------------------------------------------------------
# 3. LOGIN
# -------------------------------------------------------------------
@router.post("/login", response_model=Token)
async def login(
    user_in: UserLogin, 
    response: Response, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(user_in.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is deactivated")
        
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # 1. Генерируем Access JWT
    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})

    # 2. Генерируем Refresh Token
    raw_refresh_token = secrets.token_urlsafe(64)
    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh_token),
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    db.add(refresh_record)
    
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # 3. Устанавливаем HttpOnly Cookie
    response.set_cookie(
        key="refresh_token", 
        value=raw_refresh_token, 
        httponly=True, 
        secure=False, # В проде поставить True
        samesite="lax",
        max_age=30 * 24 * 60 * 60
    )

    return {"access_token": access_token, "token_type": "bearer"}

# -------------------------------------------------------------------
# 4. REFRESH
# -------------------------------------------------------------------
@router.post("/refresh", response_model=Token)
async def refresh_tokens(
    response: Response, 
    request: Request,
    refresh_token: str | None = Cookie(default=None), 
    db: AsyncSession = Depends(get_db)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    t_hash = hash_token(refresh_token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == t_hash)
    result = await db.execute(stmt)
    db_token = result.scalars().first()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if db_token.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    stmt_user = select(User).where(User.id == db_token.user_id)
    user = (await db.execute(stmt_user)).scalars().first()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    db_token.revoked_at = datetime.now(timezone.utc)

    new_access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    new_raw_refresh = secrets.token_urlsafe(64)
    
    new_refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        replaced_by_token_id=db_token.id,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    db.add(new_refresh_record)
    await db.commit()

    response.set_cookie(
        key="refresh_token", 
        value=new_raw_refresh, 
        httponly=True, 
        secure=False, 
        samesite="lax",
        max_age=30 * 24 * 60 * 60
    )

    return {"access_token": new_access_token, "token_type": "bearer"}

# -------------------------------------------------------------------
# 5. LOGOUT
# -------------------------------------------------------------------
@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db)
):
    if refresh_token:
        t_hash = hash_token(refresh_token)
        stmt = select(RefreshToken).where(RefreshToken.token_hash == t_hash)
        result = await db.execute(stmt)
        db_token = result.scalars().first()
        
        if db_token and not db_token.revoked_at:
            db_token.revoked_at = datetime.now(timezone.utc)
            await db.commit()

    response.delete_cookie(key="refresh_token")
    return {"detail": "Successfully logged out"}
    
# -------------------------------------------------------------------
# 6. VALIDATE (For NGINX)
# -------------------------------------------------------------------
@router.get("/validate", status_code=status.HTTP_200_OK)
async def validate_token_for_nginx(
    response: Response,
    # ВНИМАНИЕ: Здесь используем get_user_from_token!
    current_user: User = Depends(get_user_from_token) 
):
    response.headers["X-User-Id"] = str(current_user.id)
    response.headers["X-User-Role"] = current_user.role
    return {"status": "valid"}

# -------------------------------------------------------------------
# 6b. АДМИН-СЕССИЯ (вход в панель db-svc за /admin/)
# -------------------------------------------------------------------
@router.post("/admin-session", status_code=status.HTTP_200_OK)
async def open_admin_session(response: Response, current_user: User = Depends(get_current_user)):
    """Выдаёт короткоживущую HttpOnly-куку для входа в админ-панель.

    Вызывается фронтендом по нажатию кнопки «Админка». Сам пользователь определяется по
    заголовку X-User-Id, который проставил nginx после проверки JWT, — то есть в этот роут
    нельзя попасть, не имея валидного access-токена.

    Зачем кука, а не заголовок: переход в панель — обычная навигация браузера, в ней нет
    Authorization. Кука уходит и с навигацией, и со всеми подзапросами админки.
    """
    if current_user.role != "admin":
        # 404, а не 403: не подтверждаем существование раздела тем, у кого нет прав.
        # Это не замена проверке прав, а лишь отсутствие лишнего сигнала.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    response.set_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        value=create_admin_session_token(current_user),
        httponly=True,
        secure=ADMIN_SESSION_COOKIE_SECURE,
        samesite="lax",
        # Кука ограничена путём админки: на обычные запросы приложения она не отправляется.
        path=ADMIN_SESSION_COOKIE_PATH,
        max_age=ADMIN_SESSION_EXPIRE_MINUTES * 60,
    )
    return {"status": "ok", "expires_in": ADMIN_SESSION_EXPIRE_MINUTES * 60, "url": "/admin/"}


@router.post("/admin-session/close", status_code=status.HTTP_200_OK)
async def close_admin_session(response: Response):
    """Досрочно гасит админ-сессию (выход из панели)."""
    response.delete_cookie(key=ADMIN_SESSION_COOKIE_NAME, path=ADMIN_SESSION_COOKIE_PATH)
    return {"status": "ok"}


@router.get("/validate-admin", status_code=status.HTTP_200_OK)
async def validate_admin_for_nginx(
    response: Response,
    current_user: User = Depends(get_admin_from_cookie),
):
    """auth_request-эндпоинт для nginx перед проксированием в db-svc.

    Возвращает 200 только обладателю действующей админ-сессии; всем остальным — 403, и тогда
    nginx не обращается к db-svc вовсе, то есть страницы админки не покидают контур.
    """
    response.headers["X-User-Id"] = str(current_user.id)
    response.headers["X-User-Role"] = current_user.role
    return {"status": "valid"}

# -------------------------------------------------------------------
# 7. FORGOT PASSWORD
# -------------------------------------------------------------------
@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    data: ForgotPassword,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        return {"detail": "If the email is registered, a password reset link has been sent."}

    raw_reset_token = secrets.token_urlsafe(32)
    reset_record = PasswordReset(
        user_id=user.id,
        token_hash=hash_token(raw_reset_token),
        requested_ip=request.client.host,
        requested_user_agent=request.headers.get("user-agent")
    )
    db.add(reset_record)
    await db.commit()

    print(f"DEBUG EMAIL LINK: /reset-password?token={raw_reset_token}")

    return {"detail": "If the email is registered, a password reset link has been sent."}

# -------------------------------------------------------------------
# 8. UPDATE PASSWORD
# -------------------------------------------------------------------
@router.post("/update-password", status_code=status.HTTP_200_OK)
async def update_password(
    data: ResetPassword,
    db: AsyncSession = Depends(get_db)
):
    t_hash = hash_token(data.token)
    stmt = select(PasswordReset).where(
        PasswordReset.token_hash == t_hash, 
        PasswordReset.used_at == None
    )
    result = await db.execute(stmt)
    reset_record = result.scalars().first()

    if not reset_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    if datetime.now(timezone.utc) - reset_record.created_at > timedelta(hours=1):
        raise HTTPException(status_code=400, detail="Token expired")

    stmt_user = select(User).where(User.id == reset_record.user_id)
    user = (await db.execute(stmt_user)).scalars().first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = get_password_hash(data.new_password)
    reset_record.used_at = datetime.now(timezone.utc)
    
    await db.commit()

    return {"detail": "Password has been updated successfully"}

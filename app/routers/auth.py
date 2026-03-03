import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, RefreshToken, PasswordReset
from app.schemas import UserLogin, Token, ForgotPassword, ResetPassword
from app.security import verify_password, create_access_token, get_password_hash, get_current_user

router = APIRouter()

# Вспомогательная функция для хэширования токенов перед сохранением в БД
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# -------------------------------------------------------------------
# 1. LOGIN
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

    # 1. Генерируем Access JWT
    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})

    # 2. Генерируем Refresh Token (длинная случайная строка)
    raw_refresh_token = secrets.token_urlsafe(64)
    
    # 3. Сохраняем хэш Refresh Token в БД
    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh_token),
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    db.add(refresh_record)
    
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # 4. Устанавливаем HttpOnly Cookie
    response.set_cookie(
        key="refresh_token", 
        value=raw_refresh_token, 
        httponly=True, 
        secure=False, # В проде (HTTPS) обязательно поставить True!
        samesite="lax",
        max_age=30 * 24 * 60 * 60 # 30 дней
    )

    return {"access_token": access_token, "token_type": "bearer"}

# -------------------------------------------------------------------
# 2. REFRESH
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
    
    # Ищем токен в БД
    stmt = select(RefreshToken).where(RefreshToken.token_hash == t_hash)
    result = await db.execute(stmt)
    db_token = result.scalars().first()

    # Проверки: существует ли, не отозван ли
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if db_token.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    # Ищем пользователя
    stmt_user = select(User).where(User.id == db_token.user_id)
    user = (await db.execute(stmt_user)).scalars().first()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # ROTATION: Инвалидируем старый токен
    db_token.revoked_at = datetime.now(timezone.utc)

    # Генерируем новую пару токенов
    new_access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    new_raw_refresh = secrets.token_urlsafe(64)
    
    new_refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        replaced_by_token_id=db_token.id, # Связываем цепочку ротации
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    db.add(new_refresh_record)
    await db.commit()

    # Обновляем куку
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
# 3. LOGOUT
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
        
        # Помечаем токен как отозванный
        if db_token and not db_token.revoked_at:
            db_token.revoked_at = datetime.now(timezone.utc)
            await db.commit()

    # Удаляем куку
    response.delete_cookie(key="refresh_token")
    return {"detail": "Successfully logged out"}

# -------------------------------------------------------------------
# 4. VALIDATE (For NGINX)
# -------------------------------------------------------------------
@router.get("/validate", status_code=status.HTTP_200_OK)
async def validate_token_for_nginx(
    response: Response,
    current_user: User = Depends(get_current_user)
):
    # Возвращаем заголовки для NGINX auth_request
    response.headers["X-User-Id"] = str(current_user.id)
    response.headers["X-User-Role"] = current_user.role
    return {"status": "valid"}

# -------------------------------------------------------------------
# 5. FORGOT PASSWORD
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

    # Возвращаем 200 OK даже если юзер не найден, чтобы не раскрывать базу email-ов
    if not user:
        return {"detail": "If the email is registered, a password reset link has been sent."}

    # Генерируем уникальный токен для сброса
    raw_reset_token = secrets.token_urlsafe(32)
    
    reset_record = PasswordReset(
        user_id=user.id,
        token_hash=hash_token(raw_reset_token),
        requested_ip=request.client.host,
        requested_user_agent=request.headers.get("user-agent")
    )
    db.add(reset_record)
    await db.commit()

    # TODO: Отправить письмо на data.email со ссылкой:
    # https://твой-домен.com/reset-password?token={raw_reset_token}
    print(f"DEBUG EMAIL LINK: /reset-password?token={raw_reset_token}")

    return {"detail": "If the email is registered, a password reset link has been sent."}

# -------------------------------------------------------------------
# 6. UPDATE PASSWORD
# -------------------------------------------------------------------
@router.post("/update-password", status_code=status.HTTP_200_OK)
async def update_password(
    data: ResetPassword,
    db: AsyncSession = Depends(get_db)
):
    t_hash = hash_token(data.token)
    
    # Ищем неиспользованный токен сброса
    stmt = select(PasswordReset).where(
        PasswordReset.token_hash == t_hash, 
        PasswordReset.used_at == None
    )
    result = await db.execute(stmt)
    reset_record = result.scalars().first()

    # Дополнительно можно проверять created_at, чтобы токен "протухал" через час
    if not reset_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    if datetime.now(timezone.utc) - reset_record.created_at > timedelta(hours=1):
        raise HTTPException(status_code=400, detail="Token expired")

    # Ищем юзера и обновляем пароль
    stmt_user = select(User).where(User.id == reset_record.user_id)
    user = (await db.execute(stmt_user)).scalars().first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = get_password_hash(data.new_password)
    reset_record.used_at = datetime.now(timezone.utc)
    
    await db.commit()

    return {"detail": "Password has been updated successfully"}

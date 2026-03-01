import secrets
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_db
from app.models import User, UserProfile, EmailVerification, RefreshToken
from app.schemas import UserCreate, UserRead, Token
from app.security import get_password_hash, verify_password, create_access_token
from datetime import datetime, timezone

router = APIRouter()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    # Проверка, существует ли юзер
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Создание пользователя
    hashed_pwd = get_password_hash(user_in.password)
    new_user = User(email=user_in.email, password_hash=hashed_pwd)
    db.add(new_user)
    await db.flush()  # Получаем new_user.id

    # Создание пустого профиля
    new_profile = UserProfile(user_id=new_user.id)
    db.add(new_profile)

    # Генерация токена для почты
    raw_verify_token = secrets.token_urlsafe(32)
    verify_record = EmailVerification(
        user_id=new_user.id,
        email=new_user.email,
        token_hash=hash_token(raw_verify_token)
    )
    db.add(verify_record)

    await db.commit()
    await db.refresh(new_user)

    # TODO: Отправить письмо на почту со ссылкой:
    # https://твой_сайт/verify-email?token={raw_verify_token}
    print(f"DEBUG EMAIL LINK: /verify-email?token={raw_verify_token}")

    return new_user


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


@router.post("/login", response_model=Token)
async def login(user_in: UserCreate, response: Response, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(user_in.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # Генерация Access Token
    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})

    # Генерация Refresh Token
    raw_refresh_token = secrets.token_urlsafe(64)
    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh_token)
    )
    db.add(refresh_record)

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # Ставим Refresh Token в HttpOnly Cookie (защита от XSS)
    response.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        httponly=True,
        secure=False,  # True в продакшене (HTTPS)
        samesite="lax",
        max_age=30 * 24 * 60 * 60  # 30 дней
    )

    return {"access_token": access_token, "token_type": "bearer"}
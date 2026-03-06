import os
from datetime import datetime, timedelta, timezone
import bcrypt
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import ValidationError
from app.database import get_db
from app.models import User
import jwt

SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)

def get_password_hash(password: str) -> str:
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Возвращаем декодированную строку, чтобы её можно было положить в БД (тип String)
    return hashed_password.decode('utf-8')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# =====================================================================
# 1. ЭТУ ФУНКЦИЮ ИСПОЛЬЗУЕТ ТОЛЬКО NGINX (роут /validate)
# Она честно проверяет JWT-токен.
# =====================================================================
async def get_user_from_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_exception

    token = authorization.removeprefix("Bearer ").strip()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.is_active:
        raise credentials_exception

    return user

# =====================================================================
# 2. ЭТУ ФУНКЦИЮ ИСПОЛЬЗУЮТ ВСЕ ВНУТРЕННИЕ РОУТЫ (например, профиль)
# Она просто читает заголовок X-User-Id, который прокинул Nginx.
# =====================================================================
async def get_current_user(
    x_user_id: str = Header(None, alias="X-User-Id"),
    db: AsyncSession = Depends(get_db)
):
    # Если заголовка нет — значит запрос пришел в обход Nginx или юзер не авторизован
    if not x_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-User-Id header. Unauthorized."
        )
        
    # Просто достаем юзера из базы (чтобы роуты профиля могли с ним работать)
    stmt = select(User).where(User.id == x_user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    return user

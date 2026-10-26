import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
import bcrypt
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import ValidationError
from app.database import get_db
from app.models import User
from app import user_context
import jwt

logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

# Отдельная короткоживущая сессия для админ-панели (db-svc за /admin/).
# Нужна потому, что переход по ссылке — обычная навигация браузера, и заголовка
# Authorization в ней нет: access-токен живёт в памяти фронтенда и добавляется только
# в fetch. Кука HttpOnly уходит автоматически и с навигацией, и со всеми подзапросами
# админки. Передавать вместо этого JWT в query (как сделано для WebSocket) не стали:
# токен оседал бы в истории браузера, логах nginx и Referer.
ADMIN_SESSION_COOKIE_NAME = os.getenv("ADMIN_SESSION_COOKIE_NAME", "admin_session")
ADMIN_SESSION_EXPIRE_MINUTES = int(os.getenv("ADMIN_SESSION_EXPIRE_MINUTES", "30"))
ADMIN_SESSION_COOKIE_PATH = os.getenv("ADMIN_SESSION_COOKIE_PATH", "/admin")
ADMIN_SESSION_COOKIE_SECURE = os.getenv("ADMIN_SESSION_COOKIE_SECURE", "false").lower() == "true"

# Значение claim "scope" у токена админ-сессии. Токены с этим scope НЕ должны работать
# как обычные access-токены, и наоборот — см. get_user_from_token и get_admin_from_cookie.
ADMIN_SESSION_SCOPE = "admin_panel"
INTERNAL_AUTH_MODE = os.getenv("INTERNAL_AUTH_MODE", "mtls")
CALLER_HEADER = "X-Caller-Identity"


def validate_internal_auth_mode() -> None:
    """Статических токенов нет: вызывающего подтверждает сертификат, а имя из него проставляет
    прокси-сайдкар в X-Caller-Identity (infra/mtls в корне main). Заголовку верим только от
    loopback, то есть от прокси в том же сетевом пространстве. INTERNAL_AUTH_MODE=insecure
    отключает проверку и нужен только для локальной отладки без PKI."""
    if INTERNAL_AUTH_MODE not in ("mtls", "insecure"):
        raise RuntimeError(f"INTERNAL_AUTH_MODE={INTERNAL_AUTH_MODE!r}: допустимо mtls, insecure")
    if INTERNAL_AUTH_MODE == "insecure":
        logger.warning(
            "INTERNAL_AUTH_MODE=insecure: внутренние вызовы не аутентифицируются. "
            "Не для стенда и продакшена."
        )


def _is_loopback(host: str | None) -> bool:
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


async def verify_internal_service_request(request: Request) -> str:
    caller = request.headers.get(CALLER_HEADER) or None
    if INTERNAL_AUTH_MODE == "insecure":
        return caller or "unauthenticated"
    peer = request.client.host if request.client else None
    if not caller or not _is_loopback(peer):
        logger.warning("Internal API forbidden: caller not verified (peer=%s)", peer)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden internal service",
        )
    logger.info("Internal API authorized for service=%s", caller)
    return caller


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

def create_admin_session_token(user: User) -> str:
    """Короткоживущий токен для входа в админ-панель.

    Отличается от access-токена claim'ом scope: перепутать их нельзя ни в одну сторону.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ADMIN_SESSION_EXPIRE_MINUTES)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "scope": ADMIN_SESSION_SCOPE,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


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
        # Токен админ-сессии подписан тем же ключом, но обычным access-токеном быть не должен:
        # у него другое назначение и он живёт в куке, доступной и другим вкладкам.
        if payload.get("scope") == ADMIN_SESSION_SCOPE:
            raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.is_active:
        raise credentials_exception

    return user

async def get_admin_from_cookie(
    admin_session: str | None = Cookie(default=None, alias=ADMIN_SESSION_COOKIE_NAME),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Проверка админ-сессии для nginx (роут /auth/validate-admin).

    Роль перепроверяется в базе, а не берётся из токена: если у пользователя отозвали admin,
    доступ должен пропасть сразу, а не после истечения куки.
    """
    forbidden = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    if not admin_session:
        raise forbidden

    try:
        payload = jwt.decode(admin_session, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise forbidden

    # Обычный access-токен в этой куке не должен открывать админку: назначение разное.
    if payload.get("scope") != ADMIN_SESSION_SCOPE:
        raise forbidden

    user_id = payload.get("sub")
    if not user_id:
        raise forbidden

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if user is None or not user.is_active or user.role != "admin":
        raise forbidden

    return user


# =====================================================================
# 2. ЭТУ ФУНКЦИЮ ИСПОЛЬЗУЮТ ВСЕ ВНУТРЕННИЕ РОУТЫ (например, профиль)
# Пользователь берётся из подписанного контекста X-User-Context, который выпустил этот же
# сервис в /auth/validate и пробросил nginx (app/user_context.py). Голый X-User-Id больше
# не принимается: его мог выставить любой контейнер в сети.
# =====================================================================
def _user_id_from_headers(x_user_context: str | None, x_user_id: str | None) -> str:
    if x_user_context:
        try:
            return user_context.verify_from_env(x_user_context).user_id
        except user_context.UserContextError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user context. Unauthorized.",
            ) from exc
    # Переходный режим (USER_CONTEXT_ALLOW_LEGACY): старый заголовок от nginx без подписи.
    if x_user_id and user_context.allow_legacy():
        return x_user_id
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing user context. Unauthorized.",
    )


async def get_current_user(
    x_user_context: str = Header(None, alias=user_context.HEADER),
    x_user_id: str = Header(None, alias="X-User-Id"),
    db: AsyncSession = Depends(get_db)
):
    user_id = _user_id_from_headers(x_user_context, x_user_id)

    # Просто достаем юзера из базы (чтобы роуты профиля могли с ним работать)
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user

import hashlib

import redis.asyncio as redis

from app.config import settings


# Один Redis-клиент на процесс auth-svc.
#
# Используем тот же Redis, который уже существует
# в pochemuchnic-miem-prj.
redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
)


def _hash_value(value: str) -> str:
    """
    Не кладём email в Redis key в открытом виде.

    Например:
    user@example.com
        ↓
    SHA-256
        ↓
    auth:email-cooldown:verify:<hash>
    """

    normalized = value.strip().casefold()

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def make_email_cooldown_key(
    purpose: str,
    email: str,
) -> str:
    """
    Создаёт namespaced Redis key.

    purpose:
    - verify
    - reset
    """

    email_hash = _hash_value(email)

    return (
        f"auth:email-cooldown:"
        f"{purpose}:{email_hash}"
    )


async def acquire_email_cooldown(
    purpose: str,
    email: str,
) -> tuple[bool, str]:
    """
    Пытаемся поставить Redis-ключ с NX + EX.

    True  -> письмо можно отправлять.
    False -> cooldown уже существует.
    """

    key = make_email_cooldown_key(
        purpose,
        email,
    )

    acquired = await redis_client.set(
        key,
        "1",
        nx=True,
        ex=settings.EMAIL_SEND_COOLDOWN_SECONDS,
    )

    return bool(acquired), key


async def release_email_cooldown(
    key: str,
) -> None:
    """
    Удаляем cooldown, если отправка письма
    завершилась ошибкой.

    Тогда пользователь сможет сразу
    попробовать ещё раз.
    """

    await redis_client.delete(key)


async def close_redis() -> None:
    """
    Корректно закрываем Redis connection pool.
    """

    await redis_client.aclose()

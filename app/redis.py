import hashlib

import redis.asyncio as redis

from app.config import settings


# Единый Redis client для auth-svc.
#
# Сами auth-токены сюда НЕ записываются.
#
# Redis используется только для временных cooldown/rate-limit
# ключей отправки email.
redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
)


def _hash_email(email: str) -> str:
    """
    Не помещаем email в Redis key открытым текстом.
    """

    normalized_email = email.strip().casefold()

    return hashlib.sha256(
        normalized_email.encode("utf-8")
    ).hexdigest()


def make_email_cooldown_key(
    purpose: str,
    email: str,
) -> str:
    """
    Redis keys:

        auth:email-cooldown:verify:<hash>
        auth:email-cooldown:reset:<hash>
    """

    return (
        "auth:email-cooldown:"
        f"{purpose}:"
        f"{_hash_email(email)}"
    )


async def acquire_email_cooldown(
    purpose: str,
    email: str,
) -> tuple[bool, str]:
    """
    Пытаемся создать cooldown key.

    NX:
        создать ключ только если его ещё нет.

    EX:
        автоматически удалить через N секунд.

    Возвращает:

        (True, key)
            письмо можно отправлять.

        (False, key)
            cooldown уже существует.
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
    Если SMTP-отправка завершилась ошибкой,
    удаляем cooldown, чтобы пользователь
    мог попробовать отправить письмо ещё раз.
    """

    await redis_client.delete(key)


async def close_redis() -> None:
    """
    Закрываем Redis connection pool
    при завершении auth-svc.
    """

    await redis_client.aclose()def make_email_cooldown_key(
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

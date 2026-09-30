import hashlib
import json
from uuid import UUID

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.config import settings


# =========================================================
# REDIS CLIENT
# =========================================================

redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
)


# =========================================================
# SHORT-LIVED TOKENS
# =========================================================

def _token_key(
    kind: str,
    token_hash: str,
) -> str:
    """
    Примеры:

    auth:token:verify:v1:<sha256>
    auth:token:reset:v1:<sha256>
    """

    return (
        f"auth:token:"
        f"{kind}:v1:"
        f"{token_hash}"
    )


async def cache_one_time_token(
    kind: str,
    token_hash: str,
    user_id: UUID,
    ttl_seconds: int,
) -> None:
    """
    Кладём hash одноразового токена в Redis.

    Raw token в Redis не хранится.

    PostgreSQL при этом остаётся источником истины.
    """

    try:
        await redis_client.set(
            _token_key(
                kind,
                token_hash,
            ),
            str(user_id),
            ex=max(1, ttl_seconds),
        )

    except RedisError:
        # Redis — дополнительный слой.
        # Отказ Redis не должен ломать auth.
        pass


async def get_cached_one_time_token(
    kind: str,
    token_hash: str,
) -> str | None:
    """
    Возвращает user_id из Redis,
    либо None при cache miss/ошибке Redis.
    """

    try:
        return await redis_client.get(
            _token_key(
                kind,
                token_hash,
            )
        )

    except RedisError:
        return None


async def delete_cached_one_time_token(
    kind: str,
    token_hash: str,
) -> None:
    """
    Удаляет использованный одноразовый токен.
    """

    try:
        await redis_client.delete(
            _token_key(
                kind,
                token_hash,
            )
        )

    except RedisError:
        pass


# =========================================================
# PROFILE CACHE
# =========================================================

def _profile_key(
    user_id: UUID | str,
    scope: str,
) -> str:
    """
    Scope:

    me
        /users/me

    internal
        /internal/users/{id}/profile
    """

    return (
        f"auth:profile:"
        f"{scope}:v1:"
        f"{user_id}"
    )


async def get_profile_cache(
    user_id: UUID | str,
    scope: str,
) -> dict | None:
    """
    Получить сериализованный профиль из Redis.
    """

    try:
        raw = await redis_client.get(
            _profile_key(
                user_id,
                scope,
            )
        )

        if raw is None:
            return None

        value = json.loads(raw)

        if isinstance(value, dict):
            return value

        return None

    except (
        RedisError,
        json.JSONDecodeError,
    ):
        return None


async def set_profile_cache(
    user_id: UUID | str,
    scope: str,
    value: dict,
) -> None:
    """
    Сохраняем профиль с коротким TTL.
    """

    try:
        await redis_client.set(
            _profile_key(
                user_id,
                scope,
            ),
            json.dumps(
                value,
                ensure_ascii=False,
            ),
            ex=max(
                1,
                settings.PROFILE_CACHE_TTL_SECONDS,
            ),
        )

    except (
        RedisError,
        TypeError,
    ):
        pass


async def invalidate_profile_cache(
    user_id: UUID | str,
) -> None:
    """
    После изменения профиля удаляем оба варианта cache.
    """

    try:
        await redis_client.delete(
            _profile_key(
                user_id,
                "me",
            ),
            _profile_key(
                user_id,
                "internal",
            ),
        )

    except RedisError:
        pass


# =========================================================
# SHUTDOWN
# =========================================================

async def close_redis() -> None:
    """
    Закрываем Redis connection pool.
    """

    await redis_client.aclose()

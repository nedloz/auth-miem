"""Хранилище аватаров в MinIO (бакет avatars).

Доступ идёт через прокси MinIO с клиентским сертификатом; права auth-svc на этот бакет описаны
в infra/mtls/minio.conf. Клиент minio-py блокирующий, поэтому вызовы уходят в пул потоков.
"""

from __future__ import annotations

import io
import logging
import os
from functools import lru_cache

from minio import Minio
from minio.error import S3Error
from starlette.concurrency import run_in_threadpool

from app import s3_tls

logger = logging.getLogger(__name__)

BUCKET = os.getenv("MINIO_AVATARS_BUCKET", "avatars")


class AvatarStorageUnavailable(RuntimeError):
    """MinIO не настроен или недоступен."""


@lru_cache(maxsize=2)
def _client(_cert_stamp: int) -> Minio:
    endpoint = os.getenv("MINIO_ENDPOINT")
    access_key = os.getenv("MINIO_ACCESS_KEY")
    secret_key = os.getenv("MINIO_SECRET_KEY")

    if not (endpoint and access_key and secret_key):
        raise AvatarStorageUnavailable("MinIO не настроен")

    secure = os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes", "on"}

    return Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
        # Регион известен заранее: без него minio-py сам запрашивает его у бакета.
        region=os.getenv("MINIO_REGION") or "us-east-1",
        http_client=s3_tls.urllib3_pool(),
    )


def _get() -> Minio:
    # Сертификат живёт сутки; при обновлении файла клиент пересоздаётся.
    return _client(s3_tls.cert_stamp())


def _put(key: str, data: bytes, content_type: str) -> None:
    _get().put_object(BUCKET, key, io.BytesIO(data), len(data), content_type=content_type)


def _read(key: str) -> tuple[bytes, str]:
    response = _get().get_object(BUCKET, key)
    try:
        return response.read(), response.headers.get("Content-Type", "application/octet-stream")
    finally:
        response.close()
        response.release_conn()


def _remove(key: str) -> None:
    _get().remove_object(BUCKET, key)


async def put(key: str, data: bytes, content_type: str) -> None:
    try:
        await run_in_threadpool(_put, key, data, content_type)
    except AvatarStorageUnavailable:
        raise
    except Exception as exc:
        logger.error("Не удалось записать аватар %s: %s", key, exc)
        raise AvatarStorageUnavailable("MinIO недоступен") from exc


async def read(key: str) -> tuple[bytes, str] | None:
    """Содержимое и тип объекта или None, если объекта нет."""
    try:
        return await run_in_threadpool(_read, key)
    except AvatarStorageUnavailable:
        raise
    except S3Error as exc:
        if exc.code in {"NoSuchKey", "NoSuchBucket"}:
            return None
        logger.error("Не удалось прочитать аватар %s: %s", key, exc)
        raise AvatarStorageUnavailable("MinIO недоступен") from exc
    except Exception as exc:
        logger.error("Не удалось прочитать аватар %s: %s", key, exc)
        raise AvatarStorageUnavailable("MinIO недоступен") from exc


async def remove(key: str) -> None:
    """Удаление старой картинки не должно ломать запрос: ошибка только в лог."""
    try:
        await run_in_threadpool(_remove, key)
    except Exception as exc:
        logger.warning("Не удалось удалить аватар %s: %s", key, exc)

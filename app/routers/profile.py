import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app import avatar_store
from app.models import User, UserProfile
from app.redis import (
    get_profile_cache,
    invalidate_profile_cache,
    set_profile_cache,
)
from app.schemas import (
    UserProfileRead,
    UserProfileUpdate,
)
from app.security import get_current_user


router = APIRouter()

AVATAR_MAX_BYTES = 5 * 1024 * 1024
AVATAR_CACHE_SECONDS = 86400
AVATAR_EXTENSIONS = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
}


def _avatar_type(head: bytes) -> str | None:
    """Тип картинки по сигнатуре: заголовку Content-Type клиента верить нельзя."""

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


# -------------------------------------------------------------------
# GET CURRENT PROFILE
# -------------------------------------------------------------------

@router.get(
    "/me",
    response_model=UserProfileRead,
)
async def get_my_profile(
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Получить профиль текущего пользователя.

    Сначала проверяем Redis.
    При cache miss читаем PostgreSQL.
    """

    cached = await get_profile_cache(
        current_user.id,
        "me",
    )

    # Роль лежит в учётной записи, а не в профиле, но фронтенд решает по ней, показывать ли
    # вход в админ-панель. Берём её из current_user каждый раз, а не из кэша: смена роли
    # в базе не должна ждать истечения TTL.
    if cached is not None:
        payload = UserProfileRead.model_validate(
            cached
        )
        payload.role = current_user.role
        payload.email = current_user.email
        return payload

    stmt = select(UserProfile).where(
        UserProfile.user_id == current_user.id
    )

    result = await db.execute(stmt)

    profile = result.scalars().first()

    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Profile not found",
        )

    response = UserProfileRead.model_validate(
        profile
    )
    response.role = current_user.role
    response.email = current_user.email

    await set_profile_cache(
        current_user.id,
        "me",
        response.model_dump(
            mode="json"
        ),
    )

    return response


# -------------------------------------------------------------------
# UPDATE CURRENT PROFILE
# -------------------------------------------------------------------

@router.patch(
    "/me",
    response_model=UserProfileRead,
)
async def update_my_profile(
    profile_update: UserProfileUpdate,
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Частичное обновление профиля.

    После изменения обязательно инвалидируем
    Redis cache.
    """

    stmt = select(UserProfile).where(
        UserProfile.user_id == current_user.id
    )

    result = await db.execute(stmt)

    profile = result.scalars().first()

    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Profile not found",
        )

    update_data = (
        profile_update.model_dump(
            exclude_unset=True
        )
    )

    faculty_id = update_data.get("faculty_id", profile.faculty_id)
    program_id = update_data.get("program_id", profile.program_id)

    if program_id is not None:
        program_faculty = (
            await db.execute(
                text(
                    "SELECT faculty_id FROM core.programs "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": str(program_id)},
            )
        ).scalar_one_or_none()

        if program_faculty is None:
            raise HTTPException(
                status_code=422,
                detail="Unknown program_id",
            )

        if faculty_id is not None and program_faculty != faculty_id:
            raise HTTPException(
                status_code=422,
                detail="program_id does not belong to faculty_id",
            )

    for key, value in update_data.items():
        setattr(
            profile,
            key,
            value,
        )

    await db.commit()
    await db.refresh(profile)

    # Важнейшая часть cache invalidation:
    # удаляем и /users/me, и internal profile cache.
    await invalidate_profile_cache(
        current_user.id
    )

    # Без роли ответ PATCH затирал бы её на фронтенде, и кнопка админ-панели пропадала бы
    # после первого же сохранения профиля.
    updated = UserProfileRead.model_validate(
        profile
    )
    updated.role = current_user.role
    updated.email = current_user.email

    return updated


# -------------------------------------------------------------------
# DELETE ACCOUNT
# -------------------------------------------------------------------

@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_my_account(
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Soft Delete аккаунта.

    Redis cache также очищается, чтобы старый
    профиль не продолжал возвращаться после deactivate.
    """

    current_user.is_active = False

    await db.commit()

    await invalidate_profile_cache(
        current_user.id
    )

    return None


# -------------------------------------------------------------------
# AVATAR
# -------------------------------------------------------------------

def _storage_unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Avatar storage is unavailable",
    )


async def _get_profile(db: AsyncSession, user: User) -> UserProfile:
    profile = (
        await db.execute(
            select(UserProfile).where(
                UserProfile.user_id == user.id
            )
        )
    ).scalars().first()

    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Profile not found",
        )

    return profile


@router.post(
    "/me/avatar",
    response_model=UserProfileRead,
)
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Загрузить или заменить аватар (png, jpeg, webp, до 5 МБ).

    Картинка лежит в MinIO (бакет avatars), в профиле остаются ключ объекта и
    путь GET /users/me/avatar с версией, чтобы браузер не держал старую.
    """

    data = await file.read(AVATAR_MAX_BYTES + 1)

    if len(data) > AVATAR_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Avatar is larger than 5 MB",
        )

    content_type = _avatar_type(data[:12])

    if content_type is None:
        raise HTTPException(
            status_code=415,
            detail="Avatar must be png, jpeg or webp",
        )

    profile = await _get_profile(db, current_user)

    version = uuid.uuid4().hex
    key = f"{current_user.id}/{version}.{AVATAR_EXTENSIONS[content_type]}"
    old_key = profile.avatar_key

    try:
        await avatar_store.put(key, data, content_type)
    except avatar_store.AvatarStorageUnavailable:
        raise _storage_unavailable()

    profile.avatar_key = key
    profile.avatar_url = f"/api/users/me/avatar?v={version}"

    try:
        await db.commit()
    except Exception:
        await avatar_store.remove(key)
        raise

    await db.refresh(profile)

    if old_key:
        await avatar_store.remove(old_key)

    await invalidate_profile_cache(
        current_user.id
    )

    updated = UserProfileRead.model_validate(
        profile
    )
    updated.role = current_user.role
    updated.email = current_user.email

    return updated


@router.get("/me/avatar")
async def get_avatar(
    request: Request,
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """Отдать аватар текущего пользователя как картинку."""

    profile = await _get_profile(db, current_user)

    if not profile.avatar_key:
        raise HTTPException(
            status_code=404,
            detail="Avatar not found",
        )

    # Имя объекта содержит случайную версию и не меняется: она же служит ETag.
    etag = f'"{profile.avatar_key.rsplit("/", 1)[-1].split(".")[0]}"'

    headers = {
        "ETag": etag,
        "Cache-Control": f"private, max-age={AVATAR_CACHE_SECONDS}",
    }

    if request.headers.get("if-none-match") == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers=headers,
        )

    try:
        stored = await avatar_store.read(profile.avatar_key)
    except avatar_store.AvatarStorageUnavailable:
        raise _storage_unavailable()

    if stored is None:
        raise HTTPException(
            status_code=404,
            detail="Avatar not found",
        )

    content, content_type = stored

    return Response(
        content=content,
        media_type=content_type,
        headers=headers,
    )


@router.delete(
    "/me/avatar",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_avatar(
    current_user: User = Depends(
        get_current_user
    ),
    db: AsyncSession = Depends(get_db),
):
    """Сбросить аватар к заглушке."""

    profile = await _get_profile(db, current_user)

    old_key = profile.avatar_key

    profile.avatar_key = None
    profile.avatar_url = None

    await db.commit()

    if old_key:
        await avatar_store.remove(old_key)

    await invalidate_profile_cache(
        current_user.id
    )

    return None

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
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

    if cached is not None:
        return UserProfileRead.model_validate(
            cached
        )

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

    return profile


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

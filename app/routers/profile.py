from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, UserProfile
from app.schemas import UserProfileRead, UserProfileUpdate
from app.security import get_current_user

router = APIRouter()


@router.get("/me", response_model=UserProfileRead)
async def get_my_profile(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    """
    Получить профиль текущего авторизованного пользователя.
    """
    stmt = select(UserProfile).where(UserProfile.user_id == current_user.id)
    result = await db.execute(stmt)
    profile = result.scalars().first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    return profile


@router.patch("/me", response_model=UserProfileRead)
async def update_my_profile(
        profile_update: UserProfileUpdate,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    """
    Частичное обновление полей профиля текущего пользователя.
    """
    stmt = select(UserProfile).where(UserProfile.user_id == current_user.id)
    result = await db.execute(stmt)
    profile = result.scalars().first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Идем по всем полям из Pydantic-схемы, которые были переданы (не None)
    update_data = profile_update.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(profile, key, value)

    await db.commit()
    await db.refresh(profile)

    return profile


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_account(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
):
    """
    Удаление аккаунта (Soft Delete).
    Мы не удаляем юзера физически, чтобы не поломать связи в БД (например, историю чатов),
    а просто ставим is_active = False.
    """
    current_user.is_active = False
    await db.commit()

    return None
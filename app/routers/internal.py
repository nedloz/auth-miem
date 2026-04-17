import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import User
from app.schemas import InternalUserProfileResponse, InternalUserProfilePayload
from app.security import verify_internal_service_request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/users/{user_id}/profile", response_model=InternalUserProfileResponse)
async def get_internal_user_profile(
    user_id: UUID,
    _: str = Depends(verify_internal_service_request),
    db: AsyncSession = Depends(get_db),
):
    logger.info("Internal API: profile requested for user_id=%s", user_id)

    stmt = (
        select(User)
        .options(selectinload(User.profile))
        .where(User.id == user_id, User.is_active.is_(True))
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    profile = user.profile

    return InternalUserProfileResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        profile=InternalUserProfilePayload(
            first_name=profile.first_name if profile else None,
            last_name=profile.last_name if profile else None,
            telegram_username=profile.telegram_username if profile else None,
            university_id=profile.university_id if profile else None,
            campus_id=profile.campus_id if profile else None,
            faculty_id=profile.faculty_id if profile else None,
            program_id=profile.program_id if profile else None,
            year=profile.year if profile else None,
            group_name=profile.group_name if profile else None,
            preferences=profile.preferences_json if profile else {},
        ),
    )

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import UUID4
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User
from app.schemas import FacultyRead, ProgramRead
from app.security import get_current_user


router = APIRouter()


# Моделей схемы core в auth-svc нет: роль сервиса читает её только как справочник
# (core_ro), поэтому достаточно сырого SQL.

@router.get(
    "/faculties",
    response_model=list[FacultyRead],
)
async def list_faculties(
    university_id: Optional[UUID4] = None,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Факультеты по алфавиту; `university_id` сужает список до одного вуза."""

    result = await db.execute(
        text(
            """
            SELECT id, name, short_name
            FROM core.faculties
            WHERE (CAST(:university_id AS uuid) IS NULL
                   OR university_id = CAST(:university_id AS uuid))
            ORDER BY name
            """
        ),
        {"university_id": str(university_id) if university_id else None},
    )

    return [dict(row) for row in result.mappings()]


@router.get(
    "/programs",
    response_model=list[ProgramRead],
)
async def list_programs(
    faculty_id: Optional[UUID4] = None,
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Действующие направления по алфавиту; `faculty_id` сужает список до одного факультета."""

    result = await db.execute(
        text(
            """
            SELECT id, name, short_name, code, degree_level
            FROM core.programs
            WHERE is_active
              AND (CAST(:faculty_id AS uuid) IS NULL
                   OR faculty_id = CAST(:faculty_id AS uuid))
            ORDER BY name
            """
        ),
        {"faculty_id": str(faculty_id) if faculty_id else None},
    )

    return [dict(row) for row in result.mappings()]

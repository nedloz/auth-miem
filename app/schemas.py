from pydantic import BaseModel, EmailStr, UUID4, field_validator
from typing import Optional, Any
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserProfileUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    telegram_username: Optional[str] = None
    university_id: Optional[UUID4] = None
    faculty_id: Optional[UUID4] = None
    program_id: Optional[UUID4] = None
    year: Optional[int] = None
    group_name: Optional[str] = None

    @field_validator("group_name")
    @classmethod
    def clean_group_name(cls, value: Optional[str]) -> Optional[str]:
        # Группа — свободная строка (IVHR-75): справочника нет, формат проверяет фронт. Здесь
        # только убираем лишние пробелы, пустую строку превращаем в None и ограничиваем длину.
        if value is None:
            return None
        value = " ".join(value.split())
        if len(value) > 32:
            raise ValueError("group_name is longer than 32 characters")
        return value or None

class UserProfileRead(BaseModel):
    user_id: UUID4
    first_name: Optional[str]
    last_name: Optional[str]
    telegram_username: Optional[str]
    university_id: Optional[UUID4]
    campus_id: Optional[UUID4]
    faculty_id: Optional[UUID4]
    program_id: Optional[UUID4]
    year: Optional[int]
    group_name: Optional[str]
    # Роль лежит не в профиле, а в самой учётной записи, но фронтенду нужна именно здесь:
    # по ней решается, показывать ли вход в админ-панель. Заполняется в обработчике.
    role: Optional[str] = None
    # Почта хранится в auth.users и в профиль подставляется так же, как роль. Только для чтения.
    email: Optional[str] = None
    # Путь API для <img src>; меняется вместе с картинкой (?v=<etag>), чтобы не держать старую в кэше.
    avatar_url: Optional[str] = None

    class Config:
        from_attributes = True

class FacultyRead(BaseModel):
    id: UUID4
    name: str
    short_name: Optional[str] = None

class ProgramRead(BaseModel):
    id: UUID4
    name: str
    short_name: Optional[str] = None
    code: Optional[str] = None
    degree_level: Optional[str] = None

class UserRead(BaseModel):
    id: UUID4
    email: str
    role: str
    is_email_verified: bool
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    token: str
    new_password: str

class ResendVerification(BaseModel):
    email: EmailStr


class InternalUserProfilePayload(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    telegram_username: Optional[str] = None
    university_id: Optional[UUID4] = None
    campus_id: Optional[UUID4] = None
    faculty_id: Optional[UUID4] = None
    program_id: Optional[UUID4] = None
    year: Optional[int] = None
    group_name: Optional[str] = None
    preferences: dict[str, Any] = {}


class InternalUserProfileResponse(BaseModel):
    id: UUID4
    email: Optional[str] = None
    role: Optional[str] = None
    profile: InternalUserProfilePayload

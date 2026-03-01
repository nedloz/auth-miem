from pydantic import BaseModel, EmailStr, UUID4
from typing import Optional
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

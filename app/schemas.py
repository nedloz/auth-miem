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

    class Config:
        from_attributes = True

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

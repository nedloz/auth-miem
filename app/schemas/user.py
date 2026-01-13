from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

class UserResponse(BaseModel):
    id: str
    email: EmailStr
    email_verified: bool

    university: str | None = None
    study_direction: str | None = None
    admission_year: int | None = None

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    university: str | None = None
    study_direction: str | None = None
    admission_year: int | None = Field(default=None, ge=1900, le=2100)

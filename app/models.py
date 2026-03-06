import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship
from app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True) # CITEXT в БД
    password_hash = Column(String, nullable=False)
    is_email_verified = Column(Boolean, nullable=False, default=False)
    role = Column(String, nullable=False, default="student")
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    profile = relationship("UserProfile", back_populates="user", uselist=False)

class UserProfile(Base):
    __tablename__ = "user_profiles"
    __table_args__ = {"schema": "auth"}

    user_id = Column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"), primary_key=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    telegram_username = Column(String, nullable=True)
    
    university_id = Column(UUID(as_uuid=True), nullable=True)
    campus_id = Column(UUID(as_uuid=True), nullable=True)
    faculty_id = Column(UUID(as_uuid=True), nullable=True)
    program_id = Column(UUID(as_uuid=True), nullable=True)
    
    year = Column(Integer, nullable=True)
    group_name = Column(String, nullable=True)
    preferences_json = Column(JSONB, nullable=False, default={})

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    user = relationship("User", back_populates="profile")

class EmailVerification(Base):
    __tablename__ = "email_verifications"
    __table_args__ = {"schema": "auth"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"), nullable=False)
    email = Column(String, nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = {"schema": "auth"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    replaced_by_token_id = Column(UUID(as_uuid=True), ForeignKey("auth.refresh_tokens.id", ondelete="SET NULL"), nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

class PasswordReset(Base):
    __tablename__ = "password_resets"
    __table_args__ = {"schema": "auth"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    requested_ip = Column(INET, nullable=True)
    requested_user_agent = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

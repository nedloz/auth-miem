from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl

class Settings(BaseSettings):
    # Database (use async driver)
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

    # JWT
    SECRET_KEY: str = "change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 14  # 14 days

    # One-time tokens (minutes)
    EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24h
    MAGIC_LOGIN_TOKEN_EXPIRE_MINUTES: int = 15
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 60

    # Email
    EMAIL_FROM: str = "no-reply@example.com"
    SMTP_SERVER: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "example_user"
    SMTP_PASSWORD: str = "example_password"

    # Links (where user lands after clicking email links)
    # You can point these to your frontend later.
    FRONTEND_BASE_URL: AnyHttpUrl = "http://localhost:3000"
    API_BASE_URL: AnyHttpUrl = "http://127.0.0.1:8000"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

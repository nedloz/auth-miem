from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Дополнительная конфигурация auth-svc.

    Существующие DATABASE_URL, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
    и admin-настройки остаются в текущих database.py/security.py.

    Здесь находятся только параметры, которые нужны для нового
    SMTP/Redis/token-lifetime функционала.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # =========================================================
    # TOKEN LIFETIMES
    # =========================================================

    # Refresh token: 30 дней
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 43200

    # Email verification token: 24 часа
    EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, gt=0)

    EMAIL_VERIFY_RESEND_COOLDOWN_SECONDS: int = Field(default=60, ge=0)

    # Password reset token: 1 час
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 60

    # =========================================================
    # FRONTEND
    # =========================================================

    # Публичный URL frontend/nginx.
    FRONTEND_BASE_URL: str = "http://localhost"

    @field_validator("FRONTEND_BASE_URL")
    @classmethod
    def validate_frontend_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(char.isspace() for char in value)
        ):
            raise ValueError("FRONTEND_BASE_URL must be an http(s) URL without credentials, query or fragment")
        return value.rstrip("/")

    # =========================================================
    # SMTP
    # =========================================================

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587

    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False

    EMAIL_FROM: str = ""

    # =========================================================
    # REDIS
    # =========================================================

    # В основном docker-compose это значение уже
    # прокидывается через environment.
    REDIS_URL: str = "redis://redis:6379/0"

    # Кэш профилей.
    PROFILE_CACHE_TTL_SECONDS: int = 300


settings = Settings()

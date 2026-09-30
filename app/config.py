from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Единая конфигурация auth-svc.

    Зачем:
    - убираем os.getenv() из разных файлов;
    - TTL токенов задаются только через ENV;
    - SMTP и Redis тоже настраиваются через ENV;
    - compose/.env становится единственным источником конфигурации.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # =========================================================
    # DATABASE
    # =========================================================

    DATABASE_URL: str

    # =========================================================
    # JWT
    # =========================================================

    SECRET_KEY: str
    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15

    # =========================================================
    # TOKEN LIFETIMES
    # =========================================================

    REFRESH_TOKEN_EXPIRE_MINUTES: int = 43200

    EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES: int = 1440

    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 60

    # =========================================================
    # FRONTEND
    # =========================================================

    FRONTEND_BASE_URL: str = "http://localhost"

    # =========================================================
    # SMTP
    # =========================================================

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587

    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False

    EMAIL_FROM: str = ""

    # =========================================================
    # REDIS
    # =========================================================

    REDIS_URL: str = "redis://redis:6379/0"

    # Сколько секунд нельзя повторно отправлять
    # одно и то же verification/reset письмо.
    EMAIL_SEND_COOLDOWN_SECONDS: int = 60

    # =========================================================
    # REFRESH COOKIE
    # =========================================================

    REFRESH_COOKIE_NAME: str = "refresh_token"
    REFRESH_COOKIE_SECURE: bool = False
    REFRESH_COOKIE_SAMESITE: str = "lax"

    # =========================================================
    # ADMIN SESSION
    # =========================================================

    ADMIN_SESSION_COOKIE_NAME: str = "admin_session"
    ADMIN_SESSION_EXPIRE_MINUTES: int = 30
    ADMIN_SESSION_COOKIE_PATH: str = "/admin"
    ADMIN_SESSION_COOKIE_SECURE: bool = False

    # =========================================================
    # INTERNAL SERVICE AUTH
    # =========================================================

    INTERNAL_AUTH_HEADER_NAME: str = "X-Service-Token"
    INTERNAL_SERVICE_NAME_HEADER: str = "X-Service-Name"

    TRUSTED_SERVICE_TOKENS: dict[str, str] = Field(
        default_factory=dict
    )


@lru_cache
def get_settings() -> Settings:
    """
    Возвращаем один экземпляр настроек на весь процесс.
    """
    return Settings()


settings = get_settings()
